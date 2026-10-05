// test_kv_engine_recovery.cpp  (single-file engine, kv_engine.hpp)
//
// Recovery must survive ANY damage to the log without crashing, throwing, or
// returning a value that was not written:
//   - garbage length fields in a header (used to throw std::bad_alloc),
//   - truncation at every possible byte length,
//   - every single-bit flip in the file,
//   - compaction followed by reopen, with a stale compaction temp file.
//
// Build: g++ -std=c++17 -O2 -pthread test_kv_engine_recovery.cpp -o test_kv_engine_recovery
// NOTE: run under `ulimit -v 3000000` against old code: a bad length can try to allocate ~4 GB.
#include "kv_engine.hpp"
#include "test_util.hpp"

#include <unordered_map>
using kvengine::KVEngine;
using tu::check;

static constexpr int N = 10;
static constexpr uint64_t REC = 20 + 4 + 6; // header + "keyN" + "valueN"
static std::string K(int i) { return "key" + std::to_string(i); }
static std::string V(int i) { return "value" + std::to_string(i); }
static const std::string PATH = "v1_recovery.db";

static void build() {
    std::remove(PATH.c_str());
    KVEngine db(PATH);
    for (int i = 0; i < N; ++i) db.put(K(i), V(i));
}

// Opens PATH; returns -1 if the constructor threw. Otherwise how many of the
// first `expect_present` keys are intact, and sets `extra` to the number of
// keys that should NOT be there but are.
static int open_and_count(int expect_present, int& extra, bool& threw) {
    threw = false; extra = 0;
    try {
        KVEngine db(PATH);
        int ok = 0;
        for (int i = 0; i < N; ++i) {
            auto v = db.get(K(i));
            if (i < expect_present) { if (v && *v == V(i)) ++ok; }
            else if (v) ++extra;
        }
        if (db.size() != static_cast<size_t>(ok + extra)) extra += 1000; // index disagrees with reality
        return ok;
    } catch (const std::exception&) { threw = true; return -1; }
}

static void test_garbage_lengths() {
    std::cout << "=== Garbage length fields in the middle of the log ===\n";
    struct Case { const char* name; uint64_t field_off; uint32_t value; };
    const Case cases[] = {
        {"key length = 0xF0000000", 12, 0xF0000000u},
        {"key length = 0xFFFFFFFF", 12, 0xFFFFFFFFu},
        {"value length = 0xFFFFFFFE", 16, 0xFFFFFFFEu},
        {"value length = 0x7FFFFFFF", 16, 0x7FFFFFFFu},
        {"value length = tombstone marker on a record with a body", 16, 0xFFFFFFFFu},
    };
    for (const auto& c : cases) {
        build();
        tu::put_u32_at(PATH, 5 * REC + c.field_off, c.value);
        int extra; bool threw;
        const int ok = open_and_count(5, extra, threw);
        check(std::string(c.name) + ": opens without throwing", !threw);
        check(std::string(c.name) + ": keys before the damage recovered, none after", ok == 5 && extra == 0);
        check(std::string(c.name) + ": log truncated at the damaged record", tu::file_size(PATH) == 5 * REC);
        bool appended = false;
        try {
            KVEngine db(PATH);
            db.put("after", "ok");
            auto v = db.get("after");
            appended = v && *v == "ok";
        } catch (const std::exception&) {}
        check(std::string(c.name) + ": appending after recovery works", appended);
    }
}

static void test_every_truncation() {
    std::cout << "\n=== Truncate the file at every possible length ===\n";
    build();
    const std::string full = PATH + ".full";
    tu::copy_file(PATH, full);
    const uint64_t size = tu::file_size(full);
    bool all_ok = true; uint64_t bad_len = 0;
    for (uint64_t len = 0; len <= size; ++len) {
        tu::copy_file(full, PATH);
        tu::truncate_to(PATH, len);
        const int expect = static_cast<int>(len / REC);
        int extra; bool threw;
        const int ok = open_and_count(expect, extra, threw);
        if (threw || ok != expect || extra != 0 || tu::file_size(PATH) != expect * REC) { all_ok = false; bad_len = len; break; }
    }
    check("every truncation length 0.." + std::to_string(size) + " recovers exactly the whole records",
          all_ok);
    if (!all_ok) std::cout << "       (first bad length: " << bad_len << ")\n";
    std::remove(full.c_str());
}

static void test_every_bit_flip() {
    std::cout << "\n=== Flip every bit of every byte of the file (one at a time) ===\n";
    build();
    const std::string full = PATH + ".full";
    tu::copy_file(PATH, full);
    const uint64_t size = tu::file_size(full);
    uint64_t runs = 0, bad = 0, bad_off = 0; int bad_bit = 0;
    for (uint64_t off = 0; off < size; ++off) {
        for (int bit = 0; bit < 8; ++bit) {
            tu::copy_file(full, PATH);
            tu::flip_bit(PATH, off, bit);
            const int expect = static_cast<int>(off / REC); // records before the damaged one
            int extra; bool threw;
            const int ok = open_and_count(expect, extra, threw);
            ++runs;
            if (threw || ok != expect || extra != 0) { if (!bad) { bad_off = off; bad_bit = bit; } ++bad; }
        }
    }
    check(std::to_string(runs) + " single-bit flips: records before the flip intact, the damaged record and everything after dropped, never a wrong value",
          bad == 0);
    if (bad) std::cout << "       (" << bad << " bad; first at byte " << bad_off << " bit " << bad_bit << ")\n";
    std::remove(full.c_str());
}

static void test_compaction_and_reopen() {
    std::cout << "\n=== Compaction, stale temp file, reopen ===\n";
    std::remove(PATH.c_str());
    std::unordered_map<std::string, std::string> model;
    {
        KVEngine db(PATH);
        for (int round = 0; round < 5; ++round)
            for (int i = 0; i < 40; ++i) { const auto k = "k" + std::to_string(i); const auto v = "r" + std::to_string(round) + "_" + std::to_string(i); db.put(k, v); model[k] = v; }
        for (int i = 0; i < 40; i += 4) { db.del("k" + std::to_string(i)); model.erase("k" + std::to_string(i)); }
        const uint64_t before = db.data_file_bytes();
        check("compact() succeeds", db.compact());
        check("log got smaller", db.data_file_bytes() < before);
        db.put("post", "compact"); model["post"] = "compact";
    }
    tu::write_file(PATH + ".compact.tmp", "stale junk from a crashed compaction");
    {
        KVEngine db(PATH);
        bool ok = db.size() == model.size();
        for (const auto& [k, v] : model) { auto g = db.get(k); ok &= g && *g == v; }
        check("reopen after compaction matches the model exactly", ok);
        check("compact() works again with a stale temp file lying around", db.compact());
    }
    {
        KVEngine db(PATH);
        bool ok = db.size() == model.size();
        for (const auto& [k, v] : model) { auto g = db.get(k); ok &= g && *g == v; }
        check("second reopen still matches", ok);
    }
    std::remove(PATH.c_str()); std::remove((PATH + ".compact.tmp").c_str());
}

int main() {
    test_garbage_lengths();
    test_every_truncation();
    test_every_bit_flip();
    test_compaction_and_reopen();
    std::remove(PATH.c_str());
    return tu::summary();
}
