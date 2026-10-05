// test_segment_hardening.cpp  (segmented_engine.hpp)
//
// A hint file is only a startup accelerator. Whatever state it is in --
// missing, empty, cut short, missing its last entry, pointing outside the
// segment, unreadable -- recovery must produce exactly the same data as a
// full scan. And garbage length fields must never throw.
//
// Build: g++ -std=c++17 -O2 -pthread test_segment_hardening.cpp -o test_segment_hardening
// NOTE: run under `ulimit -v 3000000` against old code (garbage lengths can try to allocate ~4 GB).
#include "segmented_engine.hpp"
#include "test_util.hpp"
#include <functional>

using kvengine::SegmentedKVEngine;
using tu::check;

static constexpr int NKEYS = 60;
static std::string K(int i) { return "h" + std::to_string(i); }
static std::string V(int i) { return "val_" + std::to_string(i) + "_" + std::string(12, 'p'); }
static const std::string DBDIR = "hardening_db";

static void build(uint64_t threshold = 512) {
    tu::rm_rf(DBDIR);
    SegmentedKVEngine db(DBDIR, threshold, 16);
    for (int i = 0; i < NKEYS; ++i) db.put(K(i), V(i));
}

static std::vector<std::string> hint_files() {
    std::vector<std::string> out;
    for (const auto& n : tu::list_dir(DBDIR)) if (n.size() > 5 && n.substr(n.size() - 5) == ".hint") out.push_back(n);
    return out;
}

// Reopens and verifies all NKEYS; returns number wrong/missing (-1 if it threw).
static int verify(uint64_t threshold = 512, uint64_t* full_scans = nullptr) {
    try {
        SegmentedKVEngine db(DBDIR, threshold, 16);
        int bad = 0;
        for (int i = 0; i < NKEYS; ++i) { auto v = db.get(K(i)); if (!v || *v != V(i)) ++bad; }
        if (db.size() != static_cast<size_t>(NKEYS)) ++bad;
        if (full_scans) *full_scans = db.full_scan_recoveries();
        return bad;
    } catch (const std::exception&) { return -1; }
}

static void test_hint_damage() {
    std::cout << "=== Damaged hint files fall back to a full scan ===\n";
    build();
    auto hints = hint_files();
    check("setup: several sealed segments with hints", hints.size() >= 3);
    if (hints.size() < 3) return;
    const std::string target = DBDIR + "/" + hints[1];
    const std::string pristine = tu::read_file(target);
    const uint64_t hsize = pristine.size();

    // Position (in bytes) where the last entry of this hint starts.
    uint64_t last_entry_start = 0;
    for (uint64_t pos = 0; pos + 24 <= hsize;) {
        uint32_t klen; std::memcpy(&klen, pristine.data() + pos, 4);
        last_entry_start = pos; pos += 24 + klen;
    }

    struct Case { const char* name; std::function<void()> damage; };
    const Case cases[] = {
        {"hint deleted", [&] { std::remove(target.c_str()); }},
        {"hint empty (0 bytes)", [&] { tu::truncate_to(target, 0); }},
        {"hint cut mid-entry (last 7 bytes gone)", [&] { tu::truncate_to(target, hsize - 7); }},
        {"hint missing exactly its last entry", [&] { tu::truncate_to(target, last_entry_start); }},
        {"hint has trailing garbage", [&] { tu::write_file(target, pristine + std::string(11, '\x5a')); }},
        {"hint entry points far outside the segment", [&] { tu::put_u64_at(target, 4, 0x7FFFFFFF00000000ull); }},
        {"hint entry value size larger than the segment", [&] { tu::put_u32_at(target, 12, 0x00FFFFFFu); }},
    };
    for (const auto& c : cases) {
        tu::write_file(target, pristine);
        c.damage();
        uint64_t scans = 0;
        const int bad = verify(512, &scans);
        check(std::string(c.name) + ": every key still correct (" + std::to_string(bad) + " wrong)", bad == 0);
    }
    tu::write_file(target, pristine);
    uint64_t scans = 0;
    check("pristine hints: all keys correct", verify(512, &scans) == 0);
}

static void test_unreadable_hint() {
    std::cout << "\n=== A hint that cannot be written or read must not lose keys ===\n";
    tu::rm_rf(DBDIR);
    ::mkdir(DBDIR.c_str(), 0755);
    // A directory squatting where segment 0's hint file belongs: creating or
    // reading that "file" fails. Sealing must shrug it off, and the next
    // segments' hints must not inherit segment 0's records.
    ::mkdir((DBDIR + "/000000.hint").c_str(), 0755);
    {
        SegmentedKVEngine db(DBDIR, 512, 16);
        for (int i = 0; i < NKEYS; ++i) db.put(K(i), V(i));
    }
    check("all keys correct after restart despite the unwritable/unreadable hint", verify() == 0);
    check("and after a second restart", verify() == 0);
    tu::rm_rf(DBDIR);
}

static void test_garbage_lengths_active() {
    std::cout << "\n=== Garbage lengths in the active segment ===\n";
    tu::rm_rf(DBDIR);
    {
        SegmentedKVEngine db(DBDIR, 1u << 20, 16); // one big segment: everything in 000000.seg
        for (int i = 0; i < 10; ++i) db.put("key" + std::to_string(i), "value" + std::to_string(i));
    }
    const uint64_t REC = 30;
    const std::string seg = DBDIR + "/" + tu::seg_name(0);
    tu::put_u32_at(seg, 5 * REC + 12, 0xF0000000u);
    bool threw = false; size_t n = 0; bool prefix_ok = true;
    try {
        SegmentedKVEngine db(DBDIR, 1u << 20, 16);
        n = db.size();
        for (int i = 0; i < 5; ++i) { auto v = db.get("key" + std::to_string(i)); prefix_ok &= v && *v == "value" + std::to_string(i); }
        db.put("later", "ok");
        auto v = db.get("later"); prefix_ok &= v && *v == "ok";
    } catch (const std::exception&) { threw = true; }
    check("opens without throwing", !threw);
    check("keys before the damage recovered (5), none after, appends work", !threw && n == 5 && prefix_ok);
    check("segment truncated at the damaged record (+ the one new record)", tu::file_size(seg) == 5 * REC + 20 + 5 + 2);
    tu::rm_rf(DBDIR);
}

static void test_garbage_lengths_sealed_scan() {
    std::cout << "\n=== Garbage lengths in a sealed segment that has no hint ===\n";
    build();
    auto hints = hint_files();
    if (hints.size() < 3) { check("setup", false); return; }
    // Damage the second sealed segment and delete its hint so it gets scanned.
    const std::string name = hints[1].substr(0, 6);
    std::remove((DBDIR + "/" + hints[1]).c_str());
    tu::put_u32_at(DBDIR + "/" + name + ".seg", 20 + 40 + 12, 0xF0000000u); // klen of its 2nd-or-so record
    bool threw = false; bool never_wrong = true; size_t present = 0;
    try {
        SegmentedKVEngine db(DBDIR, 512, 16);
        for (int i = 0; i < NKEYS; ++i) { auto v = db.get(K(i)); if (v) { ++present; never_wrong &= (*v == V(i)); } }
    } catch (const std::exception&) { threw = true; }
    check("opens without throwing", !threw);
    check("every value returned is correct, and the other segments' keys are present", !threw && never_wrong && present >= 30);
    tu::rm_rf(DBDIR);
}

int main() {
    test_hint_damage();
    test_unreadable_hint();
    test_garbage_lengths_active();
    test_garbage_lengths_sealed_scan();
    return tu::summary();
}
