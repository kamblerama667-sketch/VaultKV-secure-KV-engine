// test_compaction_restart.cpp
//
// Compaction and restart together. Bug B from the handoff: a key updated /
// deleted AFTER a compaction came back stale after a restart because the
// compacted segment sorted wrongly against newer data. Every scenario here
// closes and reopens the engine at least twice.
//
// Build: g++ -std=c++17 -O2 -pthread test_compaction_restart.cpp -o test_compaction_restart
#include "segmented_engine.hpp"
#include "test_util.hpp"

#include <map>
using kvengine::SegmentedKVEngine;
using tu::check;

static std::string filler_key(int i) { return "fill" + std::to_string(i); }
static std::string filler_val(int i) { return "fval" + std::to_string(i) + std::string(20, 'f'); }

static bool state_matches(SegmentedKVEngine& db, const std::map<std::string, std::string>& model) {
    if (db.size() != model.size()) return false;
    for (const auto& [k, v] : model) { auto g = db.get(k); if (!g || *g != v) return false; }
    return true;
}

// The exact scenario from the handoff README.
static void scenario_b() {
    std::cout << "=== B: update and delete after a compaction, then restart twice ===\n";
    const std::string dir = "cr_b";
    tu::rm_rf(dir);
    {
        SegmentedKVEngine db(dir, 512, 16);
        for (int i = 0; i < 300; ++i) {
            db.put(filler_key(i), filler_val(i));
            if (i % 6 == 0) db.put("up", "OLD_" + std::to_string(i));
        }
        db.put("del_me", "doomed");
        for (int i = 300; i < 330; ++i) db.put(filler_key(i), filler_val(i)); // push del_me into a sealed segment
        check("B setup: many segments before compaction", db.segment_count() > 5);
        const size_t before = db.segment_count();
        check("B: compact() succeeds", db.compact());
        check("B: compaction reduced the segment count", db.segment_count() < before);
        db.put("up", "NEWEST");
        db.del("del_me");
        auto v = db.get("up");
        check("B: before restart, 'up' is NEWEST", v && *v == "NEWEST");
    }
    for (int restart = 1; restart <= 3; ++restart) {
        SegmentedKVEngine db(dir, 512, 16);
        auto up = db.get("up");
        check("B restart " + std::to_string(restart) + ": 'up' == NEWEST (not an older compacted value)", up && *up == "NEWEST");
        check("B restart " + std::to_string(restart) + ": 'del_me' is still deleted (not resurrected)", !db.get("del_me").has_value());
        int fillers = 0;
        for (int i = 0; i < 330; ++i) { auto g = db.get(filler_key(i)); if (g && *g == filler_val(i)) ++fillers; }
        check("B restart " + std::to_string(restart) + ": all 330 filler keys intact (got " + std::to_string(fillers) + ")", fillers == 330);
        if (restart == 1) {
            db.put("after1", "x"); // restart-then-write onto the compacted layout
            for (int i = 0; i < 40; ++i) db.put("pad" + std::to_string(i), std::string(60, 'p')); // forces a roll
        }
    }
    tu::rm_rf(dir);
}

static void scenario_model_with_compactions() {
    std::cout << "\n=== 60 restarts with compactions mixed in, checked against a model ===\n";
    const std::string dir = "cr_model";
    tu::rm_rf(dir);
    std::map<std::string, std::string> model;
    bool ok = true; int counter = 0; size_t hint_used = 0;
    for (int round = 0; round < 60 && ok; ++round) {
        SegmentedKVEngine db(dir, 700, 8);
        ok &= state_matches(db, model);
        hint_used += db.hint_recoveries();
        const int writes = 5 + (round * 11) % 30;
        for (int i = 0; i < writes; ++i) {
            const std::string k = "k" + std::to_string((counter * 7 + i) % 45);
            const int n = counter++;
            const std::string v = "v" + std::to_string(n) + std::string(8 + n % 20, 'z');
            db.put(k, v); model[k] = v;
        }
        if (round % 4 == 1 && !model.empty()) { const auto victim = model.begin()->first; db.del(victim); model.erase(victim); }
        if (round % 3 == 0) { ok &= db.compact(); ok &= state_matches(db, model); }
        if (round % 5 == 2) { // compaction immediately followed by overwrites and deletes of compacted keys
            ok &= db.compact();
            for (auto it = model.begin(); it != model.end() && std::distance(model.begin(), it) < 6; ) {
                if (std::distance(model.begin(), it) % 2) { db.del(it->first); it = model.erase(it); }
                else { db.put(it->first, "post-compact-" + std::to_string(round)); it->second = "post-compact-" + std::to_string(round); ++it; }
            }
        }
    }
    check("every restart matches the model (puts, overwrites, deletes, compactions)", ok);
    check("restarts used hint files (not only full scans)", hint_used > 0);
    tu::rm_rf(dir);
}

static void scenario_edges() {
    std::cout << "\n=== Edge cases ===\n";
    const std::string dir = "cr_edge";
    tu::rm_rf(dir);
    {
        SegmentedKVEngine db(dir, 1u << 20, 8);
        db.put("only", "active");
        check("compact() with no sealed segments is a successful no-op", db.compact() && db.segment_count() == 1);
    }
    tu::rm_rf(dir);
    {
        SegmentedKVEngine db(dir, 400, 8);
        for (int i = 0; i < 80; ++i) db.put("d" + std::to_string(i), std::string(30, 'q'));
        for (int i = 0; i < 80; ++i) db.del("d" + std::to_string(i));
        for (int i = 0; i < 20; ++i) db.put("pad" + std::to_string(i), std::string(40, 'x')); // roll past the tombstones
        check("compact() when every sealed key is deleted", db.compact());
        check("compact() twice in a row", db.compact());
    }
    {
        SegmentedKVEngine db(dir, 400, 8);
        bool none = true;
        for (int i = 0; i < 80; ++i) none &= !db.get("d" + std::to_string(i)).has_value();
        check("deleted keys stay deleted after restart", none);
        check("compact + restart + compact again works", db.compact());
    }
    tu::rm_rf(dir);

    // Leftovers of an interrupted compaction are cleaned up, and no stray files remain.
    {
        SegmentedKVEngine db(dir, 400, 8);
        for (int i = 0; i < 100; ++i) db.put("e" + std::to_string(i % 30), "v" + std::to_string(i));
        db.compact();
    }
    tu::write_file(dir + "/000003.seg.compact.tmp", "junk");
    tu::write_file(dir + "/000003.hint.tmp", "junk");
    { SegmentedKVEngine db(dir, 400, 8); }
    bool clean = true;
    for (const auto& n : tu::list_dir(dir)) if (n.find(".tmp") != std::string::npos) clean = false;
    check("stale .tmp files are removed on startup", clean);
    tu::rm_rf(dir);
}

static void scenario_corrupt_source_aborts() {
    std::cout << "\n=== A corrupt record must stop compaction, not be copied ===\n";
    const std::string dir = "cr_corrupt";
    tu::rm_rf(dir);
    {
        SegmentedKVEngine db(dir, 500, 8);
        for (int i = 0; i < 100; ++i) db.put("c" + std::to_string(i), "value_" + std::to_string(i) + std::string(10, 'c'));
    }
    // Damage a value byte of the very first record ("c0") in sealed segment 0.
    tu::flip_bit(dir + "/" + tu::seg_name(0), 20 + 2 + 1, 3);
    const auto files_before = tu::list_dir(dir);
    std::string seg0_before = tu::read_file(dir + "/" + tu::seg_name(0));
    {
        SegmentedKVEngine db(dir, 500, 8); // hint-based recovery trusts the hint; the damage surfaces at compaction
        const size_t segs = db.segment_count();
        check("compact() refuses to copy a corrupt record", !db.compact());
        check("segment count unchanged after the refused compaction", db.segment_count() == segs);
        auto other = db.get("c50");
        check("unrelated keys still readable", other && *other == "value_50" + std::string(10, 'c'));
    }
    check("no files were added, removed or rewritten by the refused compaction",
          tu::list_dir(dir) == files_before && tu::read_file(dir + "/" + tu::seg_name(0)) == seg0_before);
    tu::rm_rf(dir);
}

int main() {
    scenario_b();
    scenario_model_with_compactions();
    scenario_edges();
    scenario_corrupt_source_aborts();
    return tu::summary();
}
