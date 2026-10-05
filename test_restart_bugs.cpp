// test_restart_bugs.cpp
//
// Permanent regression tests for the restart bugs in segmented_engine.hpp.
// Every scenario closes and reopens the engine at least twice, which the
// earlier suites never did.
//
//   A. Keys written before a restart vanish after the active segment seals
//      following that restart (the hint only lists post-restart records).
//   C. Active segment already over the size limit at restart: it seals
//      immediately with an empty hint, and its keys vanish on the next open.
//
// Bug B (compaction vs. restart) lives in test_compaction_restart.cpp.
//
// Build: g++ -std=c++17 -O2 -pthread test_restart_bugs.cpp -o test_restart_bugs
// ASan:  g++ -std=c++17 -O1 -g -pthread -fsanitize=address,undefined test_restart_bugs.cpp -o test_restart_bugs_asan

#include "segmented_engine.hpp"

#include "test_util.hpp"
#include <unordered_map>

using kvengine::SegmentedKVEngine;

using tu::check;
using tu::rm_rf;

static int count_present(SegmentedKVEngine& db, const std::string& prefix, int n) {
    int found = 0;
    for (int i = 0; i < n; ++i) {
        auto v = db.get(prefix + std::to_string(i));
        if (v.has_value() && *v == "val_" + prefix + std::to_string(i)) ++found;
    }
    return found;
}

// Scenario A: write 10 keys, close. Reopen and write enough to fill and seal
// that same segment. Close. Reopen. The 10 keys must still be there.
static void scenario_a() {
    std::cout << "=== A: keys written before a restart survive that segment sealing ===\n";
    const std::string dir = "restart_a";
    rm_rf(dir);
    {
        SegmentedKVEngine db(dir, /*segment_threshold=*/2048);
        for (int i = 0; i < 10; ++i) db.put("early" + std::to_string(i), "val_early" + std::to_string(i));
    }
    {
        SegmentedKVEngine db(dir, 2048);
        for (int i = 0; i < 200; ++i) db.put("late" + std::to_string(i), "val_late" + std::to_string(i));
        check("A: engine rolled to more than one segment", db.segment_count() > 1);
    }
    {
        SegmentedKVEngine db(dir, 2048);
        const int early = count_present(db, "early", 10);
        const int late = count_present(db, "late", 200);
        check("A: all 10 pre-restart keys present (got " + std::to_string(early) + "/10)", early == 10);
        check("A: all 200 post-restart keys present (got " + std::to_string(late) + "/200)", late == 200);
    }
    rm_rf(dir);
}

// Scenario C: write until the active segment just crosses its limit without
// rolling, close, reopen, write one key, close, reopen. Nothing may be lost.
static void scenario_c() {
    std::cout << "\n=== C: segment over its limit at restart keeps its keys ===\n";
    const std::string dir = "restart_c";
    rm_rf(dir);
    int written = 0;
    {
        SegmentedKVEngine db(dir, /*segment_threshold=*/2048);
        // Write until the active segment is at or over the limit but has not
        // rolled yet (rolling happens at the start of the NEXT write).
        while (db.active_segment_bytes() < 2048) {
            db.put("c" + std::to_string(written), "val_c" + std::to_string(written));
            ++written;
        }
        check("C: setup left exactly one segment, at or over the limit",
              db.segment_count() == 1 && db.active_segment_bytes() >= 2048);
    }
    {
        SegmentedKVEngine db(dir, 2048);
        db.put("after_restart", "val_after_restart");
    }
    {
        SegmentedKVEngine db(dir, 2048);
        const int found = count_present(db, "c", written);
        check("C: all " + std::to_string(written) + " original keys present (got " + std::to_string(found) + ")",
              found == written);
        auto v = db.get("after_restart");
        check("C: key written after the restart present", v.has_value() && *v == "val_after_restart");
    }
    rm_rf(dir);
}

// Extra coverage in the same spirit: many restarts in a row, each followed by
// a few writes, with an overwrite and a delete thrown in. A model map is the
// source of truth.
static void scenario_repeated_restarts() {
    std::cout << "\n=== Repeated restarts against a model ===\n";
    const std::string dir = "restart_many";
    rm_rf(dir);
    std::unordered_map<std::string, std::string> model;
    bool ok = true;
    int counter = 0;
    for (int round = 0; round < 40 && ok; ++round) {
        SegmentedKVEngine db(dir, /*segment_threshold=*/1024);
        // Verify everything the model says is there, and nothing else.
        if (db.size() != model.size()) ok = false;
        for (const auto& [k, v] : model) {
            auto got = db.get(k);
            if (!got.has_value() || *got != v) { ok = false; break; }
        }
        const int writes = 3 + (round * 7) % 25;
        for (int i = 0; i < writes; ++i) {
            const std::string key = "k" + std::to_string((counter * 5 + i) % 40);
            const std::string val = "v" + std::to_string(counter++);
            db.put(key, val);
            model[key] = val;
        }
        if (round % 3 == 0 && !model.empty()) {
            const std::string victim = model.begin()->first;
            db.del(victim);
            model.erase(victim);
        }
    }
    check("40 consecutive restarts: engine always matches the model", ok);
    rm_rf(dir);
}

int main() {
    scenario_a();
    scenario_c();
    scenario_repeated_restarts();
    return tu::summary();
}
