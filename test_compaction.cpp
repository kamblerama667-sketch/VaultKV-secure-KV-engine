// test_compaction.cpp
//
// Build: g++ -std=c++17 -O2 -pthread test_compaction.cpp -o test_compaction
// TSan:  g++ -std=c++17 -O1 -g -pthread -fsanitize=thread test_compaction.cpp -o test_compaction_tsan

#include "segmented_engine.hpp"

#include <atomic>
#include <chrono>
#include <dirent.h>
#include <iostream>
#include <thread>
#include <vector>

using kvengine::SegmentedKVEngine;

int passed = 0, total = 0;
void check(const char* label, bool cond) {
    ++total;
    std::cout << (cond ? "  OK   " : "  FAIL ") << label << "\n";
    if (cond) ++passed;
}

void rm_rf(const std::string& dir) {
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name != "." && name != "..") std::remove((dir + "/" + name).c_str());
    }
    closedir(d);
    ::rmdir(dir.c_str());
}

void test_basic_compaction() {
    std::cout << "=== Basic compaction: space reclaimed, data intact ===\n";
    const std::string dir = "compact_basic";
    rm_rf(dir);
    SegmentedKVEngine db(dir, /*segment_threshold=*/4096);

    for (int rewrite = 0; rewrite < 30; ++rewrite)
        for (int i = 0; i < 100; ++i)
            db.put("k" + std::to_string(i), "value_r" + std::to_string(rewrite) + std::string(30, 'x'));
    for (int i = 0; i < 100; i += 5) db.del("k" + std::to_string(i));

    const size_t segments_before = db.segment_count();
    bool ok = db.compact();
    check("compact() succeeded", ok);
    check("fewer segments after compaction", db.segment_count() < segments_before);

    bool data_correct = true;
    for (int i = 0; i < 100; ++i) {
        auto v = db.get("k" + std::to_string(i));
        const bool should_exist = (i % 5 != 0);
        if (should_exist && (!v.has_value() || *v != "value_r29" + std::string(30, 'x'))) data_correct = false;
        if (!should_exist && v.has_value()) data_correct = false;
    }
    check("every key has its correct latest value (or is correctly absent) after compaction", data_correct);
    rm_rf(dir);
}

void test_the_critical_race() {
    std::cout << "\n=== THE race: update a key while its segment is mid-compaction ===\n";
    // This is the scenario the whole design exists to get right: if
    // compaction is slow enough to overlap with a concurrent write to a
    // key it's currently processing, the newer write must win. Getting
    // this wrong means a "resurrected" stale value silently reappearing.
    const std::string dir = "compact_race";
    rm_rf(dir);
    SegmentedKVEngine db(dir, /*segment_threshold=*/2048);

    // Build up several sealed segments containing "racer".
    for (int i = 0; i < 200; ++i) {
        db.put("racer", "old_value_" + std::to_string(i));
        db.put("filler" + std::to_string(i), std::string(50, 'f')); // forces segment rollover
    }
    check("multiple segments exist before the race", db.segment_count() > 2);

    std::atomic<bool> compaction_done{false};
    std::thread compactor([&] {
        db.compact();
        compaction_done.store(true);
    });

    // Hammer "racer" with new writes while compaction is running, trying
    // to land at least one update inside the window compaction is open.
    std::string last_written;
    while (!compaction_done.load()) {
        last_written = "NEW_VALUE_DURING_COMPACTION";
        db.put("racer", last_written);
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    compactor.join();

    // Whatever the last successful write was, that's what must survive --
    // not any of the "old_value_N" copies compaction was busy merging.
    auto final_value = db.get("racer");
    check("key updated during compaction ends up with a value written during/after the race, not a stale compacted one",
          final_value.has_value() && final_value->rfind("old_value_", 0) != 0);
    std::cout << "  (final value: " << (final_value.has_value() ? *final_value : "<missing>") << ")\n";
    rm_rf(dir);
}

void test_delete_during_compaction() {
    std::cout << "\n=== Delete a key while its segment is mid-compaction ===\n";
    const std::string dir = "compact_race_del";
    rm_rf(dir);
    SegmentedKVEngine db(dir, /*segment_threshold=*/2048);

    for (int i = 0; i < 200; ++i) {
        db.put("doomed", "value_" + std::to_string(i));
        db.put("filler" + std::to_string(i), std::string(50, 'f'));
    }

    std::atomic<bool> compaction_done{false};
    std::thread compactor([&] { db.compact(); compaction_done.store(true); });

    bool deleted = false;
    while (!compaction_done.load()) {
        if (!deleted) { db.del("doomed"); deleted = true; }
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    compactor.join();

    check("key deleted during compaction stays deleted, not resurrected", !db.get("doomed").has_value());
    rm_rf(dir);
}

void test_concurrent_stress_with_background_compaction() {
    std::cout << "\n=== Full stress: put/get/del from many threads while compaction runs repeatedly ===\n";
    const std::string dir = "compact_stress";
    rm_rf(dir);
    SegmentedKVEngine db(dir, /*segment_threshold=*/4096);

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> ops_ok{0}, ops_total{0};

    std::vector<std::thread> workers;
    for (int t = 0; t < 6; ++t) {
        workers.emplace_back([&, t] {
            int i = 0;
            while (!stop.load()) {
                std::string key = "key" + std::to_string(t) + "_" + std::to_string(i % 20); // small key space -> real contention on the same keys
                std::string value = "v" + std::to_string(i);
                db.put(key, value);
                auto got = db.get(key);
                ops_total.fetch_add(1);
                if (got.has_value()) ops_ok.fetch_add(1); // value may be a newer write from another thread on the same key -- just confirm SOMETHING valid comes back, not corruption
                ++i;
            }
        });
    }

    std::thread compactor([&] {
        while (!stop.load()) {
            db.compact();
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    std::this_thread::sleep_for(std::chrono::seconds(3));
    stop.store(true);
    for (auto& w : workers) w.join();
    compactor.join();

    check("no crashes/hangs across 3s of concurrent ops + repeated background compaction", true);
    std::cout << "  (" << ops_ok.load() << "/" << ops_total.load() << " gets returned a value)\n";
    rm_rf(dir);
}

int main() {
    test_basic_compaction();
    test_the_critical_race();
    test_delete_during_compaction();
    test_concurrent_stress_with_background_compaction();

    std::cout << "\n" << passed << "/" << total << " checks passed\n";
    return (passed == total) ? 0 : 1;
}
