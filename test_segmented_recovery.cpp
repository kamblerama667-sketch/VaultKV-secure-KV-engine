// test_segmented_recovery.cpp
//
// Two things the demo doesn't cover: (1) a genuinely torn active segment
// -- truncated mid-record, exactly what a crash mid-write leaves behind --
// recovers correctly while untouched sealed segments (with valid hints)
// are unaffected, and (2) concurrent put/get/del from real threads
// produces zero data races under ThreadSanitizer.

#include "segmented_engine.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <vector>

using kvengine::SegmentedKVEngine;

void rm_rf(const std::string& dir) {
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::remove((dir + "/" + name).c_str());
    }
    closedir(d);
    ::rmdir(dir.c_str());
}

int main() {
    // --- Test A: torn active segment, sealed segments untouched ---
    const std::string dirA = "segtest_crash";
    rm_rf(dirA);
    {
        SegmentedKVEngine db(dirA, /*segment_threshold=*/2048);
        for (int i = 0; i < 100; ++i) db.put("k" + std::to_string(i), "value_" + std::to_string(i));
    }
    // Find the highest-numbered .seg file (the active one) and chop its tail.
    {
        std::vector<std::string> segs;
        DIR* d = opendir(dirA.c_str());
        struct dirent* entry;
        while ((entry = readdir(d)) != nullptr) {
            std::string name = entry->d_name;
            if (name.size() == 10 && name.substr(6) == ".seg") segs.push_back(name);
        }
        closedir(d);
        std::sort(segs.begin(), segs.end());
        std::string active_path = dirA + "/" + segs.back();
        int fd = open(active_path.c_str(), O_RDWR);
        off_t sz = lseek(fd, 0, SEEK_END);
        if (ftruncate(fd, sz > 5 ? sz - 5 : 0) != 0) { /* best-effort for this test */ }
        close(fd);
        std::cout << "Truncated " << segs.back() << " by 5 bytes (simulated crash mid-record)\n";
    }
    {
        SegmentedKVEngine db(dirA);
        std::cout << "Recovered " << db.size() << " keys (expect 99 or 100 depending on where the cut landed), "
                   << db.full_scan_recoveries() << " full-scan (expect 1, the torn active segment), "
                   << db.hint_recoveries() << " via hint (sealed segments, untouched)\n";

        bool sealed_intact = true;
        for (int i = 0; i < 90; ++i) { // comfortably inside the earlier, sealed segments
            auto v = db.get("k" + std::to_string(i));
            if (!v.has_value() || *v != "value_" + std::to_string(i)) sealed_intact = false;
        }
        std::cout << "Sealed-segment data (well before the truncation point) intact: "
                  << (sealed_intact ? "OK" : "FAILED") << "\n";

        db.put("post_crash_key", "post_crash_value");
        auto v = db.get("post_crash_key");
        std::cout << "Write after recovery works: "
                  << ((v.has_value() && *v == "post_crash_value") ? "OK" : "FAILED") << "\n\n";
    }

    // --- Test B: concurrency stress (run this binary under -fsanitize=thread) ---
    const std::string dirB = "segtest_concurrency";
    rm_rf(dirB);
    {
        SegmentedKVEngine db(dirB, /*segment_threshold=*/8192); // small, so this also exercises rollover under concurrency
        constexpr int N_THREADS = 8;
        constexpr int OPS_PER_THREAD = 3000;
        std::atomic<int> total_ok{0};

        std::vector<std::thread> workers;
        for (int t = 0; t < N_THREADS; ++t) {
            workers.emplace_back([&db, &total_ok, t] {
                int ok = 0;
                for (int i = 0; i < OPS_PER_THREAD; ++i) {
                    std::string key = std::to_string(t) + "_" + std::to_string(i);
                    if (db.put(key, "v_" + key)) ++ok;
                    auto v = db.get(key);
                    if (v.has_value() && *v == "v_" + key) ++ok;
                    if (i % 10 == 0) { db.del(key); if (!db.get(key).has_value()) ++ok; }
                }
                total_ok += ok;
            });
        }
        for (auto& w : workers) w.join();

        const int expected = N_THREADS * OPS_PER_THREAD * 2 + N_THREADS * (OPS_PER_THREAD / 10);
        std::cout << "Concurrency: " << total_ok.load() << "/" << expected << " ops confirmed correct, "
                  << db.segment_count() << " segments, " << db.size() << " live keys\n";
    }

    rm_rf(dirA);
    rm_rf(dirB);
    return 0;
}
