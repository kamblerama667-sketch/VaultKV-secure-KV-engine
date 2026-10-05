// test_crash_harness.cpp
//
// Part 1: deterministic crash points. For each of the six numbered points
//         inside compact(), a child process dies exactly there (_exit(77)),
//         and the parent checks that the database reopens with exactly the
//         same contents -- over several different data layouts.
// Part 2: random SIGKILL. A child runs a random put/delete/compact workload
//         (small segments, so it seals and compacts constantly); the parent
//         kills it at a random moment, reopens, and compares EVERYTHING to a
//         model of the operations the child reported as completed. The one
//         operation in flight at the kill may or may not have landed; either
//         outcome is accepted, nothing else is.
//
// Build: g++ -std=c++17 -O2 -pthread test_crash_harness.cpp -o test_crash_harness
// Run:   ./test_crash_harness [kill_iterations=1500]
#include "segmented_engine.hpp"
#include "test_util.hpp"

#include <csignal>
#include <map>
#include <random>
#include <sys/wait.h>

using kvengine::SegmentedKVEngine;
using tu::check;
using Model = std::map<std::string, std::string>;

static bool matches(SegmentedKVEngine& db, const Model& m, std::string* why = nullptr) {
    if (db.size() != m.size()) { if (why) *why = "size " + std::to_string(db.size()) + " != " + std::to_string(m.size()); return false; }
    for (const auto& [k, v] : m) {
        auto g = db.get(k);
        if (!g) { if (why) *why = "missing " + k; return false; }
        if (*g != v) { if (why) *why = "wrong value for " + k; return false; }
    }
    return true;
}

// ------------------------------------------------------------------ part 1

// Builds a layout and returns the logical contents. `shape` varies the layout.
static Model build_layout(const std::string& dir, int shape) {
    tu::rm_rf(dir);
    Model m;
    SegmentedKVEngine db(dir, 400, 8);
    auto put = [&](const std::string& k, const std::string& v) { db.put(k, v); m[k] = v; };
    auto del = [&](const std::string& k) { db.del(k); m.erase(k); };
    for (int round = 0; round < 6; ++round)
        for (int i = 0; i < 25; ++i) put("k" + std::to_string(i), "r" + std::to_string(round) + "_" + std::to_string(i) + std::string(10, 'a'));
    for (int i = 0; i < 25; i += 3) del("k" + std::to_string(i));       // tombstones for keys whose puts are in OLD segments
    if (shape >= 1) { for (int i = 0; i < 25; i += 3) put("k" + std::to_string(i), "reborn" + std::to_string(i)); } // delete then re-put
    if (shape >= 2) { for (int i = 0; i < 30; ++i) put("pad" + std::to_string(i), std::string(35, 'p')); del("k1"); del("pad3"); } // tombstones in the ACTIVE segment
    return m;
}

static void crash_point_tests() {
    std::cout << "=== Part 1: process dies at each of the 6 crash points inside compact() ===\n";
    const char* names[] = {"", "merged file written", "old hint removed", "renamed into place (commit)",
                           "some old segments deleted", "all old segments deleted", "hint written (done)"};
    for (int shape = 0; shape <= 2; ++shape) {
        for (int step = 1; step <= 6; ++step) {
            const std::string dir = "ch_point";
            const Model model = build_layout(dir, shape);
            const pid_t pid = ::fork();
            if (pid == 0) {
                SegmentedKVEngine db(dir, 400, 8);
                db.set_crash_failpoint_for_testing(step);
                db.compact();
                ::_exit(0); // reached only if the failpoint never fired
            }
            int status = 0; ::waitpid(pid, &status, 0);
            const bool died_there = WIFEXITED(status) && WEXITSTATUS(status) == 77;
            std::string why; bool ok = true;
            for (int again = 0; again < 3 && ok; ++again) { // reopening must be stable (and finish any cleanup)
                SegmentedKVEngine db(dir, 400, 8);
                ok = matches(db, model, &why);
                if (ok && again == 1) ok = db.compact() && matches(db, model, &why); // compaction after the crash works
            }
            bool tmp_left = false;
            for (const auto& n : tu::list_dir(dir)) if (n.find(".tmp") != std::string::npos) tmp_left = true;
            check("layout " + std::to_string(shape) + ", crash after \"" + names[step] + "\": died there, reopens identical" +
                  (why.empty() ? "" : " [" + why + "]"), died_there && ok && !tmp_left);
            tu::rm_rf(dir);
        }
    }
}

// ------------------------------------------------------------------ part 2

#pragma pack(push, 1)
struct Msg { uint8_t phase; uint8_t op; uint16_t pad; uint32_t key; uint64_t seq; }; // 16 bytes < PIPE_BUF: atomic writes
#pragma pack(pop)
static_assert(sizeof(Msg) == 16, "Msg must be 16 bytes");
static constexpr int KEYS = 40;

static std::string make_value(uint32_t key, uint64_t seq) {
    return "v" + std::to_string(seq) + "_" + std::string((seq % 23) + (key % 7), 'x');
}

[[noreturn]] static void child_main(const std::string& dir, uint64_t seed, uint64_t seq_base, int wfd) {
    SegmentedKVEngine db(dir, 600, 16);
    std::mt19937_64 rng(seed);
    uint64_t seq = seq_base;
    auto send = [&](uint8_t phase, uint8_t op, uint32_t key, uint64_t s) {
        Msg m{phase, op, 0, key, s};
        if (::write(wfd, &m, sizeof m) != static_cast<ssize_t>(sizeof m)) ::_exit(3);
    };
    for (;;) {
        const int r = static_cast<int>(rng() % 100);
        const uint32_t key = static_cast<uint32_t>(rng() % KEYS);
        ++seq;
        if (r < 60)      { send(0, 'P', key, seq); db.put("k" + std::to_string(key), make_value(key, seq)); send(1, 'P', key, seq); }
        else if (r < 88) { send(0, 'D', key, seq); db.del("k" + std::to_string(key));                       send(1, 'D', key, seq); }
        else             { send(0, 'C', 0, seq);   db.compact();                                           send(1, 'C', 0, seq); }
    }
}

static void random_kill_tests(int iterations) {
    std::cout << "\n=== Part 2: " << iterations << " random SIGKILLs, verified against a model after each ===\n";
    const std::string dir = "ch_kill";
    tu::rm_rf(dir);
    Model model;
    std::mt19937_64 rng(0xC0FFEE);
    uint64_t seq_base = 1000;
    int bad = 0, in_compaction = 0, in_put = 0, in_del = 0, ambiguous_landed = 0, ambiguous_lost = 0;
    std::string first_failure;

    for (int it = 0; it < iterations; ++it) {
        int fds[2];
        if (::pipe(fds) != 0) { std::perror("pipe"); return; }
        const pid_t pid = ::fork();
        if (pid == 0) { ::close(fds[0]); child_main(dir, rng(), seq_base, fds[1]); }
        ::close(fds[1]);
        ::usleep(static_cast<useconds_t>(rng() % 6000));
        ::kill(pid, SIGKILL);
        int status = 0; ::waitpid(pid, &status, 0);
        seq_base += 1000000;

        // Everything the child reported before it died.
        std::vector<Msg> msgs; Msg m;
        while (::read(fds[0], &m, sizeof m) == static_cast<ssize_t>(sizeof m)) msgs.push_back(m);
        ::close(fds[0]);

        bool pending = false; Msg pend{};
        for (const Msg& x : msgs) {
            if (x.phase == 0) { pending = true; pend = x; continue; }
            pending = false;
            const std::string k = "k" + std::to_string(x.key);
            if (x.op == 'P') model[k] = make_value(x.key, x.seq);
            else if (x.op == 'D') model.erase(k);
        }
        if (pending) { if (pend.op == 'C') ++in_compaction; else if (pend.op == 'P') ++in_put; else ++in_del; }

        // Reopen (this is the restart under test) and compare.
        try {
            SegmentedKVEngine db(dir, 600, 16);
            std::string why; bool ok = true;
            const std::string pk = pending && pend.op != 'C' ? "k" + std::to_string(pend.key) : "";
            for (int i = 0; i < KEYS && ok; ++i) {
                const std::string k = "k" + std::to_string(i);
                const auto got = db.get(k);
                const auto expect = model.find(k);
                const bool have = expect != model.end();
                bool same = (have && got && *got == expect->second) || (!have && !got);
                if (!same && k == pk) { // the in-flight operation: accept "applied" too
                    const bool applied = pend.op == 'P' ? (got && *got == make_value(pend.key, pend.seq)) : !got;
                    if (applied) { same = true; ++ambiguous_landed; }
                    if (applied) { if (pend.op == 'P') model[k] = *got; else model.erase(k); }
                } else if (same && k == pk) ++ambiguous_lost;
                if (!same) { ok = false; why = "key " + k + (got ? " has unexpected value" : " missing"); }
            }
            size_t present = 0;
            for (int i = 0; i < KEYS; ++i) if (db.get("k" + std::to_string(i))) ++present;
            if (ok && db.size() != present) { ok = false; why = "index size " + std::to_string(db.size()) + " != " + std::to_string(present) + " readable keys"; }
            if (!ok) { ++bad; if (first_failure.empty()) first_failure = "iteration " + std::to_string(it) + ": " + why; break; }
        } catch (const std::exception& e) {
            ++bad; if (first_failure.empty()) first_failure = "iteration " + std::to_string(it) + ": reopen threw: " + e.what();
            break;
        }
    }
    check(std::to_string(iterations) + " kill/restart cycles: database always matched the model", bad == 0);
    if (bad) std::cout << "       first failure: " << first_failure << "\n";
    std::cout << "       kills landed in: compaction=" << in_compaction << ", put=" << in_put << ", delete=" << in_del
              << "  (in-flight op had landed=" << ambiguous_landed << ", had not=" << ambiguous_lost << ")\n";
    check("kills actually landed inside compactions (coverage sanity)", in_compaction > 0);
    tu::rm_rf(dir);
}

int main(int argc, char** argv) {
    const int iterations = argc > 1 ? std::atoi(argv[1]) : 1500;
    crash_point_tests();
    random_kill_tests(iterations);
    return tu::summary();
}
