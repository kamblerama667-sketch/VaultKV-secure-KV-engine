// test_crash_syscalls.cpp
//
// Exhaustive crash testing at SYSCALL granularity. The linker wraps every
// disk-mutating libc call the engine makes (open for write/create, write,
// pwrite, fsync, ftruncate, rename, unlink). A child process is armed to die
// (_exit) just BEFORE the Nth such call; the parent then reopens the database
// and checks it. N is walked from 1 until the child finishes without being
// killed, so every state between every pair of mutating calls is tested --
// including ones nobody thought to put a named crash point on.
//
//   A. compaction, over three data layouts
//   B. sealing/rolling segments while writing (hint files, new segments)
//   C. startup itself (finishing an interrupted compaction's cleanup,
//      sealing an over-limit active segment)
//
// Build (the --wrap flags are required; one command line):
//   g++ -std=c++17 -O2 -pthread test_crash_syscalls.cpp -o test_crash_syscalls
//       -Wl,--wrap=open,--wrap=write,--wrap=pwrite,--wrap=fsync,--wrap=rename,--wrap=unlink,--wrap=ftruncate
#include "segmented_engine.hpp"
#include "test_util.hpp"

#include <cstdarg>
#include <map>
#include <sys/wait.h>

static bool g_armed = false;
static long g_count = 0, g_die_at = 0;
static void tick() { if (g_armed && ++g_count == g_die_at) ::_exit(77); }

extern "C" {
int __real_open(const char*, int, ...);
ssize_t __real_write(int, const void*, size_t);
ssize_t __real_pwrite(int, const void*, size_t, off_t);
int __real_fsync(int);
int __real_rename(const char*, const char*);
int __real_unlink(const char*);
int __real_ftruncate(int, off_t);

int __wrap_open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (flags & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) tick();
    return __real_open(path, flags, mode);
}
ssize_t __wrap_write(int fd, const void* b, size_t n) { tick(); return __real_write(fd, b, n); }
ssize_t __wrap_pwrite(int fd, const void* b, size_t n, off_t o) { tick(); return __real_pwrite(fd, b, n, o); }
int __wrap_fsync(int fd) { tick(); return __real_fsync(fd); }
int __wrap_rename(const char* a, const char* b) { tick(); return __real_rename(a, b); }
int __wrap_unlink(const char* p) { tick(); return __real_unlink(p); }
int __wrap_ftruncate(int fd, off_t n) { tick(); return __real_ftruncate(fd, n); }
}

using kvengine::SegmentedKVEngine;
using tu::check;
using Model = std::map<std::string, std::string>;

static constexpr uint64_t TH = 400;

static bool matches(SegmentedKVEngine& db, const Model& m, std::string* why) {
    if (db.size() != m.size()) { *why = "size " + std::to_string(db.size()) + " != " + std::to_string(m.size()); return false; }
    for (const auto& [k, v] : m) { auto g = db.get(k); if (!g || *g != v) { *why = "bad/missing " + k; return false; } }
    return true;
}
static void copy_dir(const std::string& from, const std::string& to) {
    tu::rm_rf(to); ::mkdir(to.c_str(), 0755);
    for (const auto& n : tu::list_dir(from)) tu::copy_file(from + "/" + n, to + "/" + n);
}
static Model build_layout(const std::string& dir, int shape) {
    tu::rm_rf(dir);
    Model m;
    SegmentedKVEngine db(dir, TH, 8);
    auto put = [&](const std::string& k, const std::string& v) { db.put(k, v); m[k] = v; };
    auto del = [&](const std::string& k) { db.del(k); m.erase(k); };
    for (int round = 0; round < 5; ++round)
        for (int i = 0; i < 20; ++i) put("k" + std::to_string(i), "r" + std::to_string(round) + "_" + std::to_string(i) + std::string(10, 'a'));
    for (int i = 0; i < 20; i += 3) del("k" + std::to_string(i));
    if (shape >= 1) for (int i = 0; i < 20; i += 3) put("k" + std::to_string(i), "reborn" + std::to_string(i));
    if (shape >= 2) { for (int i = 0; i < 25; ++i) put("pad" + std::to_string(i), std::string(35, 'p')); del("k1"); del("pad3"); }
    return m;
}

// Runs `body` in a child, dying before the Nth mutating syscall. Returns true
// if the child was killed (so there may be more points), false if it finished.
template <typename F> static bool run_until_crash(long n, F body) {
    const pid_t pid = ::fork();
    if (pid == 0) { g_count = 0; g_die_at = n; g_armed = false; body(); ::_exit(0); }
    int status = 0; ::waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 77;
}

static void part_a() {
    std::cout << "=== A: compaction, killed before EVERY mutating syscall ===\n";
    for (int shape = 0; shape <= 2; ++shape) {
        const std::string dir = "cs_a", tpl = "cs_a_tpl";
        const Model model = build_layout(tpl, shape);
        long points = 0; bool all_ok = true; std::string why, first_bad;
        for (long n = 1; n < 100000; ++n) {
            copy_dir(tpl, dir);
            const bool crashed = run_until_crash(n, [&] { SegmentedKVEngine db(dir, TH, 8); g_armed = true; db.compact(); });
            if (!crashed) break;
            ++points;
            for (int again = 0; again < 3 && all_ok; ++again) {
                try {
                    SegmentedKVEngine db(dir, TH, 8);
                    if (!matches(db, model, &why)) all_ok = false;
                    else if (again == 1 && !(db.compact() && matches(db, model, &why))) { all_ok = false; why = "compaction after crash: " + why; }
                } catch (const std::exception& e) { all_ok = false; why = std::string("reopen threw: ") + e.what(); }
            }
            if (!all_ok && first_bad.empty()) { first_bad = "before syscall #" + std::to_string(n) + ": " + why; break; }
        }
        check("layout " + std::to_string(shape) + ": " + std::to_string(points) + " crash points, reopen identical every time" +
              (first_bad.empty() ? "" : " [" + first_bad + "]"), all_ok && points > 10);
        tu::rm_rf(dir); tu::rm_rf(tpl);
    }
}

static void part_b() {
    std::cout << "\n=== B: sealing/rolling while writing, killed before EVERY mutating syscall ===\n";
    const std::string dir = "cs_b", tpl = "cs_b_tpl";
    const Model base = build_layout(tpl, 1);
    long points = 0; bool all_ok = true; std::string first_bad;
    auto val = [](int i) { return "new_" + std::to_string(i) + std::string(15 + i % 9, 'n'); };
    for (long n = 1; n < 100000; ++n) {
        copy_dir(tpl, dir);
        const bool crashed = run_until_crash(n, [&] {
            SegmentedKVEngine db(dir, TH, 8); g_armed = true;
            for (int i = 0; i < 40; ++i) db.put("new" + std::to_string(i), val(i));
            db.del("k2");
        });
        if (!crashed) break;
        ++points;
        try {
            for (int again = 0; again < 2 && all_ok; ++again) {
                SegmentedKVEngine db(dir, TH, 8);
                for (const auto& [k, v] : base) { // everything that existed before must survive (k2 may or may not be deleted)
                    auto g = db.get(k);
                    if (k == "k2") { if (g && *g != v) all_ok = false; }
                    else if (!g || *g != v) { all_ok = false; first_bad = "before syscall #" + std::to_string(n) + ": lost/changed " + k; }
                }
                for (int i = 0; i < 40; ++i) { auto g = db.get("new" + std::to_string(i)); if (g && *g != val(i)) { all_ok = false; first_bad = "before syscall #" + std::to_string(n) + ": wrong value for new" + std::to_string(i); } }
                if (again == 0) for (int i = 0; i < 30; ++i) db.put("post" + std::to_string(i), std::string(30, 'z')); // writing after recovery works
                for (int i = 0; i < 30 && again == 1; ++i) { auto g = db.get("post" + std::to_string(i)); if (!g || *g != std::string(30, 'z')) { all_ok = false; first_bad = "post-recovery writes lost after restart"; } }
            }
        } catch (const std::exception& e) { all_ok = false; first_bad = std::string("reopen threw: ") + e.what(); }
        if (!all_ok) break;
    }
    check(std::to_string(points) + " crash points: pre-existing data intact, no wrong values, writes after recovery survive" +
          (first_bad.empty() ? "" : " [" + first_bad + "]"), all_ok && points > 30);
    tu::rm_rf(dir); tu::rm_rf(tpl);
}

static void part_c() {
    std::cout << "\n=== C: crash DURING STARTUP (finishing a compaction's cleanup, sealing an over-limit segment) ===\n";
    const std::string dir = "cs_c", tpl = "cs_c_tpl", src = "cs_c_src";
    const Model model = build_layout(src, 2);
    // Leave the directory in the "committed but not cleaned up" state: die at the first unlink of a superseded segment.
    // (Counting syscalls from the start of compact(); find the one that is the first unlink after the rename by probing.)
    long committed_n = -1;
    for (long n = 1; n < 100000 && committed_n < 0; ++n) {
        copy_dir(src, tpl);
        if (!run_until_crash(n, [&] { SegmentedKVEngine db(tpl, TH, 8); g_armed = true; db.compact(); })) break;
        // The state we want: marker segment in place AND older segments still present.
        std::vector<std::string> segs;
        for (const auto& f : tu::list_dir(tpl)) if (f.size() > 4 && f.substr(f.size() - 4) == ".seg") segs.push_back(f);
        const std::string top_sealed = segs.size() >= 3 ? segs[segs.size() - 2] : "";
        if (!top_sealed.empty() && tu::file_size(tpl + "/" + top_sealed) > 0) {
            const std::string head = tu::read_file(tpl + "/" + top_sealed).substr(0, 20);
            uint32_t vlen = 0; if (head.size() == 20) std::memcpy(&vlen, head.data() + 16, 4);
            if (vlen == kvengine::COMPACTION_BASE && segs.size() > 3) committed_n = n;
        }
    }
    check("setup: found a committed-but-not-cleaned-up directory state", committed_n > 0);
    if (committed_n < 0) return;
    copy_dir(src, tpl);
    run_until_crash(committed_n, [&] { SegmentedKVEngine db(tpl, TH, 8); g_armed = true; db.compact(); });

    long points = 0; bool all_ok = true; std::string why, first_bad;
    for (long n = 1; n < 100000; ++n) {
        copy_dir(tpl, dir);
        const bool crashed = run_until_crash(n, [&] { g_armed = true; SegmentedKVEngine db(dir, TH, 8); });
        if (!crashed) break;
        ++points;
        for (int again = 0; again < 2 && all_ok; ++again) {
            try { SegmentedKVEngine db(dir, TH, 8); if (!matches(db, model, &why)) all_ok = false; }
            catch (const std::exception& e) { all_ok = false; why = std::string("reopen threw: ") + e.what(); }
        }
        if (!all_ok) { first_bad = "before syscall #" + std::to_string(n) + ": " + why; break; }
    }
    check(std::to_string(points) + " crash points during startup recovery: reopen identical every time" +
          (first_bad.empty() ? "" : " [" + first_bad + "]"), all_ok && points > 3);
    tu::rm_rf(dir); tu::rm_rf(tpl); tu::rm_rf(src);
}

int main() {
    part_a();
    part_b();
    part_c();
    return tu::summary();
}
