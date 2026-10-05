#pragma once
// test_util.hpp -- tiny shared helpers for the VaultKV test programs.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace tu {

inline const bool unbuffered = (std::cout << std::unitbuf, true); // so output survives a hang/kill
inline int passed = 0, total = 0;

inline void check(const std::string& label, bool cond) {
    ++total;
    std::cout << (cond ? "  OK   " : "  FAIL ") << label << "\n";
    if (cond) ++passed;
}
inline int summary() {
    std::cout << "\n" << passed << "/" << total << " checks passed\n";
    return passed == total ? 0 : 1;
}

inline std::vector<std::string> list_dir(const std::string& dir) {
    std::vector<std::string> names;
    if (DIR* d = ::opendir(dir.c_str())) {
        while (dirent* e = ::readdir(d)) {
            const std::string n = e->d_name;
            if (n != "." && n != "..") names.push_back(n);
        }
        ::closedir(d);
    }
    std::sort(names.begin(), names.end());
    return names;
}
inline void rm_rf(const std::string& dir) {
    for (const auto& n : list_dir(dir)) {
        const std::string p = dir + "/" + n;
        struct stat st{};
        if (::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) rm_rf(p);
        else std::remove(p.c_str());
    }
    ::rmdir(dir.c_str());
}
inline uint64_t file_size(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 ? static_cast<uint64_t>(st.st_size) : 0;
}
inline bool exists(const std::string& path) { struct stat st{}; return ::stat(path.c_str(), &st) == 0; }

inline std::string read_file(const std::string& path) {
    std::string out;
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return out;
    char buf[4096]; ssize_t n;
    while ((n = ::read(fd, buf, sizeof buf)) > 0) out.append(buf, static_cast<size_t>(n));
    ::close(fd);
    return out;
}
inline void write_file(const std::string& path, const std::string& data) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t w = ::write(fd, data.data() + off, data.size() - off);
        if (w <= 0) break;
        off += static_cast<size_t>(w);
    }
    ::close(fd);
}
inline void copy_file(const std::string& from, const std::string& to) { write_file(to, read_file(from)); }
inline void truncate_to(const std::string& path, uint64_t size) { if (::truncate(path.c_str(), static_cast<off_t>(size)) != 0) {} }
inline void flip_bit(const std::string& path, uint64_t off, int bit) {
    const int fd = ::open(path.c_str(), O_RDWR);
    if (fd < 0) return;
    uint8_t b = 0;
    if (::pread(fd, &b, 1, static_cast<off_t>(off)) == 1) { b ^= static_cast<uint8_t>(1u << bit); if (::pwrite(fd, &b, 1, static_cast<off_t>(off)) != 1) {} }
    ::close(fd);
}
inline void put_u32_at(const std::string& path, uint64_t off, uint32_t v) {
    const int fd = ::open(path.c_str(), O_RDWR);
    if (fd < 0) return;
    if (::pwrite(fd, &v, 4, static_cast<off_t>(off)) != 4) {}
    ::close(fd);
}
inline void put_u64_at(const std::string& path, uint64_t off, uint64_t v) {
    const int fd = ::open(path.c_str(), O_RDWR);
    if (fd < 0) return;
    if (::pwrite(fd, &v, 8, static_cast<off_t>(off)) != 8) {}
    ::close(fd);
}
inline std::string seg_name(uint64_t id) { char b[32]; std::snprintf(b, sizeof b, "%06llu.seg", (unsigned long long)id); return b; }
inline std::string hint_name(uint64_t id) { char b[32]; std::snprintf(b, sizeof b, "%06llu.hint", (unsigned long long)id); return b; }

} // namespace tu
