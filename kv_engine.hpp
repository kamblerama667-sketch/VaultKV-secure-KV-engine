#pragma once
// kv_engine.hpp
//
// Bitcask-style, append-only, persistent, thread-safe Key-Value engine.
// Header-only; depends only on the C++ Standard Library and POSIX syscalls.
//
// New in this revision, on top of the verified single-file prototype:
//   - std::shared_mutex: concurrent get()s, exclusive put()/del()/compact().
//     The lock wraps the *entire* operation, including the pread/pwrite --
//     that's what actually prevents a write racing a read at the OS level,
//     not just protecting the in-memory KeyDir.
//   - compact(): rewrites the log keeping only each live key's current
//     value, reclaiming space from overwritten/deleted records. Builds a
//     fresh file, fsyncs it, then atomically rename()s it over the original
//     -- so a crash mid-compaction leaves the original file untouched.
//     "Stop-the-world": holds the exclusive lock for its whole duration.
//     Online/background compaction (no blocking) is a further upgrade, not
//     implemented here.
//   - write_record(): the on-disk serialization pulled out into one pure
//     function, called by both append_record() and compact(), so there is
//     exactly one place that defines the record format.
//
// ON-DISK RECORD LAYOUT (unchanged from the prototype) -- 20-byte header,
// host-endian, no padding:
//   [0:4)         CRC32     (covers everything from byte 4 onward)
//   [4:12)        timestamp (ms since epoch)
//   [12:16)       key_len
//   [16:20)       value_len -- 0xFFFFFFFF is a delete tombstone (0 value
//                 bytes actually stored on disk for a tombstone)
//   [20:20+klen)  key bytes
//   [20+klen:...) value bytes

#include "record_format.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace kvengine {

class KVEngine {
public:
    explicit KVEngine(const std::string& path, bool sync_on_write = false)
        : path_(path), sync_on_write_(sync_on_write) {
        fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT, 0644);
        if (fd_ < 0)
            throw std::runtime_error("open(" + path_ + ") failed: " + std::strerror(errno));

        struct stat st{};
        if (::fstat(fd_, &st) != 0) {
            ::close(fd_);
            throw std::runtime_error(std::string("fstat() failed: ") + std::strerror(errno));
        }
        write_offset_ = static_cast<uint64_t>(st.st_size);
        rebuild_index(); // single-threaded by construction; no lock needed yet
    }

    ~KVEngine() {
        if (fd_ >= 0) ::close(fd_);
    }

    KVEngine(const KVEngine&) = delete;
    KVEngine& operator=(const KVEngine&) = delete;

    bool put(const std::string& key, const std::string& value) {
        if (key.size() > UINT32_MAX || value.size() >= TOMBSTONE) return false;
        std::unique_lock lock(mutex_);
        const uint64_t ts = now_ms();
        uint64_t value_pos = 0, record_len = 0;
        if (!write_record(fd_, write_offset_, key, value.data(), static_cast<uint32_t>(value.size()),
                           ts, sync_on_write_, value_pos, record_len))
            return false;
        write_offset_ += record_len;
        keydir_[key] = KeyDirEntry{value_pos, static_cast<uint32_t>(value.size()), ts};
        return true;
    }

    std::optional<std::string> get(const std::string& key) const {
        std::shared_lock lock(mutex_); // multiple readers run concurrently
        auto it = keydir_.find(key);
        if (it == keydir_.end()) return std::nullopt;
        const auto& e = it->second;
        if (e.value_size == 0) return std::string();
        std::string value(e.value_size, '\0');
        const ssize_t n = ::pread(fd_, value.data(), e.value_size, static_cast<off_t>(e.value_pos));
        if (n < 0 || static_cast<uint32_t>(n) != e.value_size) return std::nullopt;
        return value;
    }

    bool del(const std::string& key) {
        std::unique_lock lock(mutex_);
        if (keydir_.find(key) == keydir_.end()) return false;
        const uint64_t ts = now_ms();
        uint64_t value_pos = 0, record_len = 0;
        if (!write_record(fd_, write_offset_, key, nullptr, TOMBSTONE, ts, sync_on_write_, value_pos, record_len))
            return false;
        write_offset_ += record_len;
        keydir_.erase(key);
        return true;
    }

    // Rewrites the log keeping only each live key's current value. Holds the
    // exclusive lock for its whole duration -- correct and simple, at the
    // cost of blocking other operations while it runs (see header note).
    bool compact() {
        std::unique_lock lock(mutex_);
        const std::string tmp_path = path_ + ".compact.tmp";
        const int tmp_fd = ::open(tmp_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (tmp_fd < 0) return false;

        std::unordered_map<std::string, KeyDirEntry> new_keydir;
        new_keydir.reserve(keydir_.size());
        uint64_t new_offset = 0;
        bool ok = true;

        for (const auto& [key, entry] : keydir_) {
            std::string value(entry.value_size, '\0');
            if (entry.value_size > 0) {
                const ssize_t n = ::pread(fd_, value.data(), entry.value_size, static_cast<off_t>(entry.value_pos));
                if (n < 0 || static_cast<uint32_t>(n) != entry.value_size) { ok = false; break; }
            }
            uint64_t value_pos = 0, record_len = 0;
            if (!write_record(tmp_fd, new_offset, key, value.data(), static_cast<uint32_t>(value.size()),
                               entry.timestamp, /*sync_after=*/false, value_pos, record_len)) {
                ok = false;
                break;
            }
            new_keydir[key] = KeyDirEntry{value_pos, entry.value_size, entry.timestamp};
            new_offset += record_len;
        }

        if (!ok) {
            ::close(tmp_fd);
            ::unlink(tmp_path.c_str());
            return false;
        }

        ::fsync(tmp_fd); // always durable here: compaction is rare/deliberate, not the hot path
        if (::rename(tmp_path.c_str(), path_.c_str()) != 0) {
            ::close(tmp_fd);
            ::unlink(tmp_path.c_str());
            return false;
        }

        ::close(fd_);
        fd_ = tmp_fd;
        keydir_ = std::move(new_keydir);
        write_offset_ = new_offset;
        return true;
    }

    size_t size() const { std::shared_lock lock(mutex_); return keydir_.size(); }
    uint64_t data_file_bytes() const { std::shared_lock lock(mutex_); return write_offset_; }

private:
    struct KeyDirEntry {
        uint64_t value_pos;
        uint32_t value_size;
        uint64_t timestamp;
    };

    std::string path_;
    int fd_ = -1;
    uint64_t write_offset_ = 0;
    bool sync_on_write_;
    mutable std::shared_mutex mutex_; // mutable: locking isn't a logical mutation
    std::unordered_map<std::string, KeyDirEntry> keydir_;

    // Sequentially replays the file into the KeyDir. Stops at the first
    // torn record or CRC mismatch and truncates to the last known-good
    // record -- the crash-recovery path, run on every startup.
    void rebuild_index() {
        uint64_t offset = 0;
        uint8_t header[HEADER_SIZE];

        while (true) {
            const ssize_t n = ::pread(fd_, header, HEADER_SIZE, static_cast<off_t>(offset));
            if (n < static_cast<ssize_t>(HEADER_SIZE)) break;

            uint32_t crc, klen, vlen;
            uint64_t ts;
            decode_header(header, crc, ts, klen, vlen);
            const uint32_t actual_vlen = (vlen == TOMBSTONE) ? 0u : vlen;

            std::vector<uint8_t> body(static_cast<size_t>(klen) + actual_vlen);
            if (!body.empty()) {
                const ssize_t bn = ::pread(fd_, body.data(), body.size(), static_cast<off_t>(offset + HEADER_SIZE));
                if (bn < 0 || static_cast<size_t>(bn) != body.size()) break;
            }

            uint32_t recomputed = crc32_update(0xFFFFFFFFu, header + 4, HEADER_SIZE - 4);
            if (!body.empty()) recomputed = crc32_update(recomputed, body.data(), body.size());
            recomputed ^= 0xFFFFFFFFu;
            if (recomputed != crc) break;

            const std::string key = (klen > 0) ? std::string(reinterpret_cast<char*>(body.data()), klen)
                                                : std::string();
            if (vlen == TOMBSTONE) {
                keydir_.erase(key);
            } else {
                keydir_[key] = KeyDirEntry{offset + HEADER_SIZE + klen, vlen, ts};
            }
            offset += HEADER_SIZE + klen + actual_vlen;
        }

        if (::ftruncate(fd_, static_cast<off_t>(offset)) != 0) {
            // Best-effort trim of a torn tail; failure here doesn't corrupt
            // anything already indexed, so we don't throw over it.
        }
        write_offset_ = offset;
    }
};

} // namespace kvengine
