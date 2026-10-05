#pragma once
// segmented_engine.hpp
//
// Segmented Bitcask-style engine. Where the single-file KVEngine had one
// ever-growing file, this one keeps a directory of segments:
//   <dir>/000000.seg, 000001.seg, ...   -- the actual records
//   <dir>/000000.hint, 000001.hint, ... -- written when a segment seals
//
// Only the highest-numbered segment is ever written to (the "active"
// segment). When it reaches segment_threshold bytes, it seals: its list of
// {key, offset, size, timestamp} is written to a .hint file (data segment
// fsynced first), and a fresh active segment opens.
//
// INVARIANTS (every restart bug found so far was a violation of one):
//   1. Only the newest segment is ever written to.
//   2. Replay order is log order: a later record overrides an earlier one.
//      A compacted segment keeps the ID of the NEWEST segment it replaces, so
//      ID order stays log order.
//   3. A record is valid only if its CRC checks. Recovery stops at the first
//      invalid record of a segment and (for the active segment) truncates.
//      Length fields are bounded by the bytes that are actually left in the
//      file BEFORE anything is allocated.
//   4. A hint must describe its segment completely, or not exist. A missing
//      hint is safe (full scan). On startup a hint is only trusted if it
//      parses exactly, every entry lies inside the segment, and the entries
//      reach the very end of the segment; anything else is discarded and the
//      segment is scanned instead. The in-memory hint list of the active
//      segment is rebuilt when it is recovered, and cleared on every seal.
//   5. One mutex covers the KeyDir, all segment I/O and the cache together.
//
// COMPACTION (compact()) merges EVERY sealed segment into one new segment.
// It is stop-the-world (holds the exclusive lock) and crash-safe:
//   - the merged segment begins with a COMPACTION_BASE marker record, which
//     means "I replace every segment with a lower ID". The marker is
//     published by one atomic rename, so the swap needs no manifest.
//   - on startup, the newest sealed segment that begins with the marker
//     wins; all lower-ID segments are deleted as leftovers of a compaction
//     that was interrupted before it finished cleaning up. This is why
//     tombstones may safely be dropped from the merged segment.
//   - every record is CRC-verified while being copied; a corrupt record
//     aborts the compaction (returns false) and leaves all files untouched.
//   Crash points are numbered 1-6 (see compact_locked); tests kill the
//   process at each one and at random moments.
//
// sync_on_write governs per-record fsync (default false: fast, relies on
// the OS + the seal-time checkpoint). Sealing always fsyncs the segment
// first and the hint second, so a hint is never durable before its data.

#include "crc32.hpp"
#include "lru_cache.hpp"
#include "record_format.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace kvengine {

class SegmentedKVEngine {
public:
    explicit SegmentedKVEngine(const std::string& dir,
                                uint64_t segment_threshold = 64ull * 1024 * 1024,
                                size_t cache_capacity = 10000,
                                bool sync_on_write = false)
        : dir_(dir), segment_threshold_(segment_threshold),
          sync_on_write_(sync_on_write), cache_(cache_capacity) {
        if (::mkdir(dir_.c_str(), 0755) != 0 && errno != EEXIST)
            throw std::runtime_error("mkdir(" + dir_ + ") failed: " + std::strerror(errno));
        try {
            discover_and_recover();
        } catch (...) {
            close_all_fds(); // the destructor does not run for a throwing constructor
            throw;
        }
    }

    ~SegmentedKVEngine() { close_all_fds(); }

    SegmentedKVEngine(const SegmentedKVEngine&) = delete;
    SegmentedKVEngine& operator=(const SegmentedKVEngine&) = delete;

    bool put(const std::string& key, const std::string& value) {
        if (key.size() > UINT32_MAX || value.size() >= COMPACTION_BASE) return false;
        std::unique_lock lock(mutex_);
        maybe_roll_segment();

        const uint64_t ts = now_ms();
        uint64_t value_pos = 0, record_len = 0;
        if (!write_record(active_fd_, active_write_offset_, key, value.data(),
                           static_cast<uint32_t>(value.size()), ts, sync_on_write_, value_pos, record_len))
            return false;
        active_write_offset_ += record_len;

        keydir_[key] = KeyDirEntry{active_segment_id_, value_pos, static_cast<uint32_t>(value.size()), ts};
        active_hints_.push_back(HintRecord{key, value_pos, static_cast<uint32_t>(value.size()), ts});
        cache_.put(key, value); // same lock as the KeyDir update above -- no staleness window
        return true;
    }

    std::optional<std::string> get(const std::string& key) {
        std::unique_lock lock(mutex_); // unique, not shared: cache.get() reorders the LRU list (a write to cache_ state)
        if (auto cached = cache_.get(key)) { ++cache_hits_; return cached; }
        ++cache_misses_;

        auto it = keydir_.find(key);
        if (it == keydir_.end()) return std::nullopt;
        const KeyDirEntry& e = it->second;
        if (e.value_size == 0) return std::string();

        auto seg_it = segment_fds_.find(e.segment_id);
        if (seg_it == segment_fds_.end()) return std::nullopt; // shouldn't happen; defensive
        std::string value(e.value_size, '\0');
        const ssize_t n = ::pread(seg_it->second, value.data(), e.value_size, static_cast<off_t>(e.value_pos));
        if (n < 0 || static_cast<uint32_t>(n) != e.value_size) return std::nullopt;

        cache_.put(key, value);
        return value;
    }

    bool del(const std::string& key) {
        std::unique_lock lock(mutex_);
        if (keydir_.find(key) == keydir_.end()) return false;
        maybe_roll_segment();

        const uint64_t ts = now_ms();
        uint64_t value_pos = 0, record_len = 0;
        if (!write_record(active_fd_, active_write_offset_, key, nullptr, TOMBSTONE, ts,
                           sync_on_write_, value_pos, record_len))
            return false;
        active_write_offset_ += record_len;

        keydir_.erase(key);
        active_hints_.push_back(HintRecord{key, value_pos, TOMBSTONE, ts});
        cache_.erase(key);
        return true;
    }

    // Merges every sealed segment into one, dropping overwritten and deleted
    // records. Returns false (changing nothing on disk or in memory) if
    // anything fails before the atomic swap. Stop-the-world.
    bool compact() {
        std::unique_lock lock(mutex_);
        return compact_locked();
    }

    size_t size() const { std::shared_lock lock(mutex_); return keydir_.size(); }
    size_t segment_count() const { std::shared_lock lock(mutex_); return segment_fds_.size(); }
    uint64_t active_segment_bytes() const { std::shared_lock lock(mutex_); return active_write_offset_; }
    uint64_t hint_recoveries() const { std::shared_lock lock(mutex_); return hint_recoveries_; }
    uint64_t full_scan_recoveries() const { std::shared_lock lock(mutex_); return full_scan_recoveries_; }
    uint64_t cache_hits() const { std::shared_lock lock(mutex_); return cache_hits_; }
    uint64_t cache_misses() const { std::shared_lock lock(mutex_); return cache_misses_; }

    // TEST HOOK: makes compact() call _exit(77) when it reaches crash point
    // `step` (1-6), simulating a process death at exactly that moment.
    void set_crash_failpoint_for_testing(int step) { failpoint_ = step; }

private:
    struct KeyDirEntry {
        uint64_t segment_id;
        uint64_t value_pos;
        uint32_t value_size;
        uint64_t timestamp;
    };
    struct HintRecord {
        std::string key;
        uint64_t value_pos;
        uint32_t value_size; // TOMBSTONE for a delete
        uint64_t timestamp;
    };

    std::string dir_;
    uint64_t segment_threshold_;
    bool sync_on_write_;

    uint64_t active_segment_id_ = 0;
    int active_fd_ = -1;
    uint64_t active_write_offset_ = 0;
    std::vector<HintRecord> active_hints_; // complete list of the ACTIVE segment's valid records

    std::unordered_map<uint64_t, int> segment_fds_; // every segment, active included
    std::unordered_map<std::string, KeyDirEntry> keydir_;
    LRUCache<std::string, std::string> cache_;
    mutable std::shared_mutex mutex_;
    uint64_t hint_recoveries_ = 0;
    uint64_t full_scan_recoveries_ = 0;
    uint64_t cache_hits_ = 0;
    uint64_t cache_misses_ = 0;
    int failpoint_ = 0;

    void close_all_fds() {
        for (auto& [id, fd] : segment_fds_)
            if (fd >= 0) ::close(fd);
        segment_fds_.clear();
    }
    void maybe_crash(int step) const { if (failpoint_ == step) ::_exit(77); }

    std::string segment_path(uint64_t id) const {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%06llu.seg", static_cast<unsigned long long>(id));
        return dir_ + "/" + buf;
    }
    std::string hint_path(uint64_t id) const {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%06llu.hint", static_cast<unsigned long long>(id));
        return dir_ + "/" + buf;
    }

    static bool ends_with(const std::string& s, const char* suffix) {
        const size_t n = std::strlen(suffix);
        return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
    }
    // "000042.seg" -> 42. Needs at least 6 digits; more are allowed (IDs past 999999).
    static bool parse_segment_name(const std::string& name, uint64_t& id) {
        if (name.size() < 10 || !ends_with(name, ".seg")) return false;
        const std::string digits = name.substr(0, name.size() - 4);
        if (digits.size() > 19 || !std::all_of(digits.begin(), digits.end(), [](unsigned char c) { return std::isdigit(c); }))
            return false;
        id = std::stoull(digits);
        return true;
    }

    void maybe_roll_segment() {
        if (active_write_offset_ >= segment_threshold_) {
            seal_active_segment();
            open_new_active_segment(active_segment_id_ + 1);
        }
    }

    static std::vector<uint8_t> encode_hints(const std::vector<HintRecord>& hints) {
        std::vector<uint8_t> buf;
        for (const auto& h : hints) {
            const uint32_t klen = static_cast<uint32_t>(h.key.size());
            const size_t start = buf.size();
            buf.resize(start + 24 + klen);
            std::memcpy(buf.data() + start, &klen, 4);
            std::memcpy(buf.data() + start + 4, &h.value_pos, 8);
            std::memcpy(buf.data() + start + 12, &h.value_size, 4);
            std::memcpy(buf.data() + start + 16, &h.timestamp, 8);
            std::memcpy(buf.data() + start + 24, h.key.data(), klen);
        }
        return buf;
    }

    // Writes <id>.hint atomically (temp file + fsync + rename + dir fsync).
    // Best-effort: a missing hint only means a full scan on the next startup.
    bool write_hint_file(uint64_t id, const std::vector<HintRecord>& hints) {
        const std::string hpath = hint_path(id);
        const std::string tmp = hpath + ".tmp";
        const int hfd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (hfd < 0) return false;

        const std::vector<uint8_t> buf = encode_hints(hints);
        size_t off = 0;
        bool ok = true;
        while (off < buf.size()) {
            const ssize_t w = ::write(hfd, buf.data() + off, buf.size() - off);
            if (w <= 0) { ok = false; break; }
            off += static_cast<size_t>(w);
        }
        if (ok && ::fsync(hfd) != 0) ok = false;
        ::close(hfd);
        if (!ok || ::rename(tmp.c_str(), hpath.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
        fsync_dir(dir_);
        return true;
    }

    // Flushes this segment's hints to disk, fsyncing the data segment BEFORE
    // the hint file: if we crash between the two, the hint (if it landed at
    // all) only ever describes bytes already durable.
    void seal_active_segment() {
        ::fsync(active_fd_);
        write_hint_file(active_segment_id_, active_hints_);
        // ALWAYS forget this segment's hints, even if writing them failed.
        // Keeping them would make the NEXT segment's hint describe records
        // that live in a different file (invariant 4).
        active_hints_.clear();
    }

    void open_new_active_segment(uint64_t new_id) {
        const int fd = ::open(segment_path(new_id).c_str(), O_RDWR | O_CREAT, 0644);
        if (fd < 0) throw std::runtime_error("failed to create segment " + segment_path(new_id));
        fsync_dir(dir_); // the new file's directory entry must be durable too
        segment_fds_[new_id] = fd;
        active_fd_ = fd;
        active_segment_id_ = new_id;
        active_write_offset_ = 0;
        active_hints_.clear();
    }

    // Full CRC-validated scan. Returns the offset of the first byte that is
    // not part of a valid record (the truncation point).
    //
    // If hints_out is non-null, every valid key record the scan accepts (puts
    // AND tombstones, in log order) is appended to it -- used for the active
    // segment so its hint list is complete before it can seal.
    uint64_t recover_segment_via_full_scan(uint64_t id, int fd,
                                           std::vector<HintRecord>* hints_out = nullptr) {
        struct stat st{};
        if (::fstat(fd, &st) != 0 || st.st_size < 0)
            throw std::runtime_error("fstat failed on " + segment_path(id) + ": " + std::strerror(errno));
        const uint64_t file_size = static_cast<uint64_t>(st.st_size);

        uint64_t offset = 0;
        uint8_t header[HEADER_SIZE];
        while (true) {
            if (file_size - offset < HEADER_SIZE) break; // offset <= file_size always holds here
            const ssize_t n = ::pread(fd, header, HEADER_SIZE, static_cast<off_t>(offset));
            if (n < static_cast<ssize_t>(HEADER_SIZE)) break;

            uint32_t crc, klen, vlen;
            uint64_t ts;
            decode_header(header, crc, ts, klen, vlen);
            const uint32_t actual_vlen = body_value_len(vlen);
            // Untrusted until the CRC passes: never allocate more than the file can hold.
            if (static_cast<uint64_t>(klen) + actual_vlen > file_size - offset - HEADER_SIZE) break;

            std::vector<uint8_t> body(static_cast<size_t>(klen) + actual_vlen);
            if (!body.empty()) {
                const ssize_t bn = ::pread(fd, body.data(), body.size(), static_cast<off_t>(offset + HEADER_SIZE));
                if (bn < 0 || static_cast<size_t>(bn) != body.size()) break;
            }

            uint32_t recomputed = crc32_update(0xFFFFFFFFu, header + 4, HEADER_SIZE - 4);
            if (!body.empty()) recomputed = crc32_update(recomputed, body.data(), body.size());
            recomputed ^= 0xFFFFFFFFu;
            if (recomputed != crc) break;

            if (vlen == COMPACTION_BASE) {
                if (klen != 0) break;          // a marker never has a key: corrupt
                offset += HEADER_SIZE;         // no effect on the KeyDir
                continue;
            }

            const std::string key = (klen > 0) ? std::string(reinterpret_cast<char*>(body.data()), klen)
                                                : std::string();
            const uint64_t value_pos = offset + HEADER_SIZE + klen;
            if (vlen == TOMBSTONE) keydir_.erase(key);
            else keydir_[key] = KeyDirEntry{id, value_pos, vlen, ts};
            if (hints_out) hints_out->push_back(HintRecord{key, value_pos, vlen, ts});
            offset += HEADER_SIZE + klen + actual_vlen;
        }
        ++full_scan_recoveries_;
        return offset;
    }

    // Rebuilds this segment's part of the KeyDir from its hint file, but only
    // if the hint can be trusted completely. Returns false -- having changed
    // NOTHING -- if the hint is missing, unreadable, cut short, has trailing
    // bytes, points outside the segment, or does not reach the segment's end.
    // The caller then falls back to a full scan.
    bool recover_segment_via_hint(uint64_t id, int seg_fd) {
        const int hfd = ::open(hint_path(id).c_str(), O_RDONLY);
        if (hfd < 0) return false;
        struct stat st{};
        if (::fstat(hfd, &st) != 0 || st.st_size < 0 || !S_ISREG(st.st_mode)) { ::close(hfd); return false; }
        struct stat sst{};
        if (::fstat(seg_fd, &sst) != 0 || sst.st_size < 0) { ::close(hfd); return false; }
        const uint64_t seg_size = static_cast<uint64_t>(sst.st_size);

        std::vector<uint8_t> buf(static_cast<size_t>(st.st_size));
        size_t got = 0;
        while (got < buf.size()) {
            const ssize_t n = ::read(hfd, buf.data() + got, buf.size() - got);
            if (n <= 0) break;
            got += static_cast<size_t>(n);
        }
        ::close(hfd);
        if (got != buf.size()) return false;

        // Parse everything first; apply only if the whole file checks out.
        std::vector<HintRecord> parsed;
        uint64_t max_end = 0;
        size_t pos = 0;
        while (pos < buf.size()) {
            if (buf.size() - pos < 24) return false; // trailing garbage / cut mid-entry
            uint32_t klen, vsize;
            uint64_t vpos, ts;
            std::memcpy(&klen, buf.data() + pos, 4);
            std::memcpy(&vpos, buf.data() + pos + 4, 8);
            std::memcpy(&vsize, buf.data() + pos + 12, 4);
            std::memcpy(&ts, buf.data() + pos + 16, 8);
            pos += 24;
            if (klen > buf.size() - pos) return false;
            std::string key(reinterpret_cast<char*>(buf.data() + pos), klen);
            pos += klen;

            // The record must lie inside the segment, with its key before its value.
            if (vpos < HEADER_SIZE + static_cast<uint64_t>(klen) || vpos > seg_size) return false;
            uint64_t end = vpos;
            if (vsize != TOMBSTONE) {
                if (vsize > seg_size - vpos) return false;
                end = vpos + vsize;
            }
            max_end = std::max(max_end, end);
            parsed.push_back(HintRecord{std::move(key), vpos, vsize, ts});
        }
        // A sealed segment ends exactly at a record boundary, so a complete hint
        // reaches its last byte. A hint that stops short is missing records.
        if (max_end != seg_size) return false;

        for (const auto& h : parsed) {
            if (h.value_size == TOMBSTONE) keydir_.erase(h.key);
            else keydir_[h.key] = KeyDirEntry{id, h.value_pos, h.value_size, h.timestamp};
        }
        ++hint_recoveries_;
        return true;
    }

    bool segment_begins_with_base_marker(uint64_t id) const {
        const int fd = ::open(segment_path(id).c_str(), O_RDONLY);
        if (fd < 0) return false;
        uint8_t header[HEADER_SIZE];
        const ssize_t n = ::pread(fd, header, HEADER_SIZE, 0);
        ::close(fd);
        if (n < static_cast<ssize_t>(HEADER_SIZE)) return false;
        uint32_t crc, klen, vlen;
        uint64_t ts;
        decode_header(header, crc, ts, klen, vlen);
        if (klen != 0 || vlen != COMPACTION_BASE) return false;
        return crc32(header + 4, HEADER_SIZE - 4) == crc;
    }

    std::vector<std::string> list_dir_names() const {
        std::vector<std::string> names;
        if (DIR* d = ::opendir(dir_.c_str())) {
            while (struct dirent* entry = ::readdir(d)) names.emplace_back(entry->d_name);
            ::closedir(d);
        }
        return names;
    }

    void remove_stale_temp_files() {
        for (const auto& name : list_dir_names())
            if (ends_with(name, ".compact.tmp") || ends_with(name, ".hint.tmp"))
                ::unlink((dir_ + "/" + name).c_str());
    }

    void discover_and_recover() {
        remove_stale_temp_files();

        std::vector<uint64_t> ids;
        for (const auto& name : list_dir_names()) {
            uint64_t id;
            if (parse_segment_name(name, id)) ids.push_back(id);
        }
        std::sort(ids.begin(), ids.end());

        if (ids.empty()) {
            open_new_active_segment(0);
            return;
        }

        // A sealed segment that begins with a base marker is the product of a
        // compaction and replaces every lower-ID segment. If we find lower-ID
        // files, the compaction died before finishing its cleanup: finish it.
        size_t first = 0;
        for (size_t i = ids.size() - 1; i-- > 0;) { // sealed segments only, newest to oldest
            if (segment_begins_with_base_marker(ids[i])) { first = i; break; }
        }
        for (size_t i = 0; i < first; ++i) {
            ::unlink(segment_path(ids[i]).c_str());
            ::unlink(hint_path(ids[i]).c_str());
        }
        if (first > 0) fsync_dir(dir_);

        for (size_t i = first; i + 1 < ids.size(); ++i) {
            const uint64_t id = ids[i];
            const int fd = ::open(segment_path(id).c_str(), O_RDONLY);
            if (fd < 0) throw std::runtime_error("cannot open " + segment_path(id) + ": " + std::strerror(errno));
            segment_fds_[id] = fd;
            if (!recover_segment_via_hint(id, fd)) recover_segment_via_full_scan(id, fd);
        }

        const uint64_t aid = ids.back();
        const int afd = ::open(segment_path(aid).c_str(), O_RDWR);
        if (afd < 0) throw std::runtime_error("cannot open " + segment_path(aid) + ": " + std::strerror(errno));
        segment_fds_[aid] = afd;
        active_fd_ = afd;
        active_segment_id_ = aid;
        active_hints_.clear();
        active_write_offset_ = recover_segment_via_full_scan(aid, afd, &active_hints_);
        if (::ftruncate(afd, static_cast<off_t>(active_write_offset_)) != 0) {
            // Best-effort trim of a torn tail; failure here doesn't corrupt anything already indexed.
        }

        if (active_write_offset_ >= segment_threshold_) {
            seal_active_segment();
            open_new_active_segment(aid + 1);
        }
    }

    // Crash points (each is a process death at that exact moment; recovery
    // must give the same logical contents every time):
    //   1  merged segment written + fsynced as <maxid>.seg.compact.tmp
    //   2  old <maxid>.hint removed (it must not outlive the file it describes)
    //   3  tmp renamed over <maxid>.seg  (the atomic commit point)
    //   4  some superseded lower-ID segments deleted, others not
    //   5  all superseded segments deleted
    //   6  merged segment's hint written (compaction fully done)
    bool compact_locked() {
        // Every segment except the active one is sealed. All of them are merged.
        std::vector<uint64_t> sealed;
        for (const auto& [id, fd] : segment_fds_)
            if (id != active_segment_id_) sealed.push_back(id);
        if (sealed.empty()) return true;
        std::sort(sealed.begin(), sealed.end());
        const uint64_t out_id = sealed.back(); // keeps log order: newest sealed ID

        struct Item { const std::string* key; KeyDirEntry entry; };
        std::vector<Item> items;
        for (const auto& [key, e] : keydir_)
            if (e.segment_id != active_segment_id_) items.push_back({&key, e});
        std::sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
            return a.entry.segment_id != b.entry.segment_id ? a.entry.segment_id < b.entry.segment_id
                                                            : a.entry.value_pos < b.entry.value_pos;
        });

        const std::string tmp_path = segment_path(out_id) + ".compact.tmp";
        const int tmp_fd = ::open(tmp_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (tmp_fd < 0) return false;
        auto abort_compaction = [&]() { ::close(tmp_fd); ::unlink(tmp_path.c_str()); return false; };

        uint64_t value_pos = 0, record_len = 0;
        if (!write_record(tmp_fd, 0, std::string(), nullptr, COMPACTION_BASE, now_ms(), false, value_pos, record_len))
            return abort_compaction();
        uint64_t new_offset = record_len;

        std::vector<HintRecord> new_hints;
        new_hints.reserve(items.size());
        for (const auto& it : items) {
            const KeyDirEntry& e = it.entry;
            const uint64_t klen = it.key->size();
            const uint64_t rec_len = HEADER_SIZE + klen + e.value_size;
            if (e.value_pos < HEADER_SIZE + klen) return abort_compaction();
            const uint64_t rec_start = e.value_pos - klen - HEADER_SIZE;

            const auto src = segment_fds_.find(e.segment_id);
            if (src == segment_fds_.end()) return abort_compaction();
            std::vector<uint8_t> rec(rec_len);
            const ssize_t n = ::pread(src->second, rec.data(), rec.size(), static_cast<off_t>(rec_start));
            if (n < 0 || static_cast<uint64_t>(n) != rec_len) return abort_compaction();

            // Verify the record before copying it: never launder corruption into
            // the new segment and then delete the only other copy.
            uint32_t crc, rklen, rvlen;
            uint64_t rts;
            decode_header(rec.data(), crc, rts, rklen, rvlen);
            if (rklen != klen || rvlen != e.value_size || rts != e.timestamp) return abort_compaction();
            if (std::memcmp(rec.data() + HEADER_SIZE, it.key->data(), klen) != 0) return abort_compaction();
            if (crc32(rec.data() + 4, rec.size() - 4) != crc) return abort_compaction();

            const ssize_t w = ::pwrite(tmp_fd, rec.data(), rec.size(), static_cast<off_t>(new_offset));
            if (w < 0 || static_cast<uint64_t>(w) != rec_len) return abort_compaction();
            new_hints.push_back(HintRecord{*it.key, new_offset + HEADER_SIZE + klen, e.value_size, e.timestamp});
            new_offset += rec_len;
        }
        if (::fsync(tmp_fd) != 0) return abort_compaction();
        maybe_crash(1);

        // The old newest-sealed hint describes a file that is about to be replaced.
        // It must be gone BEFORE the rename, or a crash in between would pair the
        // new segment with the old hint.
        ::unlink(hint_path(out_id).c_str());
        fsync_dir(dir_);
        maybe_crash(2);

        if (::rename(tmp_path.c_str(), segment_path(out_id).c_str()) != 0) return abort_compaction();
        fsync_dir(dir_);
        maybe_crash(3);

        // ---- committed: from here on the new segment is the truth ----
        // Switch the in-memory state first; the rest is cleanup that startup
        // would redo if we died here.
        for (const uint64_t id : sealed) {
            const auto it = segment_fds_.find(id);
            if (it != segment_fds_.end()) { ::close(it->second); segment_fds_.erase(it); }
        }
        segment_fds_[out_id] = tmp_fd; // same inode as the file now named <out_id>.seg
        for (const auto& h : new_hints)
            keydir_[h.key] = KeyDirEntry{out_id, h.value_pos, h.value_size, h.timestamp};

        bool first_delete = true;
        for (const uint64_t id : sealed) {
            if (id == out_id) continue;
            ::unlink(segment_path(id).c_str());
            ::unlink(hint_path(id).c_str());
            if (first_delete) { first_delete = false; maybe_crash(4); }
        }
        fsync_dir(dir_);
        maybe_crash(5);

        if (!new_hints.empty()) write_hint_file(out_id, new_hints);
        maybe_crash(6);
        return true;
    }
};

} // namespace kvengine
