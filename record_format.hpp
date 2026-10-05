#pragma once
// record_format.hpp
//
// The on-disk record format, factored out on its own so every engine that
// reads or writes it (the single-file KVEngine, the new segmented engine,
// and later the compactor) shares one definition instead of three copies
// that could quietly drift apart.
//
// Unchanged from the original prototype -- 20-byte header, host-endian,
// no padding:
//   [0:4)         CRC32     (covers everything from byte 4 onward)
//   [4:12)        timestamp (ms since epoch)
//   [12:16)       key_len
//   [16:20)       value_len -- 0xFFFFFFFF is a delete tombstone
//   [20:20+klen)  key bytes
//   [20+klen:...) value bytes

#include "crc32.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

namespace kvengine {

constexpr size_t HEADER_SIZE = 20;
constexpr uint32_t TOMBSTONE = 0xFFFFFFFFu;

// Segmented engine only: a record with key length 0 and this value length
// is a "compaction base" marker. It carries no body. A segment that starts
// with one declares: "I replace every segment with a lower ID" (see
// segmented_engine.hpp). Real values must be smaller than this, so a value
// length can never be mistaken for it.
constexpr uint32_t COMPACTION_BASE = 0xFFFFFFFEu;

// Number of body bytes that follow the key for a given value-length field.
inline uint32_t body_value_len(uint32_t vlen_field) {
    return (vlen_field == TOMBSTONE || vlen_field == COMPACTION_BASE) ? 0u : vlen_field;
}

inline void encode_header(uint8_t* buf, uint32_t crc, uint64_t ts, uint32_t klen, uint32_t vlen) {
    std::memcpy(buf + 0, &crc, 4);
    std::memcpy(buf + 4, &ts, 8);
    std::memcpy(buf + 12, &klen, 4);
    std::memcpy(buf + 16, &vlen, 4);
}

inline void decode_header(const uint8_t* buf, uint32_t& crc, uint64_t& ts, uint32_t& klen, uint32_t& vlen) {
    std::memcpy(&crc, buf + 0, 4);
    std::memcpy(&ts, buf + 4, 8);
    std::memcpy(&klen, buf + 12, 4);
    std::memcpy(&vlen, buf + 16, 4);
}

inline uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

// Pure serialization: builds one record and pwrites it at (fd, offset).
// Touches no engine state, which is what lets every engine that uses this
// format (single-file, segmented, and the compactor still to come) share
// it directly instead of re-deriving it.
inline bool write_record(int fd, uint64_t offset, const std::string& key,
                          const char* value_data, uint32_t vlen_field, uint64_t ts,
                          bool sync_after, uint64_t& out_value_pos, uint64_t& out_record_len) {
    const uint32_t klen = static_cast<uint32_t>(key.size());
    const uint32_t actual_vlen = body_value_len(vlen_field);
    const size_t total = HEADER_SIZE + klen + actual_vlen;

    std::vector<uint8_t> buf(total);
    std::memcpy(buf.data() + HEADER_SIZE, key.data(), klen);
    if (actual_vlen > 0) std::memcpy(buf.data() + HEADER_SIZE + klen, value_data, actual_vlen);

    encode_header(buf.data(), 0, ts, klen, vlen_field);
    const uint32_t crc = crc32(buf.data() + 4, total - 4);
    std::memcpy(buf.data() + 0, &crc, 4);

    const ssize_t written = ::pwrite(fd, buf.data(), buf.size(), static_cast<off_t>(offset));
    if (written < 0 || static_cast<size_t>(written) != buf.size()) return false;
    if (sync_after) ::fsync(fd);

    out_value_pos = offset + HEADER_SIZE + klen;
    out_record_len = total;
    return true;
}

// A freshly created, renamed or deleted file is only durable once the
// DIRECTORY entry is flushed too; fsync() on the file alone does not do that.
// Best-effort: some filesystems refuse to fsync a directory.
inline void fsync_dir(const std::string& dir) {
    const int fd = ::open(dir.empty() ? "." : dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) return;
    ::fsync(fd);
    ::close(fd);
}

inline std::string parent_dir(const std::string& path) {
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return ".";
    return slash == 0 ? "/" : path.substr(0, slash);
}

} // namespace kvengine
