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

#include <sys/types.h>
#include <unistd.h>

namespace kvengine {

constexpr size_t HEADER_SIZE = 20;
constexpr uint32_t TOMBSTONE = 0xFFFFFFFFu;

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
    const uint32_t actual_vlen = (vlen_field == TOMBSTONE) ? 0u : vlen_field;
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

} // namespace kvengine
