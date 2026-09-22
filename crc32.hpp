#pragma once
// crc32.hpp — CRC32 (IEEE 802.3 / zlib polynomial 0xEDB88320), from scratch.
// Header-only so it can be shared by the engine, the benchmark, and (later)
// the network server without duplicating the table or the algorithm.

#include <array>
#include <cstddef>
#include <cstdint>

namespace kvengine {
namespace detail {

inline const std::array<uint32_t, 256>& crc32_table() {
    static const std::array<uint32_t, 256> table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t n = 0; n < 256; ++n) {
            uint32_t c = n;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[n] = c;
        }
        return t;
    }();
    return table;
}

} // namespace detail

// Incremental form: feed one or more chunks through with the running crc,
// then XOR the final result once all chunks are in.
inline uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) {
    const auto& t = detail::crc32_table();
    for (size_t i = 0; i < len; ++i)
        crc = t[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc;
}

inline uint32_t crc32(const uint8_t* data, size_t len) {
    return crc32_update(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

} // namespace kvengine
