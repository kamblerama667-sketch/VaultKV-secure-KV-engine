#pragma once
// kv_protocol.hpp
//
// Serializes PUT/GET/DEL requests and their responses into the plaintext
// payloads carried by an already-encrypted SecureChannel. This layer
// knows nothing about crypto -- by the time these bytes exist, the
// channel has already handled confidentiality and integrity.

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace kvproto {

enum class Op : uint8_t { Put = 1, Get = 2, Del = 3 };
enum class Status : uint8_t { Ok = 0, NotFound = 1, Error = 2 };

// [1-byte op][4-byte key_len][4-byte value_len][key bytes][value bytes]
// value_len is 0 (no value bytes follow) for Get and Del.
inline std::vector<uint8_t> encode_request(Op op, const std::string& key,
                                            const std::string& value = "") {
    const uint32_t klen = static_cast<uint32_t>(key.size());
    const uint32_t vlen = (op == Op::Put) ? static_cast<uint32_t>(value.size()) : 0u;

    std::vector<uint8_t> buf(1 + 4 + 4 + klen + vlen);
    buf[0] = static_cast<uint8_t>(op);
    std::memcpy(buf.data() + 1, &klen, 4);
    std::memcpy(buf.data() + 5, &vlen, 4);
    std::memcpy(buf.data() + 9, key.data(), klen);
    if (vlen > 0) std::memcpy(buf.data() + 9 + klen, value.data(), vlen);
    return buf;
}

struct Request {
    Op op;
    std::string key;
    std::string value;
};

inline std::optional<Request> decode_request(const std::vector<uint8_t>& buf) {
    if (buf.size() < 9) return std::nullopt;
    const Op op = static_cast<Op>(buf[0]);
    uint32_t klen, vlen;
    std::memcpy(&klen, buf.data() + 1, 4);
    std::memcpy(&vlen, buf.data() + 5, 4);
    if (buf.size() != 9ull + klen + vlen) return std::nullopt;

    Request r;
    r.op = op;
    r.key.assign(reinterpret_cast<const char*>(buf.data() + 9), klen);
    if (vlen > 0) r.value.assign(reinterpret_cast<const char*>(buf.data() + 9 + klen), vlen);
    return r;
}

// [1-byte status][4-byte value_len][value bytes]
inline std::vector<uint8_t> encode_response(Status status, const std::string& value = "") {
    const uint32_t vlen = static_cast<uint32_t>(value.size());
    std::vector<uint8_t> buf(1 + 4 + vlen);
    buf[0] = static_cast<uint8_t>(status);
    std::memcpy(buf.data() + 1, &vlen, 4);
    if (vlen > 0) std::memcpy(buf.data() + 5, value.data(), vlen);
    return buf;
}

struct Response {
    Status status = Status::Error;
    std::string value;
};

inline std::optional<Response> decode_response(const std::vector<uint8_t>& buf) {
    if (buf.size() < 5) return std::nullopt;
    const Status status = static_cast<Status>(buf[0]);
    uint32_t vlen;
    std::memcpy(&vlen, buf.data() + 1, 4);
    if (buf.size() != 5ull + vlen) return std::nullopt;

    Response r;
    r.status = status;
    if (vlen > 0) r.value.assign(reinterpret_cast<const char*>(buf.data() + 5), vlen);
    return r;
}

} // namespace kvproto
