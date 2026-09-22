#pragma once
// secure_channel.hpp
//
// Wire framing plus an AEAD-encrypted channel over a raw socket fd.
//
// Uses two independent, direction-separated keys (client_write_key,
// server_write_key) instead of one shared key. This is deliberate: if
// both directions used one key with each side keeping its own counter,
// a client message and a server message could end up encrypted under the
// same (key, nonce) pair -- which breaks AES-GCM's security guarantee
// outright. TLS 1.3 separates client_write_key / server_write_key for
// exactly this reason; this does the same thing at a much smaller scale.
//
// Nonces are a big-endian-agnostic 12 bytes: 4 zero bytes + an 8-byte
// monotonic counter, private to one direction's key. Never reused within
// a session because it only ever increments, and never reused across
// sessions because a fresh handshake derives a fresh key pair.
//
// Every message on the wire: [4-byte length][12-byte nonce][ciphertext]
// [16-byte tag], where length covers everything after itself.

#include "crypto_utils.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

namespace secure {

enum class Role { Client, Server };

// A single recv()/send() on a stream socket can hand back fewer bytes
// than requested even when more are on the way -- both loop until the
// full amount is in, or the peer is gone / an error occurs.
inline bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        const ssize_t r = ::recv(fd, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

inline bool write_exact(int fd, const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        const ssize_t w = ::send(fd, buf + sent, n - sent, 0);
        if (w <= 0) return false;
        sent += static_cast<size_t>(w);
    }
    return true;
}

class SecureChannel {
public:
    SecureChannel(int fd, Role role,
                  const std::array<uint8_t, crypto::AES_KEY_BYTES>& client_write_key,
                  const std::array<uint8_t, crypto::AES_KEY_BYTES>& server_write_key)
        : fd_(fd),
          send_key_(role == Role::Client ? client_write_key : server_write_key),
          recv_key_(role == Role::Client ? server_write_key : client_write_key) {}

    bool send(const std::vector<uint8_t>& plaintext) {
        uint8_t nonce[crypto::GCM_NONCE_BYTES] = {0};
        const uint64_t counter = send_counter_++;
        std::memcpy(nonce + 4, &counter, 8);

        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t tag[crypto::GCM_TAG_BYTES];
        if (!crypto::aes_gcm_encrypt(send_key_.data(), plaintext.data(), plaintext.size(),
                                      nonce, ciphertext.data(), tag))
            return false;

        const uint32_t frame_len = static_cast<uint32_t>(
            crypto::GCM_NONCE_BYTES + ciphertext.size() + crypto::GCM_TAG_BYTES);
        const uint32_t len_be = htonl(frame_len);
        uint8_t len_buf[4];
        std::memcpy(len_buf, &len_be, 4);

        return write_exact(fd_, len_buf, 4)
            && write_exact(fd_, nonce, crypto::GCM_NONCE_BYTES)
            && write_exact(fd_, ciphertext.data(), ciphertext.size())
            && write_exact(fd_, tag, crypto::GCM_TAG_BYTES);
    }

    // nullopt on any failure: connection closed, malformed frame, or a
    // tag mismatch (tampered/corrupted data) -- all treated the same way
    // by callers, as "this message can't be trusted or doesn't exist."
    std::optional<std::vector<uint8_t>> receive() {
        uint8_t len_buf[4];
        if (!read_exact(fd_, len_buf, 4)) return std::nullopt;
        uint32_t len_be;
        std::memcpy(&len_be, len_buf, 4);
        const uint32_t frame_len = ntohl(len_be);

        constexpr uint32_t MIN_FRAME = crypto::GCM_NONCE_BYTES + crypto::GCM_TAG_BYTES;
        constexpr uint32_t MAX_FRAME = 16u * 1024 * 1024; // refuse to blindly allocate on a bogus length
        if (frame_len < MIN_FRAME || frame_len > MAX_FRAME) return std::nullopt;

        std::vector<uint8_t> frame(frame_len);
        if (!read_exact(fd_, frame.data(), frame_len)) return std::nullopt;

        const uint8_t* nonce = frame.data();
        const size_t ct_len = frame_len - MIN_FRAME;
        const uint8_t* ciphertext = frame.data() + crypto::GCM_NONCE_BYTES;
        const uint8_t* tag = frame.data() + crypto::GCM_NONCE_BYTES + ct_len;

        std::vector<uint8_t> plaintext;
        if (!crypto::aes_gcm_decrypt(recv_key_.data(), ciphertext, ct_len, nonce, tag, plaintext))
            return std::nullopt;
        return plaintext;
    }

private:
    int fd_;
    std::array<uint8_t, crypto::AES_KEY_BYTES> send_key_;
    std::array<uint8_t, crypto::AES_KEY_BYTES> recv_key_;
    uint64_t send_counter_ = 0;
};

} // namespace secure
