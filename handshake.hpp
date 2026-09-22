#pragma once
// handshake.hpp
//
// Connection setup: an ephemeral KEM keypair per connection (forward
// secrecy -- compromising one connection's key material doesn't expose
// any other connection, past or future), a shared secret from the KEM
// exchange, and two direction-separated AES keys derived from it via
// HKDF-SHA256 (see secure_channel.hpp for why direction separation
// matters).
//
// NOT included: authentication. This handshake gets both sides onto the
// same shared secret, but neither side proves *who* it is. That means it
// protects a connection from eavesdropping, but not from a party that
// intercepts the very first message and runs the handshake twice (once
// with each real side, relaying between them). Real TLS pairs ephemeral
// key exchange with a signature (a certificate) specifically to close
// that gap. Worth adding before this touches a network you don't fully
// control; not needed for two processes on a machine you already trust
// (e.g. localhost, or a link you otherwise control).
//
// Wire format for the handshake itself (necessarily unencrypted -- there
// is no shared key yet):
//   server -> client: [4-byte length][1184-byte ML-KEM-768 public key]
//   client -> server: [4-byte length][1088-byte ciphertext]

#include "crypto_utils.hpp"
#include "kem_interface.hpp"
#include "secure_channel.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <vector>

namespace secure {

inline bool send_raw_frame(int fd, const uint8_t* data, size_t len) {
    const uint32_t len_be = htonl(static_cast<uint32_t>(len));
    uint8_t len_buf[4];
    std::memcpy(len_buf, &len_be, 4);
    return write_exact(fd, len_buf, 4) && write_exact(fd, data, len);
}

inline bool recv_raw_frame(int fd, std::vector<uint8_t>& out, size_t expected_len) {
    uint8_t len_buf[4];
    if (!read_exact(fd, len_buf, 4)) return false;
    uint32_t len_be;
    std::memcpy(&len_be, len_buf, 4);
    const uint32_t len = ntohl(len_be);
    if (len != expected_len) return false;
    out.resize(len);
    return read_exact(fd, out.data(), len);
}

inline void derive_directional_keys(const uint8_t shared_secret[kem::SHARED_SECRET_BYTES],
                                     std::array<uint8_t, crypto::AES_KEY_BYTES>& client_write_key,
                                     std::array<uint8_t, crypto::AES_KEY_BYTES>& server_write_key) {
    static const uint8_t salt[] = "kv-engine-tunnel-v1";
    static const uint8_t c2s_label[] = "client_write_key";
    static const uint8_t s2c_label[] = "server_write_key";

    const auto c2s = crypto::hkdf_sha256(shared_secret, kem::SHARED_SECRET_BYTES,
                                          salt, sizeof(salt) - 1,
                                          c2s_label, sizeof(c2s_label) - 1,
                                          crypto::AES_KEY_BYTES);
    const auto s2c = crypto::hkdf_sha256(shared_secret, kem::SHARED_SECRET_BYTES,
                                          salt, sizeof(salt) - 1,
                                          s2c_label, sizeof(s2c_label) - 1,
                                          crypto::AES_KEY_BYTES);
    std::copy(c2s.begin(), c2s.end(), client_write_key.begin());
    std::copy(s2c.begin(), s2c.end(), server_write_key.begin());
}

// Server side: generate an ephemeral keypair, send the public key, wait
// for the client's encapsulated ciphertext, decapsulate, derive keys.
inline std::optional<SecureChannel> server_handshake(int conn_fd) {
    uint8_t pk[kem::PUBLIC_KEY_BYTES], sk[kem::SECRET_KEY_BYTES];
    if (!kem::keypair(pk, sk)) return std::nullopt;
    if (!send_raw_frame(conn_fd, pk, kem::PUBLIC_KEY_BYTES)) return std::nullopt;

    std::vector<uint8_t> ct;
    if (!recv_raw_frame(conn_fd, ct, kem::CIPHERTEXT_BYTES)) return std::nullopt;

    uint8_t shared_secret[kem::SHARED_SECRET_BYTES];
    if (!kem::decapsulate(sk, ct.data(), shared_secret)) return std::nullopt;

    std::array<uint8_t, crypto::AES_KEY_BYTES> client_write_key{}, server_write_key{};
    derive_directional_keys(shared_secret, client_write_key, server_write_key);
    return SecureChannel(conn_fd, Role::Server, client_write_key, server_write_key);
}

// Client side: receive the server's public key, encapsulate against it,
// send the ciphertext back, derive the same keys the server just derived.
inline std::optional<SecureChannel> client_handshake(int conn_fd) {
    std::vector<uint8_t> pk;
    if (!recv_raw_frame(conn_fd, pk, kem::PUBLIC_KEY_BYTES)) return std::nullopt;

    uint8_t ct[kem::CIPHERTEXT_BYTES], shared_secret[kem::SHARED_SECRET_BYTES];
    if (!kem::encapsulate(pk.data(), ct, shared_secret)) return std::nullopt;
    if (!send_raw_frame(conn_fd, ct, kem::CIPHERTEXT_BYTES)) return std::nullopt;

    std::array<uint8_t, crypto::AES_KEY_BYTES> client_write_key{}, server_write_key{};
    derive_directional_keys(shared_secret, client_write_key, server_write_key);
    return SecureChannel(conn_fd, Role::Client, client_write_key, server_write_key);
}

} // namespace secure
