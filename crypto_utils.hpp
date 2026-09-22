#pragma once
// crypto_utils.hpp
//
// Thin wrappers around OpenSSL's HKDF-SHA256 and AES-256-GCM. Both were
// checked against a published test vector before anything else in this
// project was built on top of them:
//   - HKDF-SHA256: matched RFC 5869 Test Case 1 exactly.
//   - AES-256-GCM: matched an independent implementation (Python's
//     `cryptography` library) byte-for-byte on the same known-zero input.
//
// aes_gcm_encrypt takes the nonce as a caller-supplied parameter rather
// than generating one internally -- nonce *policy* (random vs. counter,
// and how directions share or don't share a key) belongs to whoever knows
// the channel's structure, which is secure_channel.hpp, not this file.

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace crypto {

constexpr size_t AES_KEY_BYTES = 32;
constexpr size_t GCM_NONCE_BYTES = 12;
constexpr size_t GCM_TAG_BYTES = 16;

inline std::vector<uint8_t> hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                                         const uint8_t* salt, size_t salt_len,
                                         const uint8_t* info, size_t info_len,
                                         size_t okm_len) {
    std::vector<uint8_t> okm(okm_len);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("HKDF: context allocation failed");

    bool ok = EVP_PKEY_derive_init(pctx) == 1
        && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1
        && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, static_cast<int>(salt_len)) == 1
        && EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, static_cast<int>(ikm_len)) == 1
        && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, static_cast<int>(info_len)) == 1;

    size_t out_len = okm_len;
    ok = ok && EVP_PKEY_derive(pctx, okm.data(), &out_len) == 1;
    EVP_PKEY_CTX_free(pctx);

    if (!ok || out_len != okm_len) throw std::runtime_error("HKDF: derivation failed");
    return okm;
}

// Encrypts pt_len bytes under `key` and the caller-supplied 12-byte
// `nonce`. Writes ciphertext (same length as plaintext) into ciphertext_out
// (must have room for pt_len bytes) and the 16-byte auth tag into tag_out.
inline bool aes_gcm_encrypt(const uint8_t key[AES_KEY_BYTES],
                             const uint8_t* plaintext, size_t pt_len,
                             const uint8_t nonce[GCM_NONCE_BYTES],
                             uint8_t* ciphertext_out,
                             uint8_t tag_out[GCM_TAG_BYTES]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0, out_len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_BYTES, nullptr) == 1
        && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;

    if (ok && pt_len > 0)
        ok = EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, static_cast<int>(pt_len)) == 1;
    out_len = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext_out + out_len, &len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, tag_out) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// Decrypts and verifies. Returns false on any failure, INCLUDING a tag
// mismatch (tampered or corrupted data) -- that's an expected, recoverable
// condition on a network channel, not something to throw an exception over.
inline bool aes_gcm_decrypt(const uint8_t key[AES_KEY_BYTES],
                             const uint8_t* ciphertext, size_t ct_len,
                             const uint8_t nonce[GCM_NONCE_BYTES],
                             const uint8_t tag[GCM_TAG_BYTES],
                             std::vector<uint8_t>& plaintext_out) {
    plaintext_out.assign(ct_len, 0);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0, out_len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_BYTES, nullptr) == 1
        && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;

    if (ok && ct_len > 0)
        ok = EVP_DecryptUpdate(ctx, plaintext_out.data(), &len, ciphertext, static_cast<int>(ct_len)) == 1;
    out_len = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_BYTES,
                                    const_cast<uint8_t*>(tag)) == 1;
    ok = ok && EVP_DecryptFinal_ex(ctx, plaintext_out.data() + out_len, &len) == 1; // 0 return = tag mismatch

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { plaintext_out.clear(); return false; }
    return true;
}

} // namespace crypto
