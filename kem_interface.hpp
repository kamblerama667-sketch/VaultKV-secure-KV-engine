#pragma once
// kem_interface.hpp
//
// Real ML-KEM-768 via pq-code-package/mlkem-native -- formally proven
// memory-safe and constant-time (see the project's own README/docs).
// This REPLACES the INSECURE_MOCK that stood in while the rest of the
// tunnel (framing, session keys, AES-GCM channel) was being built and
// tested against something with the right byte sizes but no real security.
//
// Function signatures and size macros below are taken directly from
// mlkem-native's own examples/basic/main.c, not inferred or guessed:
//   mlkem_keypair(pk, sk)        -> int, 0 on success
//   mlkem_enc(ct, ss, pk)        -> int, 0 on success
//   mlkem_dec(ss, ct, sk)        -> int, 0 on success
//   MLKEM768_PUBLICKEYBYTES / _SECRETKEYBYTES / _CIPHERTEXTBYTES, MLKEM_BYTES
//
// Build requirements (see the accompanying note for what's still unconfirmed):
//   - Compile with -DMLK_CONFIG_PARAMETER_SET=768
//   - The mlkem-native source needs to be reachable from the include path
//     as "mlkem_native/mlkem_native.h" (that's the exact path their own
//     example uses)
//   - A real randombytes() must be linked in -- see randombytes.cpp. The
//     library's own test_only_rng is NOT this: it's a deterministic,
//     seeded PRNG that exists purely so their test suite gets reproducible
//     output against known test vectors. Linking that into anything real
//     would mean every "random" key is actually predictable.

#include <cstddef>
#include <cstdint>

#ifndef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_PARAMETER_SET 768
#endif
#ifndef MLK_CONFIG_NAMESPACE_PREFIX
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#endif
#ifndef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_PARAMETER_SET 768
#endif
#ifndef MLK_CONFIG_NAMESPACE_PREFIX
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem
#endif
extern "C" {
#include "mlkem_native/mlkem_native.h"
}

namespace kem {

constexpr size_t PUBLIC_KEY_BYTES = MLKEM768_PUBLICKEYBYTES;
constexpr size_t SECRET_KEY_BYTES = MLKEM768_SECRETKEYBYTES;
constexpr size_t CIPHERTEXT_BYTES = MLKEM768_CIPHERTEXTBYTES;
constexpr size_t SHARED_SECRET_BYTES = MLKEM_BYTES; // 32 bytes -- same for every ML-KEM security level

inline bool keypair(uint8_t pk[PUBLIC_KEY_BYTES], uint8_t sk[SECRET_KEY_BYTES]) {
    return mlkem_keypair(pk, sk) == 0;
}

inline bool encapsulate(const uint8_t pk[PUBLIC_KEY_BYTES], uint8_t ct[CIPHERTEXT_BYTES],
                         uint8_t ss[SHARED_SECRET_BYTES]) {
    return mlkem_enc(ct, ss, pk) == 0;
}

inline bool decapsulate(const uint8_t sk[SECRET_KEY_BYTES], const uint8_t ct[CIPHERTEXT_BYTES],
                         uint8_t ss[SHARED_SECRET_BYTES]) {
    return mlkem_dec(ss, ct, sk) == 0;
}

} // namespace kem
