// randombytes.cpp
//
// mlkem-native's "randomized" API (mlkem_keypair, mlkem_enc) needs an
// actual randombytes() to link against. Their own examples link
// test_only_rng, a deterministic, seeded PRNG that exists so their test
// suite can reproduce known test vectors -- explicitly not real randomness,
// and not something to ship. This is the real one, using the same
// RAND_bytes() call already verified elsewhere in this project (see
// crypto_utils.hpp's nonce generation).
//
// Signature matches the convention used across this whole family of PQC
// libraries (PQClean, the NIST reference code, liboqs all use the same
// shape). This is the one piece of this file that's an informed inference
// rather than something confirmed on screen -- if the linker or compiler
// disagrees, it'll fail loudly and immediately at build time, not silently
// at runtime, so it's a safe thing to have gotten slightly wrong.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <openssl/rand.h>


extern "C" int randombytes(uint8_t* buf, size_t len) {
    if (RAND_bytes(buf, static_cast<int>(len)) != 1) {
        return -1;
    }
    return 0;
}
