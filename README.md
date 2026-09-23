# VaultKV

A persistent, crash-resilient key-value engine written from scratch in modern C++ (C++17), with an optional network tunnel secured by a post-quantum key exchange. No database, serialization, or networking libraries — only the C++ standard library, POSIX APIs, and (for the tunnel) OpenSSL and [mlkem-native](https://github.com/pq-code-package/mlkem-native).

## What this is

Two pieces that work together:

1. **A Bitcask-style storage engine** (`kv_engine.hpp`) — an append-only binary log with an in-memory index for O(1) lookups, sequential-scan crash recovery, single-file compaction, and thread-safe concurrent access.
2. **A secure network tunnel** — wraps that engine behind a client/server protocol where the initial key exchange uses ML-KEM-768 (real, formally-verified, not a placeholder), and every request/response afterward is encrypted with AES-256-GCM.

## On-disk record format

Every record is a 20-byte header followed by the key and value bytes, manually packed field-by-field (not a `struct` cast) so the layout is exact regardless of compiler padding rules:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | CRC32 (covers everything from offset 4 onward) |
| 4 | 8 | Timestamp (ms since epoch) |
| 12 | 4 | Key length |
| 16 | 4 | Value length — `0xFFFFFFFF` marks a delete tombstone |
| 20 | klen | Key bytes |
| 20+klen | vlen | Value bytes |

On startup, the engine scans the log sequentially, rebuilding the index and validating each record's CRC. It stops at the first torn or corrupt record and truncates the file there — this is what makes recovery from a mid-write crash safe.

## The secure tunnel

```
Client                                          Server
  |--- (handshake, unencrypted: no key yet) --->|
  |   ML-KEM-768 public key            <---     |  ephemeral keypair generated per connection
  |   ML-KEM-768 ciphertext            --->     |  encapsulate() against that public key
  |                                              |
  |   both sides now hold the same 32-byte shared secret
  |   HKDF-SHA256 derives TWO session keys: client_write_key, server_write_key
  |
  |--- AES-256-GCM encrypted PUT/GET/DEL ------->|  (client_write_key)
  |<-- AES-256-GCM encrypted responses ----------|  (server_write_key)
```

Two separate session keys (not one shared key) is deliberate: it keeps client-to-server and server-to-client traffic in completely separate nonce spaces, so there's no way for a message in one direction to accidentally reuse a (key, nonce) pair from the other — which would break AES-GCM's security guarantee outright.

**What this handshake does and doesn't protect against:** it defeats passive eavesdropping (nobody watching the wire can read the traffic) and gives forward secrecy (each connection gets a fresh keypair, so compromising one connection doesn't expose any other, past or future). It does **not** authenticate either side — nothing here proves the server you connected to is actually your server, only that whoever you're talking to now shares a secret with you. That's fine for two processes on a link you already trust (localhost, or a network you control); it would need a signature scheme layered on top before it should touch a network you don't fully trust.

## Building

The tunnel needs `mlkem_native/` (the library source, portable-only build — see below) and OpenSSL present.

```bash
# One-time setup: vendor the library source
git clone https://github.com/pq-code-package/mlkem-native.git
cp -r mlkem-native/mlkem ./mlkem_native
rm -rf mlkem_native/src/native mlkem_native/src/fips202/native   # portable C only, no arch-specific assembly

# Build
chmod +x build_secure_kv.sh
./build_secure_kv.sh
```

`build_secure_kv.sh` compiles mlkem-native's C sources with `gcc -std=c99`, compiles this project's own code with `g++ -std=c++17`, and links both into one binary — two compilers because g++ treats `.c` files as C++ (not C), and there's no guarantee a C99 codebase is also valid C++.

## Running

```bash
./secure_kv_demo
```

Spins up a server thread and a client thread on real loopback TCP, completes the ML-KEM handshake, and runs a sequence of PUT/GET/DELETE operations over the encrypted channel, checking every response.

## Verified, not just written

- AES-256-GCM checked against an independent implementation, byte-for-byte, on a known test vector
- HKDF-SHA256 checked against RFC 5869's official test vector
- ML-KEM-768 sizes (1184 / 2400 / 1088 / 32 bytes) confirmed against the FIPS 203 standard
- Tamper detection confirmed directly: a flipped bit in an encrypted message's ciphertext, and separately in its authentication tag, are both rejected rather than silently accepted
- Crash recovery confirmed against an actually truncated file (not just a hypothetical), correctly dropping only the torn record
- Clean under AddressSanitizer, UndefinedBehaviorSanitizer, and ThreadSanitizer

## Project layout

| File | Purpose |
|---|---|
| `crc32.hpp` | CRC32 (IEEE 802.3), implemented from scratch |
| `record_format.hpp` | The on-disk record format — one shared definition |
| `kv_engine.hpp` | The storage engine: KeyDir, crash recovery, compaction, locking |
| `kem_interface.hpp` | ML-KEM-768 wrapper around mlkem-native |
| `crypto_utils.hpp` | HKDF-SHA256 and AES-256-GCM wrappers (OpenSSL-backed) |
| `secure_channel.hpp` | Wire framing and the encrypted channel |
| `handshake.hpp` | Connection setup: KEM exchange → session keys |
| `kv_protocol.hpp` | PUT/GET/DEL request and response encoding |
| `randombytes.cpp` | Real randomness for mlkem-native (OpenSSL-backed) |
| `secure_kv_demo.cpp` | End-to-end client/server demo |
| `mlkem_native/` | Vendored library source (see Third-party code) |

## Known limitations

- **No authentication in the handshake** (see above) — confidentiality and forward secrecy, not identity verification.
- **No per-read CRC check.** CRC is validated once, at startup, while rebuilding the index. A `get()` reads directly by offset and doesn't re-verify — same property as most log-structured stores, but worth knowing.
- **Compaction is single-file and stop-the-world**: it blocks other operations for its duration. Correct and simple; not built for high availability during a compaction pass.

## Third-party code

`mlkem_native/` is vendored source from [pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native) (Copyright © The mlkem-native project authors, licensed Apache-2.0 OR ISC OR MIT), formally verified for memory safety (CBMC) and constant-time behavior (HOL-Light). Not modified beyond removing the architecture-specific assembly backends for portability.

## What's next

- Clean up: `secure_kv_demo.db`, `build.log`, the `.backup` files, and the unused `mlkem_native.c`/`.h`/`_asm.S` monobuild artifacts aren't meant to be permanent — safe to delete once you're happy with the build.
- A `.gitignore` covering `*.db`, `build_objs/`, and compiled binaries, so build output stops getting committed.
- Decide whether the segmented-storage work (multi-file segments, hint-based fast recovery, integrated cache — built and tested earlier, not yet in this repo) merges into this codebase or stays separate.
- The custom atomic-based RWLock and thread pool, if you want to continue toward the full production spec.
