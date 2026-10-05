# VaultKV

A small key-value storage engine in C++17 (Bitcask-style append-only log, CRC-checked records,
crash recovery, compaction) with an optional **post-quantum encrypted network tunnel**
(ML-KEM-768 key exchange -> HKDF -> AES-256-GCM) carrying a PUT/GET/DEL protocol.

## Layout

| File | What it is |
|---|---|
| `crc32.hpp`, `record_format.hpp` | Record format shared by both engines: `[crc][timestamp][klen][vlen][key][value]`, tombstones, `fsync_dir` |
| `kv_engine.hpp` | Single-file engine: in-memory index over one log, recovery, stop-the-world `compact()` |
| `segmented_engine.hpp`, `lru_cache.hpp` | Segmented engine: many segment files + hint files, LRU cache, restart-safe crash-safe `compact()` |
| `kem_interface.hpp`, `handshake.hpp`, `crypto_utils.hpp`, `secure_channel.hpp`, `kv_protocol.hpp` | The tunnel and the wire protocol |
| `mlkem_native/` | Vendored ML-KEM (pq-code-package/mlkem-native, portable C). `mlkem_native.h` is the public header and **must stay** |
| `secure_kv_demo.cpp`, `build_secure_kv.sh` | End-to-end demo (handshake + encrypted KV round trips) |
| `test_*.cpp`, `run_tests.sh` | Tests; `./run_tests.sh` builds and runs all of them |

## Commands

Everything below is run from inside the project folder. In a Codespace the unzipped folder is usually a
sub-folder of the workspace, so `cd` into it first (if you see "No such file or directory", you are one folder too high).

### 1. Setup (Ubuntu / Debian / WSL / Codespaces)
```bash
sudo apt update && sudo apt install -y g++ gcc libssl-dev unzip
unzip VaultKV-secure-KV-engine-fixed.zip
cd VaultKV-secure-KV-engine
chmod +x run_tests.sh build_secure_kv.sh     # needed if the zip lost the executable bit
```

### 2. Run every test (recommended)
```bash
./run_tests.sh                # plain + AddressSanitizer/UBSan + ThreadSanitizer (about 2 minutes)
./run_tests.sh plain          # plain build only (fast)
KILLS=5000 ./run_tests.sh     # more random SIGKILL cycles
```
The last lines must read `ALL TESTS PASSED`.

- **ThreadSanitizer fails with `unexpected memory mapping` (exit 66)?** That is the machine's address randomisation, not a bug
  in the code (a real race prints `WARNING: ThreadSanitizer: data race`). Run it like this instead (this fixed it on GitHub Codespaces):
  ```bash
  setarch "$(uname -m)" -R ./run_tests.sh
  ```
- OpenSSL in a non-standard place:
  ```bash
  OPENSSL_INC=-I/path/include LIBCRYPTO=/path/libcrypto.so ./run_tests.sh
  ```

### 3. Encrypted-tunnel demo (real ML-KEM-768 handshake + encrypted PUT/GET/DEL)
```bash
./build_secure_kv.sh
./secure_kv_demo              # expect: 7/7 checks passed
```

### 4. Run one test on its own
These need no OpenSSL:
```bash
g++ -std=c++17 -O2 -pthread test_kv_engine_recovery.cpp -o t1 && ./t1
g++ -std=c++17 -O2 -pthread test_restart_bugs.cpp       -o t2 && ./t2
g++ -std=c++17 -O2 -pthread test_segment_hardening.cpp  -o t3 && ./t3
g++ -std=c++17 -O2 -pthread test_compaction_restart.cpp -o t4 && ./t4
g++ -std=c++17 -O2 -pthread test_compaction.cpp         -o t5 && ./t5
g++ -std=c++17 -O2 -pthread test_segmented_recovery.cpp -o t6 && ./t6
g++ -std=c++17 -O2 -pthread test_crash_harness.cpp      -o t7 && ./t7 1500      # 1500 random SIGKILL cycles
```
Syscall-level crash test (the `--wrap` flags are required):
```bash
g++ -std=c++17 -O2 -pthread test_crash_syscalls.cpp -o t8 \
  -Wl,--wrap=open,--wrap=write,--wrap=pwrite,--wrap=fsync,--wrap=rename,--wrap=unlink,--wrap=ftruncate
./t8
```
Tunnel test (run `./build_secure_kv.sh` first so `build_objs/` exists):
```bash
g++ -std=c++17 -O2 -pthread -I mlkem_native \
  -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem \
  test_secure_channel.cpp randombytes.cpp build_objs/*.o -lcrypto -o t9
./t9
```

### 5. Sanitizers on a single test
```bash
# AddressSanitizer + UBSan
g++ -std=c++17 -O1 -g -fsanitize=address,undefined -pthread test_compaction_restart.cpp -o t4_asan && ./t4_asan
# ThreadSanitizer (on Codespaces prefix the run with: setarch "$(uname -m)" -R)
g++ -std=c++17 -O1 -g -fsanitize=thread -pthread test_compaction.cpp -o t5_tsan && ./t5_tsan
```

### 6. Clean up, then commit
```bash
rm -rf build_tests build_objs secure_kv_demo secure_kv_demo.db t1 t2 t3 t4 t5 t6 t7 t8 t9 *_asan *_tsan
cd ..                                     # up to the git repository root
git add VaultKV-secure-KV-engine
git status --short | head -30             # only sources, tests, README, .gitignore should appear
git commit -m "Fix replay protection, recovery bounds, restart bugs; add compaction and crash tests"
git push
```
The tests delete their own scratch directories (`cr_*`, `ch_*`, `cs_*`, ...) when they finish; `.gitignore` covers the rest.

## What the tunnel guarantees (and does not)

Guaranteed, and tested (`test_secure_channel.cpp`):
- Confidentiality and integrity of every message (AES-256-GCM, separate key per direction, fresh keys per session).
- **Replay, reordering and dropped messages are detected.** The receiver tracks its own counter and requires each frame to
  carry exactly the next nonce. Any rejected frame is fatal for the channel; drop the connection when `receive()` returns nullopt.
- `send()` refuses messages the peer would refuse to read; the nonce counter never wraps.

NOT provided:
- **Authentication of the server or client.** The handshake is anonymous: an active attacker who sits between the two
  sides can run two handshakes and relay (man-in-the-middle). Pin the server's public key or add signatures before relying on it.
- The ML-KEM here is the **portable C** build. Upstream's formal constant-time proofs cover its assembly backends, which are
  removed; constant-time behavior of the code that runs here is neither proven nor measured.
- Keys and secrets live in ordinary process memory and are not wiped.
- No handshake/read timeouts: a silent peer can hold a blocking server forever.

## Storage engine guarantees

Tested by `test_kv_engine_recovery`, `test_segment_hardening`, `test_restart_bugs`, `test_compaction_restart`,
`test_crash_harness`, `test_crash_syscalls`:
- Recovery never throws, crashes or returns a wrong value on damaged logs: garbage length fields, truncation at every
  byte length, every single-bit flip (v1), damaged/missing/short/trailing-garbage hints (v2).
- A hint file is only an accelerator: it is trusted only if it parses exactly, stays inside its segment and reaches the
  segment's end; otherwise the segment is scanned. Hints are written atomically (temp + fsync + rename + directory fsync).
- `compact()` (v2) merges all sealed segments, CRC-verifies every record it copies, publishes the result with one
  atomic rename, and survives a kill before **every** mutating syscall (see `segmented_engine.hpp` header for the design).
- Not provided: per-read CRC checks (corruption after startup surfaces at the next restart or compaction), online
  (non-blocking) compaction, multi-process access to one directory.

## Verification scores

These are **correctness / robustness** scores. There is no speed benchmark (throughput or latency) in this repo yet:
no such numbers were measured, so none are claimed.

Measured on Ubuntu 24.04 with g++ 13.3 (full `./run_tests.sh`, about 107 s), and re-run on GitHub Codespaces
(`ALL TESTS PASSED`; ThreadSanitizer needed the `setarch ... -R` prefix there, see Commands).

### Final results (plain / AddressSanitizer+UBSan / ThreadSanitizer)

| Test | What it covers | Score | plain | ASan+UBSan | TSan |
|---|---|---|---|---|---|
| `test_kv_engine_recovery` | v1 engine: garbage lengths, every truncation, every bit flip, compaction | 27/27 | PASS | PASS | n/a |
| `test_restart_bugs` | v2 bugs A and C, 40 restarts vs a model | 7/7 | PASS | PASS | PASS |
| `test_segment_hardening` | damaged / missing / short hints, garbage lengths | 16/16 | PASS | PASS | PASS |
| `test_compaction_restart` | bug B scenario, 60 restarts with compactions, edge cases, corrupt source | 25/25 | PASS | PASS | PASS |
| `test_compaction` | original compaction suite (incl. concurrent writers) | 7/7 | PASS | PASS | PASS |
| `test_segmented_recovery` | original recovery + concurrency suite | 50,400/50,400 ops, 105 segments, 21,600 live keys | PASS | PASS | PASS |
| `test_crash_harness` | 18 named crash points + random SIGKILLs | 20/20 | PASS | PASS | n/a |
| `test_crash_syscalls` | crash before every mutating syscall | 6/6 | PASS | PASS | n/a |
| `test_secure_channel` | tunnel: replay, reorder, drop, tamper, reflection, oversize | 14/14 | PASS | PASS | n/a |
| `secure_kv_demo` | real ML-KEM-768 handshake + encrypted KV round trips | 7/7 | PASS | n/a | n/a |

(TSan is only run on the suites that use threads; the crash tests fork, which TSan does not support well.)

### Before vs after (the same tests against the original, unfixed code)

| Test | Original code | Fixed code |
|---|---|---|
| `test_secure_channel` | 4 checks FAIL, then hangs forever on the 17 MB send | 14/14 |
| `test_kv_engine_recovery` | 15/27 (12 FAIL, `std::bad_alloc` on garbage lengths) | 27/27 |
| `test_segment_hardening` | 6/16 (10 FAIL: lost keys on damaged hints, `bad_alloc`) | 16/16 |
| `test_restart_bugs` | 4/7 (3 FAIL: bugs A and C) | 7/7 |

### Crash and kill coverage

| Check | Result |
|---|---|
| Named crash points inside `compact()` (6 points x 3 data layouts) | 18/18 reopen identical |
| Crash before **every** mutating syscall during compaction | 42 / 42 / 77 points (3 layouts), all reopen identical |
| Crash before every mutating syscall while sealing/rolling segments | 81 points, no data lost, no wrong value |
| Crash during startup recovery (finishing an interrupted compaction) | 27 points, all reopen identical |
| Random SIGKILL, restart, compare to a model of completed operations | 1,500 cycles, 0 mismatches (1,175 kills landed mid-compaction, 237 mid-put, 73 mid-delete) |
| v1 log truncated at every byte length | every length recovers exactly the whole records |
| v1 log, every single-bit flip of every byte | 2,400 flips, never a wrong value, records before the flip intact |
| Tunnel: every single-bit modification of a frame | 360/360 rejected |
| Tunnel: 50 round trips in both directions, empty message | all correct |

### Do the tests actually catch bugs? (mutation testing)

Each bug below was deliberately re-introduced into a copy of the engine, and the suites were run.

| Re-introduced bug | Caught? | By |
|---|---|---|
| A: active segment's hints not rebuilt at restart | yes | restart, compaction-restart, crash-harness, crash-syscalls |
| Hint list never cleared on seal **and** roll (hint leak) | yes | segment-hardening, compaction-restart |
| Hint trusted although it stops short of the segment end | yes | segment-hardening |
| B-class: merged segment gets an ID above the active segment | yes | compaction-restart, crash-harness, crash-syscalls |
| Compaction marker ignored at startup | yes | crash-harness, crash-syscalls |
| Old segments deleted **before** the atomic rename | yes | crash-syscalls only |
| Compaction copies records without verifying their CRC | yes | compaction-restart |
| Unbounded allocation from a damaged header | yes | segment-hardening |
| Hint list not cleared on seal only | no (redundant) | the roll step clears it too, so behaviour is identical |
| Hint list not cleared on roll only | no (redundant) | the seal step clears it too, so behaviour is identical |
| Old hint file not removed before the rename | no (redundant) | hint validation already rejects a stale hint |

**8 of 11 variants caught.** The 3 that were not caught do not change behaviour: each removes one of two independent
safeguards. They are kept as defence in depth.

## Changes in this version

- **Secure channel:** receiver-side nonce tracking (replay/reorder/drop); fail-closed on any rejection; explicit big-endian
  nonces; sender refuses oversize messages (previously blocked forever on a 17 MB send) without consuming a nonce.
- **Both engines:** length fields are bounded by the bytes left in the file before allocating (a damaged header used to throw `std::bad_alloc`).
- **Segmented engine:**
  - Bug A: keys written before a restart vanished once the active segment sealed (the hint listed only post-restart records).
  - Bug C: a segment already over the size limit at restart sealed with an empty hint and lost all its keys.
  - Hint recovery no longer applies partial/short hints or silently gives up; it falls back to a full scan.
  - A failed hint write no longer leaks its records into the next segment's hint.
  - `compact()` added, designed so a compacted segment keeps the position of the newest segment it replaces (bug B cannot occur).
  - New directory `fsync`s after creating/renaming/deleting segment and hint files (also in `KVEngine::compact()`).
- Honest comment about the KEM's constant-time status; removed unused `mlkem_native.c` / `mlkem_native_asm.S`, backup files, build logs, binaries.
