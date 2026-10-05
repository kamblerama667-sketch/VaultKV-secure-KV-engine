#!/usr/bin/env bash
# run_tests.sh -- builds and runs every test, plain and under sanitizers.
#
#   ./run_tests.sh            plain + AddressSanitizer/UBSan + ThreadSanitizer
#   ./run_tests.sh plain      plain build only (fastest)
#
# Environment (all optional):
#   CXX            C++ compiler                       (default g++)
#   OPENSSL_INC    extra include flags for OpenSSL    (e.g. -I/opt/openssl/include)
#   LIBCRYPTO      how to link libcrypto              (default -lcrypto)
#   KILLS          random SIGKILL iterations          (default 1500)
set -u
cd "$(dirname "$0")"
CXX=${CXX:-g++}; INC=${OPENSSL_INC:-}; LIBCRYPTO=${LIBCRYPTO:--lcrypto}; KILLS=${KILLS:-1500}
MODE=${1:-all}
B=build_tests; mkdir -p "$B/mlkem"
WRAP="-Wl,--wrap=open,--wrap=write,--wrap=pwrite,--wrap=fsync,--wrap=rename,--wrap=unlink,--wrap=ftruncate"
MLKEM_FLAGS="-I mlkem_native -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem"

# vendored ML-KEM (portable C; same flags as build_secure_kv.sh), compiled once
MOBJS=""
i=0
for f in $(find mlkem_native/src -name '*.c' | sort); do
  i=$((i+1)); o="$B/mlkem/m$i.o"
  [ -f "$o" ] || gcc -O3 -std=c99 $MLKEM_FLAGS -w -c "$f" -o "$o" || exit 2
  MOBJS="$MOBJS $o"
done

FAILED=0; SUMMARY=""
record() { # name variant status detail
  if [ "$3" = ok ]; then SUMMARY="$SUMMARY\n  PASS  $2  $1  $4"; else SUMMARY="$SUMMARY\n  FAIL  $2  $1  $4"; FAILED=1; fi
}
run_one() { # variant flags name sources... [-- args]
  local variant=$1 flags=$2 name=$3; shift 3
  local bin="$B/${name}_${variant}" extra=""
  [ "$name" = test_crash_syscalls ] && extra="$WRAP"
  local libs=""
  case "$name" in test_secure_channel) libs="randombytes.cpp $MOBJS $LIBCRYPTO"; extra="$extra $INC $MLKEM_FLAGS" ;; esac
  if ! $CXX -std=c++17 $flags -pthread -Wall -Wextra $extra "$name.cpp" $libs -o "$bin" 2> "$B/${name}_${variant}.build.log"; then
    record "$name" "$variant" fail "(build failed, see $B/${name}_${variant}.build.log)"; return
  fi
  rm -rf "$B/run" && mkdir -p "$B/run"
  local args=""; [ "$name" = test_crash_harness ] && args="$KILLS"
  local out; out=$(cd "$B/run" && timeout 900 "../../$bin" $args 2>&1); local rc=$?
  local line; line=$(echo "$out" | grep -E "checks passed|ops confirmed correct" | tail -1)
  if [ $rc -eq 0 ] && ! echo "$out" | grep -q "^  FAIL"; then record "$name" "$variant" ok "${line:-}"
  else record "$name" "$variant" fail "(exit $rc) $(echo "$out" | grep -E '^  FAIL|ERROR|Sanitizer|runtime error' | head -2 | tr '\n' ' ')"; fi
}

ALL="test_kv_engine_recovery test_restart_bugs test_segment_hardening test_compaction_restart test_compaction test_segmented_recovery test_crash_harness test_crash_syscalls test_secure_channel"
THREADED="test_compaction test_segmented_recovery test_restart_bugs test_compaction_restart test_segment_hardening"

echo "== plain (-O2) =="
for t in $ALL; do run_one plain "-O2" $t; done
if [ "$MODE" != plain ]; then
  echo "== AddressSanitizer + UBSan =="
  for t in $ALL; do run_one asan "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined" $t; done
  echo "== ThreadSanitizer (suites that use threads) =="
  for t in $THREADED; do run_one tsan "-O1 -g -fsanitize=thread" $t; done
fi

# end-to-end demo: handshake + real ML-KEM + encrypted KV protocol
if $CXX -std=c++17 -O2 -pthread $INC $MLKEM_FLAGS secure_kv_demo.cpp randombytes.cpp $MOBJS $LIBCRYPTO -o "$B/secure_kv_demo" 2> "$B/demo.build.log"; then
  rm -rf "$B/run"; mkdir -p "$B/run"; out=$(cd "$B/run" && timeout 60 ../secure_kv_demo 2>&1)
  if echo "$out" | grep -q "7/7 checks passed"; then record secure_kv_demo plain ok "7/7 checks passed"; else record secure_kv_demo plain fail "$(echo "$out" | tail -2 | tr '\n' ' ')"; fi
else record secure_kv_demo plain fail "(build failed, see $B/demo.build.log)"; fi

echo -e "$SUMMARY"
[ $FAILED -eq 0 ] && echo -e "\nALL TESTS PASSED" || echo -e "\nSOME TESTS FAILED"
exit $FAILED
