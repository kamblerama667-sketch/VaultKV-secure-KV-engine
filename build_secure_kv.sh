#!/bin/bash
# build_secure_kv.sh
#
# Compiles mlkem-native's C sources (gcc, matching the flags confirmed in
# their own examples/basic/Makefile) separately from our C++ code (g++),
# then links everything together. Two compilers, one binary -- this is the
# standard, correct way to combine a C library with a C++ project; it's
# not done as a single g++ invocation because g++ compiles .c files as
# C++ too (not C), and there's no guarantee a C90/C99 codebase like this
# one is also valid C++.
#
# Run from the same directory as secure_kv_demo.cpp, with mlkem_native/
# (the library source, see setup below) as a sibling directory.
set -e

CFLAGS="-O3 -std=c99 -I mlkem_native -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem -w"

mkdir -p build_objs
rm -f build_objs/*.o

i=0
OBJS=""
for f in $(find mlkem_native/src -name "*.c"); do
    i=$((i + 1))
    obj="build_objs/mlk_$i.o"
    gcc $CFLAGS -c "$f" -o "$obj"
    OBJS="$OBJS $obj"
done
echo "Compiled $i mlkem-native source files"

g++ -std=c++17 -O2 -pthread -I mlkem_native secure_kv_demo.cpp randombytes.cpp $OBJS -lcrypto -o secure_kv_demo
echo "Build complete: ./secure_kv_demo"
