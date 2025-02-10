#!/bin/bash

set -euo pipefail

export KBUILD_OUTPUT=$(realpath kbuild-output)
mkdir -p $KBUILD_OUTPUT

cp -f repro.config $KBUILD_OUTPUT/.config
make olddefconfig
make -j$(nproc) all
make -j$(nproc) headers

# apt install lsb-release wget software-properties-common gnupg
# bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
export LLVM_VERSION=18

make -C tools/testing/selftests/bpf \
     CLANG=clang-${LLVM_VERSION} \
     LLC=llc-${LLVM_VERSION} \
     LLVM_STRIP=llvm-strip-${LLVM_VERSION} \
     -j$(nproc) test_progs-no_alu32

# wget https://github.com/danobi/vmtest/releases/download/v0.15.0/vmtest-x86_64
# chmod +x vmtest-x86_64
./vmtest-x86_64 -k $KBUILD_OUTPUT/$(make -s image_name) ./run-bpf-selftests.sh | tee test.log

