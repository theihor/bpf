#!/bin/bash
# Build kernel + selftests/bpf for vmtest
# Usage: ./build.sh [clean]
set -euo pipefail

cd "$(dirname "$0")/.."
KDIR=$(pwd)

MAKE="make LLVM=1 -j$(nproc)"

# LLVM 21 links against libstdc++ symbols not in system GCC 11.
# Use gcc-toolset-15's libstdc++ to resolve them.
GCC_TOOLSET_LIB="/opt/rh/gcc-toolset-15/root/usr/lib/gcc/x86_64-redhat-linux/15"
LLVM_EXTRA_LDFLAGS="-L${GCC_TOOLSET_LIB}"

if [ "${1:-}" = "clean" ]; then
    $MAKE clean
    $MAKE -C tools/testing/selftests/bpf clean
fi

# Generate config: ci.config + bpf selftests config
cp ci.config .config
cat ./tools/testing/selftests/bpf/config >> .config
$MAKE olddefconfig

# Build kernel
echo "=== Building kernel ==="
$MAKE

# Build selftests/bpf
echo "=== Building selftests/bpf ==="
$MAKE -C tools/testing/selftests/bpf clean
$MAKE -C tools/testing/selftests/bpf test_progs \
    LLVM_LDFLAGS="$(llvm-config --ldflags) ${LLVM_EXTRA_LDFLAGS}"

echo "=== Build complete ==="
echo "Kernel: $KDIR/arch/x86/boot/bzImage"
echo "test_progs: $KDIR/tools/testing/selftests/bpf/test_progs"
