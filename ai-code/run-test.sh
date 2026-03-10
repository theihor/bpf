#!/bin/bash
# Run a BPF selftest via vmtest
# Usage: ./run-test.sh [-t TEST_FILTER] [-j]
# Example: ./run-test.sh -t verifier_and
#          ./run-test.sh -j   (all tests parallel)
set -euo pipefail

cd "$(dirname "$0")/.."
KDIR=$(pwd)

VMTEST="$KDIR/vmtest"
BZIMAGE="$KDIR/arch/x86/boot/bzImage"
TEST_PROGS="$KDIR/tools/testing/selftests/bpf/test_progs"

if [ ! -f "$BZIMAGE" ]; then
    echo "Error: bzImage not found. Run build.sh first."
    exit 1
fi

if [ ! -f "$TEST_PROGS" ]; then
    echo "Error: test_progs not found. Run build.sh first."
    exit 1
fi

# Build test_progs command with arguments passed through
TEST_ARGS="${*:---help}"
CMD="cd /mnt/vmtest/tools/testing/selftests/bpf && ./test_progs $TEST_ARGS"

echo "=== Running: test_progs $TEST_ARGS ==="

VMTEST_NO_UI=1 "$VMTEST" \
    -k "$BZIMAGE" \
    -- "$CMD"
