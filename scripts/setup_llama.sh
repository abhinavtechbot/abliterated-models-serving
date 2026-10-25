#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$BASE_DIR/bin/llama"

echo "=== LLaMA.cpp Native Build / Setup for macOS ==="

if [ -x "$BIN_DIR/llama-server" ]; then
    echo "✓ llama-server is already present at $BIN_DIR/llama-server"
    "$BIN_DIR/llama-server" --version 2>&1 | head -n 2 || true
    exit 0
fi

BUILD_TMP="$(mktemp -d /tmp/llama_build_XXXXXX)"
echo "Cloning latest llama.cpp to $BUILD_TMP..."
git clone --depth 1 https://github.com/ggml-org/llama.cpp.git "$BUILD_TMP"
cd "$BUILD_TMP"

echo "Configuring CMake with Metal support enabled..."
cmake -B build -DGGML_METAL=ON -DCMAKE_BUILD_TYPE=Release
echo "Compiling llama-server..."
cmake --build build -j"$(sysctl -n hw.ncpu || echo 4)" --target llama-server

mkdir -p "$BIN_DIR"
cp build/bin/llama-server "$BIN_DIR/"
cp build/bin/*.dylib "$BIN_DIR/" 2>/dev/null || true
echo "✓ Successfully installed llama-server into $BIN_DIR"
rm -rf "$BUILD_TMP"
