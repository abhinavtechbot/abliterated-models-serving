#!/usr/bin/env bash
set -euo pipefail

# Scripts directory and Models directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODELS_DIR="$BASE_DIR/models"

mkdir -p "$MODELS_DIR"

echo "=== Abliterated Models Downloader ==="
echo "Target directory: $MODELS_DIR"
echo ""

# Choose downloader: huggingface-cli or curl
if command -v huggingface-cli >/dev/null 2>&1; then
    HF_CMD="huggingface-cli"
elif command -v hf >/dev/null 2>&1; then
    HF_CMD="hf"
else
    echo "huggingface_hub CLI not found on PATH. Attempting to install..."
    pip3 install -U "huggingface_hub[cli]" --break-system-packages 2>/dev/null || pip3 install -U "huggingface_hub[cli]" || true
    if command -v huggingface-cli >/dev/null 2>&1; then
        HF_CMD="huggingface-cli"
    else
        HF_CMD=""
    fi
fi

download_hf_file() {
    local repo="$1"
    local filename="$2"
    local dest="$MODELS_DIR/$filename"

    if [ -f "$dest" ]; then
        echo "✓ Already exists: $filename ($(du -h "$dest" | cut -f1))"
        return 0
    fi

    echo "--> Downloading $filename from $repo..."
    if [ -n "$HF_CMD" ]; then
        $HF_CMD download "$repo" "$filename" --local-dir "$MODELS_DIR" --local-dir-use-symlinks False
    else
        echo "Using curl for direct download..."
        curl -L -C - "https://huggingface.co/$repo/resolve/main/$filename" -o "$dest"
    fi
    echo "✓ Download complete: $filename"
}

# 1. Huihui-Qwen3.5-9B-abliterated (IQ4_XS) - High quality, uncensored 9B model
download_hf_file "mradermacher/Huihui-Qwen3.5-9B-abliterated-i1-GGUF" "Huihui-Qwen3.5-9B-abliterated.i1-IQ4_XS.gguf"

# 2. Huihui-Qwen3.5-4B-abliterated (IQ4_XS) - High throughput, uncensored 4B model
download_hf_file "mradermacher/Huihui-Qwen3.5-4B-abliterated-GGUF" "Huihui-Qwen3.5-4B-abliterated.IQ4_XS.gguf"

# 3. qwen25-3b-abliterated (Q4_K_M) - Ultra-fast 3B uncensored model
download_hf_file "mradermacher/qwen25-3b-abliterated-GGUF" "qwen25-3b-abliterated.Q4_K_M.gguf"

echo ""
echo "=== All Abliterated Models Downloaded Successfully ==="
ls -lh "$MODELS_DIR"/*.gguf 2>/dev/null || true
