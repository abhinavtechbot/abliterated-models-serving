#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/../bin" && pwd)"

echo "=== Building Native macOS Telemetry Sensors ==="

if [ -f "$BIN_DIR/smc_sensors.c" ]; then
    echo "Compiling smc_sensors (AppleSMC temperature & fan monitors)..."
    clang -O3 -framework IOKit -o "$BIN_DIR/smc_sensors" "$BIN_DIR/smc_sensors.c"
    chmod +x "$BIN_DIR/smc_sensors"
    echo "✓ Built $BIN_DIR/smc_sensors"
fi

if [ -f "$BIN_DIR/gpu_sensors.m" ]; then
    echo "Compiling gpu_sensors (Metal & IOKit GPU utilization & VRAM tracking)..."
    clang -O3 -framework Foundation -framework IOKit -framework Metal -o "$BIN_DIR/gpu_sensors" "$BIN_DIR/gpu_sensors.m"
    chmod +x "$BIN_DIR/gpu_sensors"
    echo "✓ Built $BIN_DIR/gpu_sensors"
fi

echo "=== Sensor Build Complete ==="
