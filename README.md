# Abliterated Model Server & System Telemetry Suite

High-performance, local serving stack for uncensored (abliterated) open-weights LLMs on macOS with native Metal acceleration, hardware telemetry, OpenAI-compatible streaming API, and responsive web chat interface.

---

## Highlights

- **Abliterated Model Serving**: Optimized for running refusal-direction stripped GGUF models:
  - `Huihui-Qwen3.5-9B-abliterated.i1-IQ4_XS.gguf` (4.71 GB — Deep reasoning & instruction following)
  - `Huihui-Qwen3.5-4B-abliterated.IQ4_XS.gguf` (2.28 GB — High-throughput 4B tier, ~8–12 tok/s)
  - `qwen25-3b-abliterated.Q4_K_M.gguf` (1.80 GB — Lightweight & ultra-fast, ~12–18 tok/s)
- **Native Apple Silicon & Intel Metal Support**: Leverages Apple `Metal` via `llama.cpp` (`llama-server`) with configurable GPU layer offloading (`-ngl`).
- **OpenAI-Compatible Streaming API**: Drop-in replacement for OpenAI SDKs at `http://127.0.0.1:8765/v1/chat/completions` with SSE streaming.
- **Dynamic Model Switching**: Hot-swap between loaded models via web UI or `POST /api/models/switch` without losing server state.
- **Real-Time Hardware Telemetry**:
  - Direct AppleSMC query engine (`bin/smc_sensors.c`) for CPU/GPU temperatures and fan RPMs without `sudo`.
  - Native Metal & IOKit monitor (`bin/gpu_sensors.m`) tracking Intel and discrete AMD/Apple GPUs, VRAM utilization, and DMA engine load.
- **Modern Web Chat Studio**:
  - Live token streaming with `<think>` collapsible accordion blocks.
  - Temperature, top-p, max tokens, and custom system prompt controls.
  - Multi-session chat history and telemetry HUD.
- **Remote Access Ready**: Built-in Cloudflare Quick Tunnel (`--tunnel`) with optional HTTP Basic Auth.

---

## Directory Layout

```
.
├── server.py              # Main daemon: HTTP proxy, SSE streamer, model manager & web server
├── collector.py           # Telemetry collector & anomaly detection engine
├── cli.py                 # CLI system inspection & baseline verification tool
├── baseline.json          # System integrity baseline configuration
├── active_model.txt       # Pointer to current active GGUF model
├── static/
│   ├── chat.html          # Chat studio web interface
│   └── index.html         # Hardware telemetry and monitoring dashboard
├── bin/
│   ├── smc_sensors.c      # AppleSMC temperature/fan sensor C source
│   └── gpu_sensors.m      # Metal/IOKit GPU metrics Objective-C source
├── scripts/
│   ├── download_models.sh # Downloads abliterated GGUFs from Hugging Face
│   ├── build_sensors.sh   # Compiles native telemetry sensors
│   └── setup_llama.sh     # Builds or links native llama.cpp server
├── models/                # Local GGUF storage (gitignored)
├── requirements.txt       # Optional Python dependencies
└── README.md
```

---

## Getting Started

### 1. Build Native Telemetry Sensors
Compile the AppleSMC and GPU sensors using Clang:
```bash
./scripts/build_sensors.sh
```

### 2. Download Abliterated Models
Download the quantization weights directly from Hugging Face into `models/`:
```bash
chmod +x scripts/download_models.sh
./scripts/download_models.sh
```

### 3. Ensure `llama-server` is Set Up
If `llama-server` is not already installed in `bin/llama/llama-server`, run:
```bash
chmod +x scripts/setup_llama.sh
./scripts/setup_llama.sh
```

### 4. Start the Server
Start the local server on port 8765:
```bash
python3 server.py --port 8765
```

Optional flags:
- `--tunnel`: Expose via a temporary Cloudflare Quick Tunnel (`trycloudflare.com`).
- `--tunnel-token <TOKEN>`: Use an authenticated named Cloudflare tunnel.
- `--interval <SEC>`: Telemetry polling interval (default: 5s).

Open your browser to:
- **Chat Studio**: [http://127.0.0.1:8765/chat](http://127.0.0.1:8765/chat)
- **System Dashboard**: [http://127.0.0.1:8765/](http://127.0.0.1:8765/)

---

## API Reference

### OpenAI-Compatible Chat Completions
```bash
curl http://127.0.0.1:8765/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "system", "content": "You are a helpful uncensored assistant."},
      {"role": "user", "content": "Hello! What model are you running?"}
    ],
    "stream": true,
    "temperature": 0.7
  }'
```

### Model Switching
List available models:
```bash
curl http://127.0.0.1:8765/api/models
```

Switch active model:
```bash
curl -X POST http://127.0.0.1:8765/api/models/switch \
  -H "Content-Type: application/json" \
  -d '{"model": "Huihui-Qwen3.5-4B-abliterated.IQ4_XS.gguf"}'
```

---

## License

MIT
