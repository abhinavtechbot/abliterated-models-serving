#!/usr/bin/env python3
"""
MacGuard Live Dashboard & Background Monitoring Daemon
Serves the web dashboard on http://127.0.0.1:8765, runs periodic
unauthorized usage checks in the background, and optionally starts a
Cloudflare Quick Tunnel (trycloudflare.com) protected by HTTP Basic Auth.
"""

import argparse
import base64
import hmac
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Optional

from collector import BASE_DIR, MODEL_PATH, MacSecurityCollector

STATIC_DIR = BASE_DIR / "static"
CLOUDFLARED_BIN = BASE_DIR / "bin" / "cloudflared"
LLAMA_SERVER_BIN = BASE_DIR / "bin" / "llama" / "llama-server"
TUNNEL_URL_FILE = BASE_DIR / "tunnel_url.txt"
TUNNEL_LOG_FILE = BASE_DIR / "tunnel.log"
ACTIVE_MODEL_FILE = BASE_DIR / "active_model.txt"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class MonitorEngine:
    def __init__(self, interval_sec: int = 5, port: int = 8765, enable_tunnel: bool = False, tunnel_token: Optional[str] = None):
        self.collector = MacSecurityCollector()
        self.interval_sec = interval_sec
        self.port = port
        self.enable_tunnel = enable_tunnel
        self.tunnel_token = tunnel_token
        self.tunnel_url: Optional[str] = None
        self.llm_proc: Optional[subprocess.Popen] = None
        self.embed_proc: Optional[subprocess.Popen] = None
        self.dispatch_proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        if ACTIVE_MODEL_FILE.exists():
            try:
                self.current_model_name = ACTIVE_MODEL_FILE.read_text().strip()
            except Exception:
                self.current_model_name = MODEL_PATH.name
        else:
            self.current_model_name = MODEL_PATH.name
        self._latest_snapshot = self.collector.collect_snapshot(record_metrics=True)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._ensure_llm_server()
        self._ensure_embed_server()
        self._ensure_dispatch_server()
        self._thread.start()

    def list_available_models(self) -> list:
        models_dir = BASE_DIR / "models"
        res = []
        if models_dir.exists():
            for p in sorted(models_dir.glob("*.gguf")):
                if p.name.endswith(".part"):
                    continue
                size_mb = round(p.stat().st_size / (1024 * 1024), 1)
                clean_name = p.stem.replace(".i1-IQ4_XS", "").replace(".IQ4_XS", "").replace(".Q4_K_M", "")
                if "3b" in clean_name.lower():
                    tag = "Fast (~11.5 tok/s)"
                elif "4b" in clean_name.lower():
                    tag = "Fast (~8.0 tok/s)"
                elif "9b" in clean_name.lower():
                    tag = "Deep (~4.6 tok/s)"
                elif "1.5b" in clean_name.lower():
                    tag = "Ultra-Fast (~20 tok/s)"
                else:
                    tag = f"{size_mb} MB"
                res.append({
                    "filename": p.name,
                    "display_name": clean_name,
                    "tag": tag,
                    "size_mb": size_mb,
                    "active": (p.name == self.current_model_name),
                })
        return res

    def switch_model(self, model_name: str) -> bool:
        target = BASE_DIR / "models" / model_name
        if not target.exists() or not target.is_file():
            return False
        with self._lock:
            self.current_model_name = model_name
            try:
                ACTIVE_MODEL_FILE.write_text(model_name)
            except Exception:
                pass
            try:
                subprocess.run(["/usr/bin/pkill", "-9", "-f", "llama-server.*--port 8080"], stderr=subprocess.DEVNULL)
            except Exception:
                pass
            if self.llm_proc:
                try:
                    self.llm_proc.kill()
                except Exception:
                    pass
                self.llm_proc = None
            self._ensure_llm_server()
            return True

    def _ensure_llm_server(self) -> None:
        """Auto-launch or hot-swap llama-server on port 8080 once the target GGUF model finishes downloading."""
        target_model_file = BASE_DIR / "models" / self.current_model_name
        if not target_model_file.exists() or not LLAMA_SERVER_BIN.exists():
            return
        if self.llm_proc is not None and self.llm_proc.poll() is None:
            return
        # Check if already listening on 8080 with the target model
        try:
            ps_out = subprocess.run(
                ["/bin/ps", "-axo", "pid,command"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            ).stdout or ""
            target_running = False
            for line in ps_out.splitlines():
                if "llama-server" in line and "--port 8080" in line:
                    if self.current_model_name in line:
                        target_running = True
                    else:
                        pid_str = line.strip().split()[0]
                        if pid_str.isdigit():
                            subprocess.run(["/bin/kill", "-9", pid_str], stderr=subprocess.DEVNULL)
                            time.sleep(0.5)
            if target_running:
                return
        except Exception:
            pass
        try:
            env = os.environ.copy()
            env["DYLD_LIBRARY_PATH"] = str(LLAMA_SERVER_BIN.parent)
            self.llm_proc = subprocess.Popen(
                [
                    str(LLAMA_SERVER_BIN),
                    "-m",
                    str(target_model_file),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8080",
                    "-c",
                    "4096",
                    "-t",
                    "5",
                    "-ctk",
                    "q8_0",
                    "-ctv",
                    "q8_0",
                    "-b",
                    "512",
                    "-ub",
                    "512",
                    "-ngl",
                    "4",
                    "-np",
                    "1",
                    "--metrics",
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            print(f"Started local LLM server ({self.current_model_name}) on http://127.0.0.1:8080 (PID {self.llm_proc.pid})")
        except Exception as exc:
            print(f"[!] Failed to start llama-server: {exc}")

    def _ensure_embed_server(self) -> None:
        """Keep the Qwen3-Embedding-0.6B-Q8_0 server resident on port 8081 outside the dynamic model switcher."""
        embed_model_file = BASE_DIR / "models" / "qwen3-embedding-0.6b" / "Qwen3-Embedding-0.6B-Q8_0.gguf"
        if not embed_model_file.exists() or not LLAMA_SERVER_BIN.exists():
            return
        if self.embed_proc is not None and self.embed_proc.poll() is None:
            return
        try:
            ps_out = subprocess.run(
                ["/bin/ps", "-axo", "pid,command"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            ).stdout or ""
            for line in ps_out.splitlines():
                if "llama-server" in line and "--port 8081" in line:
                    return
        except Exception:
            pass
        try:
            env = os.environ.copy()
            env["DYLD_LIBRARY_PATH"] = str(LLAMA_SERVER_BIN.parent)
            env["GGML_METAL_SHARED_BUFFERS_ENABLE"] = "1"
            log_path = BASE_DIR / "llama-embedding-8081.log"
            log_f = open(str(log_path), "a")
            self.embed_proc = subprocess.Popen(
                [
                    str(LLAMA_SERVER_BIN),
                    "-m",
                    str(embed_model_file),
                    "--embeddings",
                    "--pooling",
                    "last",
                    "--embd-normalize",
                    "2",
                    "-ngl",
                    "99",
                    "-c",
                    "4096",
                    "-b",
                    "4096",
                    "-ub",
                    "4096",
                    "-t",
                    "4",
                    "--port",
                    "8081",
                    "--host",
                    "127.0.0.1",
                    "--alias",
                    "qwen3-embedding-0.6b",
                ],
                env=env,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            print(f"Started resident embedding server on http://127.0.0.1:8081 (PID {self.embed_proc.pid})")
        except Exception as exc:
            print(f"[!] Failed to start embedding llama-server: {exc}")

    def _ensure_dispatch_server(self) -> None:
        """Keep the Dispatch Memory FastAPI backend resident on 127.0.0.1:8766 (proxied via /decide and /confirm on 8765)."""
        dispatch_dir = Path.home() / "dispatch-memory"
        venv_py = dispatch_dir / ".venv" / "bin" / "python"
        serve_py = dispatch_dir / "serve.py"
        if not venv_py.exists() or not serve_py.exists():
            return
        if self.dispatch_proc is not None and self.dispatch_proc.poll() is None:
            return
        try:
            ps_out = subprocess.run(
                ["/bin/ps", "-axo", "pid,command"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
            ).stdout or ""
            for line in ps_out.splitlines():
                if "dispatch-memory/serve.py" in line:
                    return
        except Exception:
            pass
        try:
            log_path = dispatch_dir / "runs" / "serve.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_f = open(str(log_path), "a")
            self.dispatch_proc = subprocess.Popen(
                [str(venv_py), str(serve_py), "--host", "127.0.0.1", "--port", "8766"],
                cwd=str(dispatch_dir),
                stdout=log_f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            print(f"Started Dispatch Memory FastAPI backend on http://127.0.0.1:8766 (PID {self.dispatch_proc.pid})")
        except Exception as exc:
            print(f"[!] Failed to start Dispatch Memory FastAPI backend: {exc}")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(self.interval_sec)
            try:
                self._ensure_llm_server()
                self._ensure_embed_server()
                self._ensure_dispatch_server()
                if self.enable_tunnel or self.tunnel_token:
                    start_cloudflare_tunnel(self.port, self, tunnel_token=self.tunnel_token, quiet=True)
                snap = self.collector.collect_snapshot(record_metrics=True)
                with self._lock:
                    self._latest_snapshot = snap
            except Exception:
                pass

    def get_snapshot(self, refresh: bool = False):
        if refresh:
            snap = self.collector.collect_snapshot(record_metrics=False)
            with self._lock:
                self._latest_snapshot = snap
        else:
            with self._lock:
                snap = dict(self._latest_snapshot)
                res = dict(snap.get("resources") or {})
                snap["resources"] = res
            if (time.time() - self.collector._prev_gpu_ts) >= 1.2:
                gpu_info = self.collector.get_gpu_stats()
                res["gpu_pct"] = gpu_info["gpu_pct"]
                res["gpu_vram_used_mb"] = gpu_info["gpu_vram_used_mb"]
                res["gpu_vram_total_mb"] = gpu_info["gpu_vram_total_mb"]
                res["gpus"] = gpu_info["gpus"]
                res["thermals"] = self.collector.get_thermal_stats()
        snap["tunnel_url"] = self.tunnel_url
        snap["active_model"] = self.current_model_name
        snap["available_models"] = self.list_available_models()
        return snap


def start_cloudflare_tunnel(
    port: int, engine: MonitorEngine, tunnel_token: Optional[str] = None, quiet: bool = False
) -> Optional[subprocess.Popen]:
    """Start or reuse an existing cloudflared tunnel writing to tunnel.log (never PIPE, avoiding SIGPIPE on server restart)."""
    # Check if cloudflared is already running for this port
    try:
        pgrep = subprocess.run(
            ["/usr/bin/pgrep", "-f", "cloudflared tunnel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
        )
        if pgrep.returncode == 0 and TUNNEL_URL_FILE.exists():
            saved_url = TUNNEL_URL_FILE.read_text().strip()
            if saved_url:
                engine.tunnel_url = saved_url
                if not quiet:
                    print(f"Reusing active Cloudflare Tunnel: {engine.tunnel_url}")
                return None
    except Exception:
        pass

    bin_path = str(CLOUDFLARED_BIN) if CLOUDFLARED_BIN.exists() else "cloudflared"
    cmd = [bin_path, "tunnel", "--no-autoupdate", "--protocol", "http2"]
    if tunnel_token:
        cmd += ["run", "--token", tunnel_token]
    else:
        cmd += ["--url", f"http://127.0.0.1:{port}"]

    try:
        log_f = open(TUNNEL_LOG_FILE, "w")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception as exc:
        print(f"[!] Failed to start cloudflared: {exc}")
        return None

    def _watch_output():
        url_pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
        for _ in range(60):
            time.sleep(0.5)
            try:
                text = TUNNEL_LOG_FILE.read_text(errors="ignore")
                match = url_pattern.search(text)
                if match:
                    engine.tunnel_url = match.group(0)
                    TUNNEL_URL_FILE.write_text(engine.tunnel_url + "\n")
                    print(f"Cloudflare Quick Tunnel active: {engine.tunnel_url}")
                    break
            except Exception:
                pass

    threading.Thread(target=_watch_output, daemon=True).start()
    return proc


def make_handler(engine: MonitorEngine, auth_creds: Optional[str]):
    expected_token = (
        base64.b64encode(auth_creds.encode("utf-8")).decode("ascii")
        if auth_creds
        else None
    )

    class RequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _check_auth(self) -> bool:
            """Require HTTP Basic Auth on Cloudflare Tunnel requests (or all requests if --auth is explicit)."""
            if not expected_token:
                return True
            is_tunnel_req = bool(
                self.headers.get("Cf-Connecting-Ip")
                or self.headers.get("Cf-Ray")
                or self.headers.get("X-Forwarded-For")
            )
            if not is_tunnel_req and self.client_address[0] == "127.0.0.1":
                return True
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                provided = auth_header.split(" ", 1)[1].strip()
                if hmac.compare_digest(provided, expected_token):
                    return True
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="MacGuard Security Monitor"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Unauthorized: Valid MacGuard credentials required.\n")
            return False

        def _send_json(self, payload, status=HTTPStatus.OK):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self._check_auth():
                return

            if self.path == "/" or self.path.startswith("/index.html"):
                index_file = STATIC_DIR / "index.html"
                content = index_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

            if self.path == "/chat" or self.path.startswith("/chat.html"):
                chat_file = STATIC_DIR / "chat.html"
                content = chat_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

            if self.path == "/dispatch" or self.path.startswith("/dispatch.html"):
                dispatch_ui = Path.home() / "dispatch-memory" / "static" / "index.html"
                if dispatch_ui.exists():
                    content = dispatch_ui.read_bytes()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return

            if self.path.startswith("/status") or self.path.startswith("/api/dispatch/status"):
                engine._ensure_dispatch_server()
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8766/status", timeout=15.0) as resp:
                        out = json.loads(resp.read().decode("utf-8"))
                    self._send_json(out)
                except Exception as exc:
                    self._send_json({"error": str(exc)}, status=HTTPStatus.SERVICE_UNAVAILABLE)
                return

            if self.path.startswith("/plot.png") or self.path.startswith("/api/dispatch/plot.png"):
                plot_file = Path.home() / "dispatch-memory" / "runs" / "accuracy_ece_vs_version.png"
                if plot_file.exists():
                    content = plot_file.read_bytes()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(content)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(content)
                    return

            if self.path.startswith("/api/models"):
                self._send_json({
                    "active_model": engine.current_model_name,
                    "models": engine.list_available_models(),
                })
                return

            if self.path.startswith("/api/overview"):
                self._send_json(engine.get_snapshot())
                return

            if self.path.startswith("/api/alerts"):
                self._send_json({"alerts": engine.collector.storage.get_alerts(limit=100)})
                return

            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self):
            if not self._check_auth():
                return

            if self.path in ("/decide", "/confirm"):
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                engine._ensure_dispatch_server()
                try:
                    req = urllib.request.Request(
                        f"http://127.0.0.1:8766{self.path}",
                        data=raw_body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=60.0) as resp:
                        out = json.loads(resp.read().decode("utf-8"))
                    self._send_json(out)
                except urllib.error.HTTPError as he:
                    try:
                        err_body = json.loads(he.read().decode("utf-8"))
                    except Exception:
                        err_body = {"error": str(he)}
                    self._send_json(err_body, status=he.code)
                except Exception as exc:
                    self._send_json(
                        {"error": f"Dispatch Memory service error: {exc}"},
                        status=HTTPStatus.SERVICE_UNAVAILABLE,
                    )
                return

            if self.path == "/api/models/switch":
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    req_data = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    req_data = {}
                target_model = req_data.get("model", "")
                if engine.switch_model(target_model):
                    self._send_json({"ok": True, "active_model": engine.current_model_name})
                else:
                    self._send_json({"ok": False, "error": "Model file not found"}, status=HTTPStatus.BAD_REQUEST)
                return

            if self.path == "/api/baseline":
                baseline = engine.collector.save_current_as_baseline()
                engine.get_snapshot(refresh=True)
                self._send_json({"ok": True, "baseline": baseline})
                return

            if self.path == "/api/alerts/clear":
                cleared = engine.collector.storage.acknowledge_all_alerts()
                engine.get_snapshot(refresh=True)
                self._send_json({"ok": True, "cleared": cleared})
                return

            if self.path == "/api/scan":
                threading.Thread(
                    target=engine.collector.run_deep_auth_scan, daemon=True
                ).start()
                snap = engine.get_snapshot(refresh=True)
                self._send_json({"ok": True, "status": snap["status"]})
                return

            if self.path == "/api/llm/chat":
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    req_data = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    req_data = {}
                prompt = str(req_data.get("prompt", "Write a one-liner Python Fibonacci generator.")).strip()
                max_tokens = int(req_data.get("max_tokens", 160))

                payload = json.dumps(
                    {
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": max_tokens,
                        "temperature": 0.6,
                        "chat_template_kwargs": {"enable_thinking": False},
                    }
                ).encode("utf-8")

                t0 = time.time()
                try:
                    req = urllib.request.Request(
                        "http://127.0.0.1:8080/v1/chat/completions",
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=90.0) as resp:
                        out = json.loads(resp.read().decode("utf-8"))
                    elapsed = max(0.05, time.time() - t0)
                    msg_obj = out.get("choices", [{}])[0].get("message", {})
                    content_str = (msg_obj.get("content") or "").strip()
                    reasoning_str = (msg_obj.get("reasoning_content") or "").strip()
                    if content_str and reasoning_str:
                        reply = f"<think>{reasoning_str}</think>\n\n{content_str}"
                    else:
                        reply = content_str or reasoning_str
                    usage = out.get("usage", {})
                    p_tok = int(usage.get("prompt_tokens", 0))
                    c_tok = int(usage.get("completion_tokens", max(1, len(reply.split()))))
                    timings = out.get("timings", {})
                    tok_s = float(timings.get("predicted_per_second", c_tok / elapsed))
                    engine.collector.record_llm_usage(p_tok, c_tok, tok_s, elapsed, reply)
                    engine.get_snapshot(refresh=True)
                    self._send_json(
                        {
                            "ok": True,
                            "reply": reply,
                            "prompt_tokens": p_tok,
                            "completion_tokens": c_tok,
                            "tok_per_sec": round(tok_s, 1),
                            "latency_sec": round(elapsed, 2),
                        }
                    )
                except Exception as exc:
                    self._send_json(
                        {"ok": False, "error": f"LLM server not ready yet: {exc}"},
                        status=HTTPStatus.SERVICE_UNAVAILABLE,
                    )
                return

            if self.path == "/api/llm/stream":
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    req_data = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    req_data = {}

                messages = req_data.get("messages") or [
                    {"role": "user", "content": str(req_data.get("prompt", "Hello!"))}
                ]
                max_tokens = int(req_data.get("max_tokens", 512))
                temperature = float(req_data.get("temperature", 0.6))
                enable_thinking = bool(req_data.get("enable_thinking", False))

                payload = json.dumps(
                    {
                        "messages": messages,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                        "stream": True,
                        "chat_template_kwargs": {"enable_thinking": enable_thinking},
                    }
                ).encode("utf-8")

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()

                t0 = time.time()
                completion_tokens = 0
                prompt_tokens = sum(len(str(m.get("content", "")).split()) for m in messages)
                full_text = []

                try:
                    req = urllib.request.Request(
                        "http://127.0.0.1:8080/v1/chat/completions",
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=180.0) as resp:
                        for raw_line in resp:
                            line = raw_line.decode("utf-8", errors="ignore").strip()
                            if not line or not line.startswith("data:"):
                                continue
                            data_str = line[5:].strip()
                            if data_str == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data_str)
                            except Exception:
                                continue

                            delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                            c_piece = delta.get("content") or ""
                            r_piece = delta.get("reasoning_content") or ""
                            if c_piece or r_piece:
                                completion_tokens += 1
                                full_text.append(c_piece or r_piece)
                                evt = json.dumps(
                                    {
                                        "content": c_piece,
                                        "reasoning": r_piece,
                                        "tokens": completion_tokens,
                                        "tok_per_sec": round(
                                            completion_tokens / max(0.05, time.time() - t0), 1
                                        ),
                                    }
                                )
                                self.wfile.write(f"data: {evt}\n\n".encode("utf-8"))
                                self.wfile.flush()

                    elapsed = max(0.05, time.time() - t0)
                    tok_s = round(completion_tokens / elapsed, 1)
                    engine.collector.record_llm_usage(
                        prompt_tokens,
                        completion_tokens,
                        tok_s,
                        elapsed,
                        "".join(full_text),
                    )
                    done_evt = json.dumps(
                        {
                            "done": True,
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "tok_per_sec": tok_s,
                            "latency_sec": round(elapsed, 2),
                        }
                    )
                    self.wfile.write(f"data: {done_evt}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except Exception as exc:
                    err_evt = json.dumps({"error": str(exc), "done": True})
                    try:
                        self.wfile.write(f"data: {err_evt}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except Exception:
                        pass
                return

            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    return RequestHandler


def main():
    parser = argparse.ArgumentParser(description="MacGuard Security Monitor Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    parser.add_argument("--interval", type=int, default=5, help="Collection interval seconds")
    parser.add_argument(
        "--tunnel",
        action="store_true",
        help="Expose dashboard via Cloudflare Tunnel",
    )
    parser.add_argument(
        "--tunnel-token",
        default=os.environ.get("CLOUDFLARE_TUNNEL_TOKEN"),
        help="Optional Cloudflare Named Tunnel token for a permanent custom subdomain",
    )
    parser.add_argument(
        "--auth",
        default=None,
        help="Optional HTTP Basic Auth in 'user:password' format (disabled by default)",
    )
    args = parser.parse_args()

    auth_creds = args.auth

    engine = MonitorEngine(
        interval_sec=args.interval,
        port=args.port,
        enable_tunnel=args.tunnel,
        tunnel_token=args.tunnel_token,
    )
    engine.start()

    if args.tunnel or args.tunnel_token:
        start_cloudflare_tunnel(args.port, engine, tunnel_token=args.tunnel_token)

    server = ThreadingHTTPServer((args.host, args.port), make_handler(engine, auth_creds))
    print(f"MacGuard Live Security Dashboard running at http://{args.host}:{args.port}")
    if auth_creds:
        print(f"HTTP Basic Auth enabled -> {auth_creds}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down MacGuard server (keeping Cloudflare Tunnel & LLM server alive).")
        server.server_close()


if __name__ == "__main__":
    main()
