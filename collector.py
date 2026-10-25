#!/usr/bin/env python3
"""
MacGuard Collector & Anomaly Detection Engine
Monitors macOS system resources, active sessions/logins, network connections,
persistence locations, and unified security logs for unauthorized usage.
"""

import hashlib
import json
import os
import plistlib
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "macguard.db"
BASELINE_PATH = BASE_DIR / "baseline.json"
SMC_BIN = BASE_DIR / "bin" / "smc_sensors"
GPU_BIN = BASE_DIR / "bin" / "gpu_sensors"
MODEL_NAME = "Huihui-Qwen3.5-9B-abliterated-IQ4_XS"
MODEL_PATH = BASE_DIR / "models" / "Huihui-Qwen3.5-9B-abliterated.i1-IQ4_XS.gguf"
MODEL_PART_PATH = BASE_DIR / "models" / "Huihui-Qwen3.5-9B-abliterated.i1-IQ4_XS.gguf.part"
MODEL_EXPECTED_BYTES = 5070612128

# Suspicious execution paths often used by malware/unauthorized scripts
SUSPICIOUS_PATHS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/")
# Known crypto-miner or suspicious process names
SUSPICIOUS_PROC_NAMES = {"xmrig", "minerd", "cpuminer", "ethminer", "nc", "ncat", "socat"}


def run_cmd(cmd: List[str], timeout: float = 4.0) -> str:
    """Run a system command safely with a timeout and return stdout."""
    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            universal_newlines=True,
        )
        return res.stdout or ""
    except Exception:
        return ""


class Storage:
    """SQLite storage for time-series stats, security alerts, and baseline state."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    cpu_pct REAL NOT NULL,
                    mem_pct REAL NOT NULL,
                    gpu_pct REAL DEFAULT 0.0,
                    gpu_vram_mb REAL DEFAULT 0.0,
                    cpu_temp_c REAL DEFAULT 0.0,
                    gpu_temp_c REAL DEFAULT 0.0,
                    load_1m REAL NOT NULL,
                    net_rx_kbps REAL NOT NULL,
                    net_tx_kbps REAL NOT NULL,
                    established_conns INTEGER NOT NULL,
                    listening_ports INTEGER NOT NULL,
                    active_users INTEGER NOT NULL
                )
                """
            )
            # Ensure existing DBs have gpu and thermal columns
            for col_def in (
                "gpu_pct REAL DEFAULT 0.0",
                "gpu_vram_mb REAL DEFAULT 0.0",
                "cpu_temp_c REAL DEFAULT 0.0",
                "gpu_temp_c REAL DEFAULT 0.0",
            ):
                try:
                    conn.execute(f"ALTER TABLE metrics ADD COLUMN {col_def}")
                except sqlite3.OperationalError:
                    pass
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    acknowledged INTEGER DEFAULT 0
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
            conn.commit()

    def insert_metric(self, data: Dict[str, Any]) -> None:
        now = int(time.time())
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO metrics (
                    ts, cpu_pct, mem_pct, gpu_pct, gpu_vram_mb, cpu_temp_c, gpu_temp_c,
                    load_1m, net_rx_kbps, net_tx_kbps, established_conns, listening_ports, active_users
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    data["cpu_pct"],
                    data["mem_pct"],
                    data.get("gpu_pct", 0.0),
                    data.get("gpu_vram_mb", 0.0),
                    data.get("cpu_temp_c", 0.0),
                    data.get("gpu_temp_c", 0.0),
                    data["load_1m"],
                    data["net_rx_kbps"],
                    data["net_tx_kbps"],
                    data["established_conns"],
                    data["listening_ports"],
                    data["active_users"],
                ),
            )
            # Retain last 24 hours of metrics
            cutoff = now - 86400
            conn.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
            conn.commit()

    def add_alert(
        self,
        severity: str,
        category: str,
        title: str,
        details: str,
        fingerprint: str,
        cooldown_sec: int = 600,
        notify_desktop: bool = True,
    ) -> bool:
        """Record an alert if an identical fingerprint wasn't raised within cooldown_sec."""
        now = int(time.time())
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.execute(
                """
                SELECT id FROM alerts
                WHERE fingerprint = ? AND ts > ? AND acknowledged = 0
                LIMIT 1
                """,
                (fingerprint, now - cooldown_sec),
            )
            if cur.fetchone():
                return False

            conn.execute(
                """
                INSERT INTO alerts (ts, severity, category, title, details, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now, severity, category, title, details, fingerprint),
            )
            conn.commit()

        if notify_desktop and severity in ("CRITICAL", "WARNING"):
            self._send_macos_notification(severity, category, title, details)
        return True

    @staticmethod
    def _send_macos_notification(severity: str, category: str, title: str, details: str) -> None:
        safe_title = f"MacGuard [{severity}] - {category}".replace('"', '\\"')
        safe_msg = f"{title}: {details}"[:160].replace('"', '\\"')
        script = f'display notification "{safe_msg}" with title "{safe_title}"'
        try:
            subprocess.Popen(
                ["/usr/bin/osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def get_recent_metrics(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM metrics ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in reversed(rows)]

    def get_alerts(self, limit: int = 50, include_ack: bool = False) -> List[Dict[str, Any]]:
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM alerts"
            if not include_ack:
                query += " WHERE acknowledged = 0"
            query += " ORDER BY ts DESC LIMIT ?"
            rows = conn.execute(query, (limit,)).fetchall()
            return [dict(r) for r in rows]

    def acknowledge_all_alerts(self) -> int:
        with self._lock, sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
            conn.commit()
            return cur.rowcount


class MacSecurityCollector:
    """Collects telemetry and evaluates security anomaly rules on macOS."""

    def __init__(self, storage: Optional[Storage] = None):
        self.storage = storage or Storage()
        self.ncpu = self._get_ncpu()
        self.total_mem_bytes = self._get_total_mem()
        self._prev_net: Optional[Tuple[float, int, int]] = None
        self._prev_gpu_ts: float = 0.0
        self._prev_gpu_ioreport: Dict[str, Tuple[int, int]] = {}
        self._last_gpu_info: Optional[Dict[str, Any]] = None
        self._gpu_lock = threading.Lock()
        self._cached_auth_events: List[Dict[str, Any]] = []
        self._last_deep_scan_ts: float = 0.0
        self._deep_scan_lock = threading.Lock()
        self._llm_stats_lock = threading.Lock()
        self._llm_usage = {
            "requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "last_tok_per_sec": 0.0,
            "last_latency_sec": 0.0,
            "last_response_preview": "",
        }
        self.baseline = self.load_baseline()

    def record_llm_usage(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        tok_per_sec: float,
        latency_sec: float,
        preview: str,
    ) -> None:
        with self._llm_stats_lock:
            self._llm_usage["requests"] += 1
            self._llm_usage["prompt_tokens"] += prompt_tokens
            self._llm_usage["completion_tokens"] += completion_tokens
            self._llm_usage["last_tok_per_sec"] = round(tok_per_sec, 1)
            self._llm_usage["last_latency_sec"] = round(latency_sec, 2)
            self._llm_usage["last_response_preview"] = preview[:200]

    @staticmethod
    def _get_ncpu() -> int:
        out = run_cmd(["/usr/sbin/sysctl", "-n", "hw.ncpu"]).strip()
        return int(out) if out.isdigit() else (os.cpu_count() or 4)

    @staticmethod
    def _get_total_mem() -> int:
        out = run_cmd(["/usr/sbin/sysctl", "-n", "hw.memsize"]).strip()
        return int(out) if out.isdigit() else 8 * 1024**3

    def load_baseline(self) -> Dict[str, Any]:
        if BASELINE_PATH.exists():
            try:
                return json.loads(BASELINE_PATH.read_text())
            except Exception:
                pass
        return {
            "created_at": None,
            "allowed_users": [os.environ.get("USER", "abhinavbot"), "root", "_windowserver"],
            "allowed_listen_ports": [],
            "launch_agents": {},
            "authorized_keys_sha256": None,
            "cpu_spike_threshold": 150.0,  # % across cores (e.g., 1.5 cores sustained)
        }

    def save_current_as_baseline(self) -> Dict[str, Any]:
        """Snapshot current listening ports, users, LaunchAgents, and SSH keys as trusted."""
        net = self.get_network_connections()
        sessions = self.get_sessions_and_logins()
        persistence = self.get_persistence_state()

        users = sorted(
            set(
                [os.environ.get("USER", "abhinavbot"), "root"]
                + [s["user"] for s in sessions["active_sessions"]]
            )
        )
        listen_sigs = sorted(
            set(f"{p['command']}:{p['port']}" for p in net["listening"])
        )
        agent_hashes = {
            item["path"]: item["sha256"] for item in persistence["items"]
        }

        baseline = {
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "allowed_users": users,
            "allowed_listen_ports": listen_sigs,
            "launch_agents": agent_hashes,
            "authorized_keys_sha256": persistence["authorized_keys_sha256"],
            "cpu_spike_threshold": 150.0,
        }
        BASELINE_PATH.write_text(json.dumps(baseline, indent=2))
        self.baseline = baseline
        return baseline

    def get_system_resources(self) -> Dict[str, Any]:
        """Collect CPU load, memory stats, disk usage, and network I/O rates."""
        # Load average
        load_str = run_cmd(["/usr/sbin/sysctl", "-n", "vm.loadavg"]).strip()
        load_vals = [float(x) for x in re.findall(r"\d+\.\d+", load_str)]
        load_1m, load_5m, load_15m = (load_vals + [0.0, 0.0, 0.0])[:3]

        # Memory via vm_stat
        vm_out = run_cmd(["/usr/bin/vm_stat"])
        page_size = 4096
        m_ps = re.search(r"page size of (\d+) bytes", vm_out)
        if m_ps:
            page_size = int(m_ps.group(1))

        pages: Dict[str, int] = {}
        for line in vm_out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                v_clean = v.strip().rstrip(".")
                if v_clean.isdigit():
                    pages[k.strip()] = int(v_clean)

        used_pages = (
            pages.get("Pages active", 0)
            + pages.get("Pages wired down", 0)
            + pages.get("Pages occupied by compressor", 0)
        )
        used_mem_bytes = used_pages * page_size
        mem_pct = round(min(100.0, (used_mem_bytes / max(1, self.total_mem_bytes)) * 100.0), 1)

        # Disk usage
        du = shutil.disk_usage("/")
        disk_pct = round((du.used / max(1, du.total)) * 100.0, 1)

        # Network throughput via netstat -ib
        rx_bytes, tx_bytes = self._read_net_bytes()
        now = time.time()
        rx_kbps, tx_kbps = 0.0, 0.0
        if self._prev_net is not None:
            dt = max(0.5, now - self._prev_net[0])
            rx_kbps = round(max(0.0, (rx_bytes - self._prev_net[1]) / 1024.0 / dt), 1)
            tx_kbps = round(max(0.0, (tx_bytes - self._prev_net[2]) / 1024.0 / dt), 1)
        self._prev_net = (now, rx_bytes, tx_bytes)

        # GPU telemetry via ioreg IOAccelerator
        gpu_info = self.get_gpu_stats()
        thermals = self.get_thermal_stats()

        return {
            "ncpu": self.ncpu,
            "load_1m": load_1m,
            "load_5m": load_5m,
            "load_15m": load_15m,
            "mem_used_gb": round(used_mem_bytes / (1024**3), 2),
            "mem_total_gb": round(self.total_mem_bytes / (1024**3), 2),
            "mem_pct": mem_pct,
            "disk_used_gb": round(du.used / (1024**3), 1),
            "disk_total_gb": round(du.total / (1024**3), 1),
            "disk_pct": disk_pct,
            "net_rx_kbps": rx_kbps,
            "net_tx_kbps": tx_kbps,
            "gpu_pct": gpu_info["gpu_pct"],
            "gpu_vram_used_mb": gpu_info["gpu_vram_used_mb"],
            "gpu_vram_total_mb": gpu_info["gpu_vram_total_mb"],
            "gpus": gpu_info["gpus"],
            "thermals": thermals,
        }

    def get_thermal_stats(self) -> Dict[str, Any]:
        """Read real-time AppleSMC CPU/GPU/Battery temperatures (°C) and fan RPMs."""
        if SMC_BIN.exists():
            out = run_cmd([str(SMC_BIN)], timeout=1.5).strip()
            if out:
                try:
                    data = json.loads(out)
                    if data.get("ok"):
                        return {
                            "cpu_temp_c": round(float(data.get("cpu_temp_c", 0.0)), 1),
                            "cpu_sensor": data.get("cpu_sensor", "TC0P"),
                            "gpu_temp_c": round(float(data.get("gpu_temp_c", 0.0)), 1),
                            "gpu_sensor": data.get("gpu_sensor", "TG0D"),
                            "mem_temp_c": round(float(data.get("mem_temp_c", 0.0)), 1),
                            "battery_temp_c": round(float(data.get("battery_temp_c", 0.0)), 1),
                            "fan0_rpm": int(data.get("fan0_rpm", 0)),
                            "fan1_rpm": int(data.get("fan1_rpm", 0)),
                        }
                except Exception:
                    pass
        return {
            "cpu_temp_c": 0.0,
            "cpu_sensor": "N/A",
            "gpu_temp_c": 0.0,
            "gpu_sensor": "N/A",
            "mem_temp_c": 0.0,
            "battery_temp_c": 0.0,
            "fan0_rpm": 0,
            "fan1_rpm": 0,
        }

    def get_llm_stats(self, procs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Collect local LLM model download progress, server status, and token/s telemetry."""
        total_mb = round(MODEL_EXPECTED_BYTES / (1024 * 1024), 1)
        downloaded_bytes = 0
        state = "NOT_DOWNLOADED"

        if MODEL_PATH.exists():
            downloaded_bytes = MODEL_PATH.stat().st_size
            state = "READY"
        elif MODEL_PART_PATH.exists():
            downloaded_bytes = MODEL_PART_PATH.stat().st_size
            state = "DOWNLOADING"

        downloaded_mb = round(downloaded_bytes / (1024 * 1024), 1)
        download_pct = round(min(100.0, (downloaded_bytes / max(1, MODEL_EXPECTED_BYTES)) * 100.0), 1)

        # Check if llama-server is running on 127.0.0.1:8080
        llm_proc = next(
            (p for p in procs if "llama" in p["command"].lower()),
            None,
        )
        server_online = False
        slots_busy = 0
        prompt_tokens_total = 0
        predicted_tokens_total = 0
        prompt_tok_s = 0.0
        gen_tok_s = 0.0

        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=0.6) as resp:
                h_data = json.loads(resp.read().decode("utf-8"))
                if h_data.get("status") == "ok":
                    server_online = True
                    if state != "DOWNLOADING":
                        state = "ONLINE"
                elif h_data.get("status") == "loading model":
                    if state != "DOWNLOADING":
                        state = "LOADING_MODEL"
        except Exception:
            pass

        if server_online:
            try:
                with urllib.request.urlopen("http://127.0.0.1:8080/metrics", timeout=0.6) as resp:
                    m_text = resp.read().decode("utf-8", errors="ignore")
                    for line in m_text.splitlines():
                        if line.startswith("#") or not line.strip():
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            k, v = parts[0], float(parts[1])
                            if "prompt_tokens_total" in k:
                                prompt_tokens_total = int(v)
                            elif "tokens_predicted_total" in k:
                                predicted_tokens_total = int(v)
                            elif "prompt_tokens_seconds" in k:
                                prompt_tok_s = round(v, 1)
                            elif "predicted_tokens_seconds" in k:
                                gen_tok_s = round(v, 1)
                            elif "requests_processing" in k:
                                slots_busy = int(v)
            except Exception:
                pass

        with self._llm_stats_lock:
            u = dict(self._llm_usage)

        return {
            "model_name": MODEL_NAME,
            "state": state,
            "server_online": server_online,
            "endpoint": "http://127.0.0.1:8080/v1",
            "downloaded_mb": downloaded_mb,
            "total_mb": total_mb,
            "download_pct": download_pct,
            "proc_cpu_pct": llm_proc["cpu"] if llm_proc else 0.0,
            "proc_mem_pct": llm_proc["mem"] if llm_proc else 0.0,
            "slots_busy": slots_busy,
            "requests": u["requests"],
            "prompt_tokens": max(prompt_tokens_total, u["prompt_tokens"]),
            "completion_tokens": max(predicted_tokens_total, u["completion_tokens"]),
            "prompt_tok_per_sec": prompt_tok_s,
            "gen_tok_per_sec": gen_tok_s or u["last_tok_per_sec"],
            "last_latency_sec": u["last_latency_sec"],
            "last_response_preview": u["last_response_preview"],
        }

    def get_gpu_stats(self) -> Dict[str, Any]:
        """Collect real-time GPU utilization, VRAM usage, and active contexts via IOReport + Metal + ioreg."""
        with self._gpu_lock:
            now = time.time()
            if self._last_gpu_info is not None and (now - self._prev_gpu_ts) < 1.2:
                return self._last_gpu_info
            dt = max(0.5, now - self._prev_gpu_ts) if self._prev_gpu_ts > 0 else 1.0
            self._prev_gpu_ts = now

        # 1. Read hardware IOReport counters & Metal device memory via bin/gpu_sensors
        ior_gpus: Dict[str, Dict[str, Any]] = {}
        if GPU_BIN.exists():
            out = run_cmd([str(GPU_BIN)], timeout=1.5).strip()
            if out:
                try:
                    data = json.loads(out)
                    if data.get("ok") and isinstance(data.get("gpus"), dict):
                        ior_gpus = data["gpus"]
                except Exception:
                    pass

        ior_util_by_key: Dict[str, float] = {}
        ior_vram_by_key: Dict[str, float] = {}
        for key, gdata in ior_gpus.items():
            busy_ns = int(gdata.get("busy_ns", 0))
            total_ns = int(gdata.get("total_ns", 0))
            prev = self._prev_gpu_ioreport.get(key)
            self._prev_gpu_ioreport[key] = (busy_ns, total_ns)
            if prev is not None:
                d_busy = max(0, busy_ns - prev[0])
                d_total = max(0, total_ns - prev[1])
                if d_total > 0:
                    ior_util_by_key[key] = min(100.0, (d_busy / d_total) * 100.0)
                else:
                    ior_util_by_key[key] = min(100.0, (d_busy / (dt * 1e9)) * 100.0)
            else:
                ior_util_by_key[key] = 0.0

            vid_b = int(gdata.get("in_use_vid_bytes", 0))
            sys_b = int(gdata.get("in_use_sys_bytes", 0))
            mtl_b = int(gdata.get("mtl_allocated_bytes", 0))
            used_bytes = max(vid_b + sys_b, mtl_b + vid_b)
            ior_vram_by_key[key] = round(used_bytes / (1024 * 1024), 1)

        # 2. Read IOAccelerator context/surface/texture counters via ioreg and merge duplicate entries
        merged_gpus: Dict[str, Dict[str, Any]] = {}
        try:
            res = subprocess.run(
                ["/usr/sbin/ioreg", "-r", "-d", "1", "-w", "0", "-c", "IOAccelerator", "-a"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
            )
            entries = plistlib.loads(res.stdout) if res.stdout else []
        except Exception:
            entries = []

        for dev in entries:
            io_class = str(dev.get("IOClass", "GPU"))
            ps = dev.get("PerformanceStatistics", {}) or {}

            if "Intel" in io_class:
                model = "Intel HD Graphics 630"
                gpu_type = "Integrated"
                vram_total_mb = int(dev.get("VRAM,totalMB") or 1536)
                ior_key = "intel"
            elif "AMD" in io_class or "Radeon" in io_class:
                model = "AMD Radeon Pro 560"
                gpu_type = "Discrete"
                vram_total_mb = int(dev.get("VRAM,totalMB") or 4096)
                ior_key = "amd"
            else:
                model = str(dev.get("model") or io_class)
                gpu_type = "Accelerator"
                vram_total_mb = int(dev.get("VRAM,totalMB") or 1024)
                ior_key = "other"

            # Calculate utilization % from IOReport delta, Device Utilization %, or wait counters
            dev_util = ps.get("Device Utilization %")
            if dev_util is not None:
                ps_util_pct = float(dev_util)
            else:
                busy_ns = (
                    int(ps.get("hardwareWaitTime", 0))
                    + int(ps.get("finishAll2DWaitTime", 0))
                    + int(ps.get("finishGLWaitTime", 0))
                    + int(ps.get("finishCLWaitTime", 0))
                    + int(ps.get("finishVideoWaitTime", 0))
                )
                ps_util_pct = min(100.0, (busy_ns / (dt * 1e9)) * 100.0)

            util_pct = max(ps_util_pct, ior_util_by_key.get(ior_key, 0.0))

            in_use_vid = int(ps.get("inUseVidMemoryBytes", 0))
            in_use_sys = int(ps.get("inUseSysMemoryBytes", 0))
            ps_vram_mb = round((in_use_vid + in_use_sys) / (1024 * 1024), 1)
            vram_used_mb = max(ps_vram_mb, ior_vram_by_key.get(ior_key, 0.0))
            vram_pct = round(min(100.0, (vram_used_mb / max(1, vram_total_mb)) * 100.0), 1)

            surfaces = int(ps.get("surfaceCount", 0))
            textures = int(ps.get("textureCount", 0))
            ctx_2d = int(ps.get("context2DCount", 0))
            ctx_gl = int(ps.get("contextGLCount", 0))
            ctx_cl = int(ps.get("contextCLCount", 0))
            ctx_video = int(ps.get("contextVideoCount", 0))

            if model not in merged_gpus:
                merged_gpus[model] = {
                    "model": model,
                    "type": gpu_type,
                    "io_class": io_class,
                    "utilization_pct": round(util_pct, 1),
                    "vram_used_mb": vram_used_mb,
                    "vram_total_mb": vram_total_mb,
                    "vram_pct": vram_pct,
                    "surfaces": surfaces,
                    "textures": textures,
                    "ctx_2d": ctx_2d,
                    "ctx_gl": ctx_gl,
                    "ctx_cl": ctx_cl,
                    "ctx_video": ctx_video,
                }
            else:
                cur = merged_gpus[model]
                cur["utilization_pct"] = round(max(cur["utilization_pct"], util_pct), 1)
                cur["vram_used_mb"] = round(max(cur["vram_used_mb"], vram_used_mb), 1)
                cur["vram_pct"] = round(min(100.0, (cur["vram_used_mb"] / max(1, vram_total_mb)) * 100.0), 1)
                cur["surfaces"] = max(cur["surfaces"], surfaces)
                cur["textures"] = max(cur["textures"], textures)
                cur["ctx_2d"] = max(cur["ctx_2d"], ctx_2d)
                cur["ctx_gl"] = max(cur["ctx_gl"], ctx_gl)
                cur["ctx_cl"] = max(cur["ctx_cl"], ctx_cl)
                cur["ctx_video"] = max(cur["ctx_video"], ctx_video)

        gpus = list(merged_gpus.values())
        max_gpu_pct = round(max((g["utilization_pct"] for g in gpus), default=0.0), 1)
        total_used_mb = round(sum(g["vram_used_mb"] for g in gpus), 1)
        total_vram_mb = sum(g["vram_total_mb"] for g in gpus)

        res_info = {
            "gpu_pct": max_gpu_pct,
            "gpu_vram_used_mb": total_used_mb,
            "gpu_vram_total_mb": total_vram_mb,
            "gpus": gpus,
        }
        self._last_gpu_info = res_info
        return res_info

    @staticmethod
    def _read_net_bytes() -> Tuple[int, int]:
        out = run_cmd(["/usr/sbin/netstat", "-ib"])
        rx_total, tx_total = 0, 0
        seen_ifaces = set()
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 10 and parts[0].startswith("en"):
                iface = parts[0]
                if iface in seen_ifaces:
                    continue
                # On macOS netstat -ib, Ibytes is col -4 or col 6 depending on Address presence
                try:
                    ibytes = int(parts[6])
                    obytes = int(parts[9])
                    rx_total += ibytes
                    tx_total += obytes
                    seen_ifaces.add(iface)
                except ValueError:
                    continue
        return rx_total, tx_total

    def get_top_processes(self, limit: int = 20) -> Tuple[List[Dict[str, Any]], float]:
        """Return top processes sorted by CPU usage and total normalized CPU percentage."""
        out = run_cmd(["/bin/ps", "-Aceo", "pid,ppid,user,%cpu,%mem,etime,comm", "-r"])
        procs: List[Dict[str, Any]] = []
        raw_cpu_sum = 0.0

        for line in out.splitlines()[1:]:
            parts = line.strip().split(None, 6)
            if len(parts) < 7:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                user = parts[2]
                cpu = float(parts[3])
                mem = float(parts[4])
                etime = parts[5]
                comm = parts[6]
            except ValueError:
                continue

            raw_cpu_sum += cpu
            if len(procs) < limit:
                procs.append(
                    {
                        "pid": pid,
                        "ppid": ppid,
                        "user": user,
                        "cpu": cpu,
                        "mem": mem,
                        "etime": etime,
                        "command": comm,
                        "suspicious": comm.lower() in SUSPICIOUS_PROC_NAMES
                        or any(comm.startswith(p) for p in SUSPICIOUS_PATHS),
                    }
                )

        normalized_cpu = round(min(100.0, raw_cpu_sum / max(1, self.ncpu)), 1)
        return procs, normalized_cpu

    def get_network_connections(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect listening TCP ports and established outbound/inbound connections."""
        listen_out = run_cmd(["/usr/sbin/lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"])
        est_out = run_cmd(["/usr/sbin/lsof", "-iTCP", "-sTCP:ESTABLISHED", "-P", "-n"])

        listening: List[Dict[str, Any]] = []
        seen_listen = set()
        for line in listen_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            cmd, pid, user, _, ip_type = parts[0], parts[1], parts[2], parts[3], parts[4]
            name = parts[8]
            host, _, port = name.rpartition(":")
            key = (cmd, pid, host, port)
            if key in seen_listen:
                continue
            seen_listen.add(key)
            exposed = host in ("*", "0.0.0.0", "[::]")
            sig = f"{cmd}:{port}"
            is_self = (
                (int(pid) == os.getpid() if pid.isdigit() else False)
                or port in ("8765", "8080")
                or cmd.startswith("cloudflar")
                or cmd.startswith("llama")
            )
            known = (
                is_self
                or not self.baseline["allowed_listen_ports"]
                or sig in self.baseline["allowed_listen_ports"]
            )
            listening.append(
                {
                    "command": cmd,
                    "pid": int(pid) if pid.isdigit() else 0,
                    "user": user,
                    "proto": ip_type,
                    "bind_addr": host,
                    "port": port,
                    "exposed": exposed,
                    "trusted": known,
                }
            )

        established: List[Dict[str, Any]] = []
        seen_est = set()
        for line in est_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            cmd, pid, user, _, ip_type = parts[0], parts[1], parts[2], parts[3], parts[4]
            name = parts[8]
            if "->" not in name:
                continue
            local, remote = name.split("->", 1)
            r_host, _, r_port = remote.rpartition(":")
            key = (cmd, pid, local, remote)
            if key in seen_est:
                continue
            seen_est.add(key)
            established.append(
                {
                    "command": cmd,
                    "pid": int(pid) if pid.isdigit() else 0,
                    "user": user,
                    "proto": ip_type,
                    "local": local,
                    "remote": remote,
                    "remote_host": r_host,
                    "remote_port": r_port,
                }
            )

        return {"listening": listening, "established": established}

    def get_sessions_and_logins(self) -> Dict[str, Any]:
        """Collect active user sessions (`who`) and recent login history (`last`)."""
        who_out = run_cmd(["/usr/bin/who"])
        active_sessions: List[Dict[str, Any]] = []
        for line in who_out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                user = parts[0]
                tty = parts[1]
                ts_str = " ".join(parts[2:5])
                host = parts[5].strip("()") if len(parts) > 5 else "local"
                is_remote = host != "local" and not host.startswith(":")
                active_sessions.append(
                    {
                        "user": user,
                        "tty": tty,
                        "login_time": ts_str,
                        "source": host,
                        "is_remote": is_remote,
                    }
                )

        last_out = run_cmd(["/usr/bin/last", "-15"])
        recent_logins: List[Dict[str, str]] = []
        for line in last_out.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("wtmp begins"):
                continue
            parts = line_s.split(None, 2)
            if len(parts) >= 3:
                recent_logins.append(
                    {
                        "user": parts[0],
                        "tty": parts[1],
                        "details": parts[2],
                    }
                )

        return {
            "active_sessions": active_sessions,
            "recent_logins": recent_logins,
            "auth_events": self._cached_auth_events,
        }

    def get_persistence_state(self) -> Dict[str, Any]:
        """Check macOS LaunchAgents, LaunchDaemons, and SSH authorized_keys for tampering."""
        dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        items: List[Dict[str, Any]] = []
        known_map = self.baseline.get("launch_agents", {})

        for d in dirs:
            if not d.exists() or not d.is_dir():
                continue
            try:
                for p in sorted(d.glob("*.plist")):
                    try:
                        stat = p.stat()
                        digest = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                        path_str = str(p)
                        status = "trusted"
                        if known_map:
                            if path_str not in known_map:
                                status = "new"
                            elif known_map[path_str] != digest:
                                status = "modified"
                        items.append(
                            {
                                "name": p.name,
                                "scope": d.name,
                                "path": path_str,
                                "mtime": datetime.fromtimestamp(stat.st_mtime).strftime(
                                    "%Y-%m-%d %H:%M"
                                ),
                                "sha256": digest,
                                "status": status,
                            }
                        )
                    except Exception:
                        continue
            except Exception:
                continue

        auth_keys_path = Path.home() / ".ssh" / "authorized_keys"
        auth_keys_hash = None
        auth_keys_count = 0
        if auth_keys_path.exists():
            try:
                raw = auth_keys_path.read_bytes()
                auth_keys_hash = hashlib.sha256(raw).hexdigest()[:16]
                auth_keys_count = sum(
                    1
                    for ln in raw.decode("utf-8", errors="ignore").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                )
            except Exception:
                pass

        return {
            "items": items,
            "authorized_keys_sha256": auth_keys_hash,
            "authorized_keys_count": auth_keys_count,
        }

    def run_deep_auth_scan(self) -> List[Dict[str, Any]]:
        """Query macOS unified logs for recent sudo, sshd, screensharingd, or failed auth events."""
        with self._deep_scan_lock:
            self._last_deep_scan_ts = time.time()
            predicate = (
                'process == "sudo" OR process == "sshd" OR process == "screensharingd" '
                'OR (process == "loginwindow" AND eventMessage CONTAINS[c] "auth")'
            )
            out = run_cmd(
                [
                    "/usr/bin/log",
                    "show",
                    "--predicate",
                    predicate,
                    "--last",
                    "10m",
                    "--style",
                    "compact",
                ],
                timeout=12.0,
            )
            events: List[Dict[str, Any]] = []
            for line in out.splitlines()[1:]:
                if "Timestamp" in line or not line.strip():
                    continue
                low = line.lower()
                severity = "INFO"
                if any(w in low for w in ("fail", "invalid", "denied", "incorrect", "error")):
                    severity = "WARNING"
                elif "sudo" in low and "command=" in low:
                    severity = "INFO"
                events.append(
                    {
                        "raw": line.strip()[:220],
                        "severity": severity,
                    }
                )
                if severity == "WARNING":
                    self.storage.add_alert(
                        severity="WARNING",
                        category="AUTH",
                        title="Suspicious Authentication / Privilege Event",
                        details=line.strip()[:180],
                        fingerprint=f"auth:{hashlib.md5(line.strip()[:80].encode()).hexdigest()}",
                    )
            self._cached_auth_events = events[-25:]
            return self._cached_auth_events

    def evaluate_anomalies(
        self,
        resources: Dict[str, Any],
        procs: List[Dict[str, Any]],
        network: Dict[str, List[Dict[str, Any]]],
        sessions: Dict[str, Any],
        persistence: Dict[str, Any],
    ) -> None:
        """Evaluate collected telemetry against unauthorized usage rules and emit alerts."""
        # 1. Check active user sessions for unknown users or remote SSH sessions
        allowed_users = set(self.baseline.get("allowed_users", []))
        for sess in sessions["active_sessions"]:
            if sess["is_remote"]:
                self.storage.add_alert(
                    severity="CRITICAL",
                    category="AUTH",
                    title=f"Remote Login Session Detected ({sess['user']})",
                    details=f"User '{sess['user']}' logged in on {sess['tty']} from {sess['source']}",
                    fingerprint=f"remote_sess:{sess['user']}:{sess['tty']}:{sess['source']}",
                )
            elif allowed_users and sess["user"] not in allowed_users:
                self.storage.add_alert(
                    severity="WARNING",
                    category="AUTH",
                    title=f"Unexpected Active User ({sess['user']})",
                    details=f"User '{sess['user']}' active on {sess['tty']} since {sess['login_time']}",
                    fingerprint=f"unexp_user:{sess['user']}:{sess['tty']}",
                )

        # 2. Check for exposed/untrusted listening ports
        for lp in network["listening"]:
            if not lp["trusted"]:
                sev = "CRITICAL" if lp["exposed"] else "WARNING"
                self.storage.add_alert(
                    severity=sev,
                    category="NETWORK",
                    title=f"New Listening Port: {lp['command']} on :{lp['port']}",
                    details=f"PID {lp['pid']} ({lp['user']}) listening on {lp['bind_addr']}:{lp['port']}",
                    fingerprint=f"listen:{lp['command']}:{lp['port']}:{lp['bind_addr']}",
                )
            elif lp["exposed"]:
                # Even without a custom baseline, flag non-localhost ports for awareness
                self.storage.add_alert(
                    severity="INFO",
                    category="NETWORK",
                    title=f"Network-Exposed Service: {lp['command']} (:{lp['port']})",
                    details=f"Bound to {lp['bind_addr']}:{lp['port']} (PID {lp['pid']}, user {lp['user']})",
                    fingerprint=f"exposed:{lp['command']}:{lp['port']}",
                    cooldown_sec=3600,
                    notify_desktop=False,
                )

        # 3. Check for resource spikes or suspicious processes
        cpu_thresh = float(self.baseline.get("cpu_spike_threshold", 150.0))
        for p in procs:
            if p["suspicious"]:
                self.storage.add_alert(
                    severity="CRITICAL",
                    category="RESOURCE",
                    title=f"Suspicious Process Running: {p['command']}",
                    details=f"PID {p['pid']} (user {p['user']}) using {p['cpu']}% CPU",
                    fingerprint=f"susp_proc:{p['command']}:{p['pid']}",
                )
            elif p["cpu"] >= cpu_thresh and not p["command"].startswith("llama"):
                self.storage.add_alert(
                    severity="WARNING",
                    category="RESOURCE",
                    title=f"High CPU Spike: {p['command']} ({p['cpu']}%)",
                    details=f"PID {p['pid']} owned by '{p['user']}' running for {p['etime']}",
                    fingerprint=f"cpu_spike:{p['command']}",
                    cooldown_sec=300,
                )

        thermals = resources.get("thermals", {})
        if thermals.get("cpu_temp_c", 0.0) >= 90.0:
            self.storage.add_alert(
                severity="WARNING",
                category="THERMAL",
                title=f"High CPU Temperature ({thermals['cpu_temp_c']}°C)",
                details=f"Fans: {thermals.get('fan0_rpm', 0)} / {thermals.get('fan1_rpm', 0)} RPM",
                fingerprint="high_cpu_temp",
                cooldown_sec=300,
            )
        if thermals.get("gpu_temp_c", 0.0) >= 90.0:
            self.storage.add_alert(
                severity="WARNING",
                category="THERMAL",
                title=f"High GPU Temperature ({thermals['gpu_temp_c']}°C)",
                details=f"Fans: {thermals.get('fan0_rpm', 0)} / {thermals.get('fan1_rpm', 0)} RPM",
                fingerprint="high_gpu_temp",
                cooldown_sec=300,
            )

        if resources["mem_pct"] >= 92.0:
            self.storage.add_alert(
                severity="WARNING",
                category="RESOURCE",
                title=f"High Memory Pressure ({resources['mem_pct']}%)",
                details=f"{resources['mem_used_gb']} GB / {resources['mem_total_gb']} GB in use",
                fingerprint="high_mem_pressure",
                cooldown_sec=600,
            )

        for gpu in resources.get("gpus", []):
            if gpu["utilization_pct"] >= 85.0:
                self.storage.add_alert(
                    severity="WARNING",
                    category="RESOURCE",
                    title=f"High GPU Usage: {gpu['model']} ({gpu['utilization_pct']}%)",
                    details=f"VRAM in use: {gpu['vram_used_mb']} MB / {gpu['vram_total_mb']} MB",
                    fingerprint=f"gpu_spike:{gpu['model']}",
                    cooldown_sec=300,
                )
            if gpu["ctx_cl"] > 0:
                self.storage.add_alert(
                    severity="WARNING",
                    category="RESOURCE",
                    title=f"Active OpenCL Compute Context on {gpu['model']}",
                    details=f"{gpu['ctx_cl']} OpenCL compute context(s) active (check for GPU compute/mining)",
                    fingerprint=f"gpu_opencl:{gpu['model']}",
                    cooldown_sec=600,
                )

        # 4. Check persistence modifications (LaunchAgents / Daemons / SSH keys)
        for item in persistence["items"]:
            if item["status"] in ("new", "modified"):
                self.storage.add_alert(
                    severity="CRITICAL",
                    category="PERSISTENCE",
                    title=f"Persistence {item['status'].upper()}: {item['name']}",
                    details=f"{item['path']} (modified {item['mtime']})",
                    fingerprint=f"persist:{item['path']}:{item['sha256']}",
                )

        base_ssh = self.baseline.get("authorized_keys_sha256")
        curr_ssh = persistence.get("authorized_keys_sha256")
        if self.baseline.get("created_at") and base_ssh != curr_ssh:
            self.storage.add_alert(
                severity="CRITICAL",
                category="PERSISTENCE",
                title="SSH authorized_keys Modified",
                details="~/.ssh/authorized_keys hash changed from saved baseline",
                fingerprint=f"ssh_keys:{curr_ssh}",
            )

    def collect_snapshot(self, record_metrics: bool = True) -> Dict[str, Any]:
        """Collect a complete system & security snapshot."""
        resources = self.get_system_resources()
        procs, norm_cpu = self.get_top_processes(limit=15)
        resources["cpu_pct"] = norm_cpu

        network = self.get_network_connections()
        sessions = self.get_sessions_and_logins()
        persistence = self.get_persistence_state()
        llm = self.get_llm_stats(procs)

        # Trigger background unified log scan every 90 seconds
        if time.time() - self._last_deep_scan_ts > 90.0:
            threading.Thread(target=self.run_deep_auth_scan, daemon=True).start()

        self.evaluate_anomalies(resources, procs, network, sessions, persistence)

        thermals = resources.get("thermals", {})
        if record_metrics:
            self.storage.insert_metric(
                {
                    "cpu_pct": resources["cpu_pct"],
                    "mem_pct": resources["mem_pct"],
                    "gpu_pct": resources.get("gpu_pct", 0.0),
                    "gpu_vram_mb": resources.get("gpu_vram_used_mb", 0.0),
                    "cpu_temp_c": thermals.get("cpu_temp_c", 0.0),
                    "gpu_temp_c": thermals.get("gpu_temp_c", 0.0),
                    "load_1m": resources["load_1m"],
                    "net_rx_kbps": resources["net_rx_kbps"],
                    "net_tx_kbps": resources["net_tx_kbps"],
                    "established_conns": len(network["established"]),
                    "listening_ports": len(network["listening"]),
                    "active_users": len(sessions["active_sessions"]),
                }
            )

        alerts = self.storage.get_alerts(limit=40)
        history = self.storage.get_recent_metrics(limit=60)

        # Compute overall security posture
        crit_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        warn_count = sum(1 for a in alerts if a["severity"] == "WARNING")
        status = "SECURE"
        if crit_count > 0:
            status = "CRITICAL ALERT"
        elif warn_count > 0:
            status = "WARNING"

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "summary": {
                "critical_alerts": crit_count,
                "warning_alerts": warn_count,
                "active_sessions": len(sessions["active_sessions"]),
                "listening_ports": len(network["listening"]),
                "exposed_ports": sum(1 for p in network["listening"] if p["exposed"]),
                "established_conns": len(network["established"]),
                "persistence_items": len(persistence["items"]),
                "baseline_configured": bool(self.baseline.get("created_at")),
                "baseline_created_at": self.baseline.get("created_at"),
            },
            "resources": resources,
            "llm": llm,
            "processes": procs,
            "network": network,
            "sessions": sessions,
            "persistence": persistence,
            "alerts": alerts,
            "history": history,
        }
