#!/usr/bin/env python3
"""
MacGuard CLI Security Audit & Unauthorized Usage Inspector
Run instant security checks, inspect alerts, or save a trusted baseline.
"""

import argparse
import json
from collector import MacSecurityCollector


def print_report(snap: dict) -> None:
    r = snap["resources"]
    s = snap["summary"]
    print("=" * 74)
    print(f" MacGuard Security Audit | {snap['timestamp']} | Status: [{snap['status']}]")
    print("=" * 74)
    print(
        f" CPU: {r['cpu_pct']}% ({r['ncpu']} cores, Load: {r['load_1m']:.2f} / {r['load_5m']:.2f} / {r['load_15m']:.2f})"
    )
    print(
        f" RAM: {r['mem_pct']}% ({r['mem_used_gb']} / {r['mem_total_gb']} GB) | Disk: {r['disk_pct']}% ({r['disk_used_gb']}/{r['disk_total_gb']} GB)"
    )
    gpu_summary = ", ".join(
        f"{g['model']}: {g['utilization_pct']}% ({g['vram_used_mb']}/{g['vram_total_mb']} MB VRAM)"
        for g in r.get("gpus", [])
    )
    print(f" GPU: {r.get('gpu_pct', 0.0)}% max | {gpu_summary}")
    th = r.get("thermals", {})
    print(
        f" Thermals: CPU {th.get('cpu_temp_c', 0)}°C | GPU {th.get('gpu_temp_c', 0)}°C | Mem {th.get('mem_temp_c', 0)}°C | Bat {th.get('battery_temp_c', 0)}°C | Fans: {th.get('fan0_rpm', 0)} / {th.get('fan1_rpm', 0)} RPM"
    )
    llm = snap.get("llm", {})
    print(
        f" Local LLM: {llm.get('model_name')} [{llm.get('state')}] | Speed: {llm.get('gen_tok_per_sec', 0)} tok/s | Tokens: {llm.get('prompt_tokens', 0)} in / {llm.get('completion_tokens', 0)} out"
    )
    print(
        f" Net: RX {r['net_rx_kbps']} KB/s, TX {r['net_tx_kbps']} KB/s | Established: {s['established_conns']} | Listening: {s['listening_ports']} ({s['exposed_ports']} exposed)"
    )
    print(
        f" Baseline: {'Active (' + str(s['baseline_created_at']) + ')' if s['baseline_configured'] else 'Not saved (run with --save-baseline)'}"
    )
    print("-" * 74)

    # Active Sessions
    print(f"\n[1] ACTIVE LOGIN SESSIONS ({len(snap['sessions']['active_sessions'])})")
    for sess in snap["sessions"]["active_sessions"]:
        tag = "REMOTE!" if sess["is_remote"] else "LOCAL"
        print(f"  - [{tag}] {sess['user']:<14} {sess['tty']:<10} {sess['login_time']} ({sess['source']})")

    # Listening Ports
    print(f"\n[2] LISTENING TCP PORTS ({len(snap['network']['listening'])})")
    for lp in snap["network"]["listening"][:15]:
        flag = "EXPOSED(*)" if lp["exposed"] else "LOCAL"
        trust = "TRUSTED" if lp["trusted"] else "UNTRUSTED!"
        print(
            f"  - {lp['command']:<16} PID {lp['pid']:<6} {lp['user']:<12} {lp['bind_addr']}:{lp['port']:<6} [{flag} | {trust}]"
        )

    # Top Processes
    print("\n[3] TOP PROCESSES BY CPU")
    for p in snap["processes"][:8]:
        warn = " [SUSPICIOUS!]" if p["suspicious"] else ""
        print(
            f"  - PID {p['pid']:<6} {p['user']:<14} CPU {p['cpu']:>5.1f}%  MEM {p['mem']:>4.1f}%  {p['command']}{warn}"
        )

    # Alerts
    alerts = snap["alerts"]
    print(f"\n[4] ACTIVE SECURITY & UNAUTHORIZED USAGE ALERTS ({len(alerts)})")
    if not alerts:
        print("  ✓ No active alerts.")
    else:
        for a in alerts[:12]:
            print(f"  ! [{a['severity']}] ({a['category']}) {a['title']} -> {a['details']}")
    print("=" * 74)


def main():
    parser = argparse.ArgumentParser(description="MacGuard CLI Security & Stats Auditor")
    parser.add_argument("--save-baseline", action="store_true", help="Save current system state as trusted baseline")
    parser.add_argument("--clear-alerts", action="store_true", help="Acknowledge and clear active alerts")
    parser.add_argument("--deep-scan", action="store_true", help="Include unified log scan for sudo/sshd/auth")
    parser.add_argument("--json", action="store_true", help="Output full snapshot as JSON")
    args = parser.parse_args()

    collector = MacSecurityCollector()

    if args.save_baseline:
        base = collector.save_current_as_baseline()
        print(
            f"✓ Saved trusted baseline at {base['created_at']} "
            f"({len(base['allowed_listen_ports'])} ports, {len(base['launch_agents'])} persistence items)."
        )

    if args.clear_alerts:
        count = collector.storage.acknowledge_all_alerts()
        print(f"✓ Cleared {count} active alert(s).")

    if args.deep_scan:
        collector.run_deep_auth_scan()

    snap = collector.collect_snapshot(record_metrics=True)
    if args.json:
        print(json.dumps(snap, indent=2))
    else:
        print_report(snap)


if __name__ == "__main__":
    main()
