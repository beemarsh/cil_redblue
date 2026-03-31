#!/usr/bin/env python3
"""
RedBlue — Operator Dashboard Server
Runs on each team machine. Provides a web UI for manual attack control and
real-time event monitoring (relayed from the team's Raspberry Pi).

Routes:
  GET  /                  — operator dashboard UI
  GET  /api/config        — team/computer info + targets
  GET  /api/history       — recent events involving this node
  POST /api/attack        — trigger an attack
  GET  /api/attack-status — current attack status
  GET  /stream            — SSE endpoint (relays Pi events + local events)

Run:
  python3 computer_server.py --team blue  --computer c1
  python3 computer_server.py --team red   --computer c2 --port 8080
"""

import argparse
import json
import os
import queue
import random
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime

import requests
import yaml
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__)

# ── attack type registry (mirrors server.py) ─────────────────────────────────

ATTACK_TYPES = {
    "port_scan":   {"label": "Port Scan",           "severity": "low",      "color": "#00ff41", "nmap": True},
    "syn_flood":   {"label": "SYN Flood",           "severity": "high",     "color": "#ff6600", "nmap": False},
    "brute_force": {"label": "Brute Force",         "severity": "medium",   "color": "#f9e2af", "nmap": False},
    "arp_poison":  {"label": "ARP Poisoning",       "severity": "high",     "color": "#ff6600", "nmap": False},
    "ping_sweep":  {"label": "Ping Sweep",          "severity": "low",      "color": "#00ff41", "nmap": True},
    "dns_spoof":   {"label": "DNS Spoofing",        "severity": "medium",   "color": "#f9e2af", "nmap": False},
    "mitm":        {"label": "Man-in-the-Middle",   "severity": "critical", "color": "#ff4444", "nmap": False},
    "os_detect":   {"label": "OS Detection",        "severity": "low",      "color": "#00ff41", "nmap": True},
    "vuln_scan":   {"label": "Vulnerability Scan",  "severity": "medium",   "color": "#f9e2af", "nmap": True},
}

# Simulated ports for non-nmap attacks
_SIM_PORTS = {
    "syn_flood":   ["80/tcp http", "443/tcp https"],
    "brute_force": ["22/tcp ssh", "21/tcp ftp", "3389/tcp rdp"],
    "arp_poison":  [],
    "dns_spoof":   ["53/udp dns"],
    "mitm":        ["80/tcp http", "8080/tcp http-alt"],
}

# ── global state ──────────────────────────────────────────────────────────────

_config:      dict = {}
_my_team:     str  = ""
_my_computer: str  = ""
_pi_base:     str  = ""

_subscribers: list[queue.Queue] = []
_lock = threading.Lock()

_local_history: deque = deque(maxlen=100)

# Latest node snapshot from Pi (for SSE init payload)
_pi_nodes:     dict = {}
_pi_connected: bool = False

# Active attack tracking
_active_attack: dict | None = None
_attack_lock = threading.Lock()

# ── config ────────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        if cfg:
            return cfg
    except Exception as e:
        print(f"[WARN] Could not load config {path!r}: {e}")
    return {}

# ── broadcast ─────────────────────────────────────────────────────────────────

def broadcast(payload: str) -> None:
    with _lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)

# ── Pi SSE relay ───────────────────────────────────────────────────────────────

def _relay_loop() -> None:
    global _pi_connected, _pi_nodes
    url     = f"{_pi_base}/stream"
    backoff = 2.0

    while True:
        try:
            with requests.get(url, stream=True, timeout=(5, None)) as resp:
                _pi_connected = True
                backoff = 2.0
                broadcast(json.dumps({"type": "pi_status", "connected": True}))
                print(f"[RELAY] Connected to Pi at {url}")

                for raw in resp.iter_lines():
                    if not raw:
                        continue
                    line = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    try:
                        msg = json.loads(payload)
                    except Exception:
                        continue

                    # Cache node snapshot
                    if msg.get("type") == "nodes":
                        _pi_nodes = msg.get("data", _pi_nodes)
                    elif msg.get("type") == "init":
                        _pi_nodes = msg.get("nodes", _pi_nodes)

                    # Track events involving our node for local history
                    if msg.get("type") == "event":
                        ev = msg.get("data", {})
                        my_key  = f"{_my_team}.{_my_computer}"
                        tgt_key = f"{ev.get('target_team','')}.{ev.get('target_computer','')}"
                        atk_key = f"{ev.get('attacker_team','')}.{ev.get('attacker_computer','')}"
                        if tgt_key == my_key or atk_key == my_key:
                            _local_history.append(ev)

                    # Forward everything to browser subscribers
                    broadcast(json.dumps({"type": "pi", "data": msg}))

        except Exception as e:
            _pi_connected = False
            broadcast(json.dumps({"type": "pi_status", "connected": False}))
            print(f"[RELAY] Pi disconnected ({e}). Retry in {backoff:.0f}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


def start_relay() -> None:
    t = threading.Thread(target=_relay_loop, daemon=True, name="pi-relay")
    t.start()

# ── nmap execution ─────────────────────────────────────────────────────────────

def _run_nmap(ip: str, ports: str, attack_type: str) -> list[str]:
    try:
        if attack_type == "ping_sweep":
            cmd = ["nmap", "-sn", "--host-timeout", "15s", ip]
        elif attack_type == "os_detect":
            cmd = ["nmap", "-p", ports, "-sV", "--host-timeout", "20s", ip]
        elif attack_type == "vuln_scan":
            cmd = ["nmap", "-p", ports, "-sV", "--host-timeout", "30s", ip]
        else:  # port_scan
            cmd = ["nmap", "-p", ports, "--open", "-T4", "--host-timeout", "20s", ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if "/tcp" in line or "/udp" in line or "open" in line.lower()
        ][:20]
    except FileNotFoundError:
        return ["ERROR: nmap not found — run: sudo apt install nmap"]
    except subprocess.TimeoutExpired:
        return ["scan timed out"]
    except Exception as e:
        return [f"error: {e}"]


def _simulate_ports(attack_type: str) -> list[str]:
    pool = _SIM_PORTS.get(attack_type, [])
    if not pool:
        return []
    return random.sample(pool, min(len(pool), random.randint(1, len(pool))))

# ── attack execution ───────────────────────────────────────────────────────────

def _do_attack(attack_id: str, attack_type: str, tgt_team: str, tgt_comp: str, tgt_ip: str) -> None:
    global _active_attack

    ainfo      = ATTACK_TYPES.get(attack_type, ATTACK_TYPES["port_scan"])
    scan_ports = _config.get("settings", {}).get("scan_ports", "1-1024")

    broadcast(json.dumps({
        "type": "attack_start",
        "attack_id": attack_id,
        "attack_type": attack_type,
        "target_team": tgt_team,
        "target_computer": tgt_comp,
        "target_ip": tgt_ip,
    }))

    try:
        if ainfo["nmap"]:
            open_ports = _run_nmap(tgt_ip, scan_ports, attack_type)
        else:
            time.sleep(random.uniform(0.5, 2.0))   # simulate work
            open_ports = _simulate_ports(attack_type)

        entry = {
            "timestamp":         datetime.now().isoformat(),
            "attacker_team":     _my_team,
            "attacker_computer": _my_computer,
            "target_team":       tgt_team,
            "target_computer":   tgt_comp,
            "target_ip":         tgt_ip,
            "attack_type":       attack_type,
            "open_ports":        open_ports,
        }

        try:
            requests.post(f"{_pi_base}/log", json=entry, timeout=5)
        except Exception as e:
            print(f"[WARN] Could not reach Pi: {e}")

        _local_history.append(entry)
        broadcast(json.dumps({"type": "attack_result", "attack_id": attack_id, "entry": entry}))

    except Exception as e:
        broadcast(json.dumps({"type": "attack_error", "attack_id": attack_id, "error": str(e)}))
    finally:
        with _attack_lock:
            _active_attack = None

# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("computer.html")


@app.route("/api/config")
def api_config():
    enemy = "red" if _my_team == "blue" else "blue"
    my_ip = (_config.get("teams", {})
                    .get(_my_team, {})
                    .get("computers", {})
                    .get(_my_computer, "unknown"))
    return jsonify({
        "team":         _my_team,
        "computer":     _my_computer,
        "my_ip":        my_ip,
        "pi_base":      _pi_base,
        "pi_connected": _pi_connected,
        "targets":      (_config.get("teams", {})
                                .get(enemy, {})
                                .get("computers", {})),
        "teammates":    {k: v for k, v in
                         (_config.get("teams", {})
                                 .get(_my_team, {})
                                 .get("computers", {})).items()
                         if k != _my_computer},
        "enemy_team":   enemy,
        "attack_types": {k: {ek: ev for ek, ev in v.items() if ek != "nmap"}
                         for k, v in ATTACK_TYPES.items()},
    })


@app.route("/api/history")
def api_history():
    return jsonify(list(_local_history))


@app.route("/api/attack-status")
def api_attack_status():
    with _attack_lock:
        return jsonify(_active_attack or {"running": False})


@app.route("/api/attack", methods=["POST"])
def api_attack():
    global _active_attack
    with _attack_lock:
        if _active_attack:
            return jsonify({"error": "attack already in progress"}), 409

    data        = request.get_json(silent=True) or {}
    attack_type = data.get("attack_type", "port_scan")
    tgt_team    = data.get("target_team", "")
    tgt_comp    = data.get("target_computer", "")

    if attack_type not in ATTACK_TYPES:
        return jsonify({"error": f"unknown attack_type '{attack_type}'"}), 400
    if not tgt_team or not tgt_comp:
        return jsonify({"error": "target_team and target_computer required"}), 400

    tgt_ip = (_config.get("teams", {})
                     .get(tgt_team, {})
                     .get("computers", {})
                     .get(tgt_comp, "unknown"))

    attack_id = uuid.uuid4().hex[:8]
    with _attack_lock:
        _active_attack = {
            "running":  True,
            "attack_id": attack_id,
            "attack_type": attack_type,
            "target": f"{tgt_team}.{tgt_comp}",
        }

    t = threading.Thread(
        target=_do_attack,
        args=(attack_id, attack_type, tgt_team, tgt_comp, tgt_ip),
        daemon=True,
        name=f"attack-{attack_id}",
    )
    t.start()
    return jsonify({"status": "started", "attack_id": attack_id})


@app.route("/stream")
def stream():
    def generate():
        q: queue.Queue = queue.Queue(maxsize=50)
        with _lock:
            _subscribers.append(q)

        init_payload = json.dumps({
            "type":         "init",
            "team":         _my_team,
            "computer":     _my_computer,
            "attack_types": {k: {ek: ev for ek, ev in v.items() if ek != "nmap"}
                             for k, v in ATTACK_TYPES.items()},
            "nodes":        _pi_nodes,
            "pi_connected": _pi_connected,
        })
        yield f"data: {init_payload}\n\n"

        try:
            while True:
                try:
                    data = q.get(timeout=25)
                    yield f"data: {data}\n\n"
                except queue.Empty:
                    yield 'data: {"type":"ping"}\n\n'
        finally:
            with _lock:
                if q in _subscribers:
                    _subscribers.remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

# ── entry point ────────────────────────────────────────────────────────────────

def main():
    global _config, _my_team, _my_computer, _pi_base

    parser = argparse.ArgumentParser(description="RedBlue — Operator Dashboard")
    parser.add_argument("--team",     required=True, choices=["blue", "red"])
    parser.add_argument("--computer", required=True, help="e.g. c1")
    parser.add_argument("--config",   default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"))
    parser.add_argument("--port",     type=int, default=8080)
    args = parser.parse_args()

    _my_team     = args.team.lower().strip()
    _my_computer = args.computer.lower().strip()
    _config      = load_config(args.config)

    pi_ip   = _config.get("teams", {}).get(_my_team, {}).get("raspberry_pi", "localhost")
    pi_port = _config.get("settings", {}).get("log_port", 5000)
    _pi_base = f"http://{pi_ip}:{pi_port}"

    print(f"[BOOT] RedBlue Operator Dashboard")
    print(f"[BOOT] Team     : {_my_team}")
    print(f"[BOOT] Computer : {_my_computer}")
    print(f"[BOOT] Pi       : {_pi_base}")
    print(f"[BOOT] Listening on 0.0.0.0:{args.port}")
    print(f"[BOOT] Dashboard: http://localhost:{args.port}/")

    start_relay()
    app.run(host="0.0.0.0", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
