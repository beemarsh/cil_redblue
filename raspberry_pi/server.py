#!/usr/bin/env python3
"""
RedBlue Security Ops — Log Server for Raspberry Pi

Routes:
  GET  /                    — visual dashboard
  POST /log                 — receive attack event JSON
  GET  /api/attack-types    — return ATTACK_TYPES dict
  GET  /api/nodes           — return node_states dict
  GET  /api/config          — return loaded config
  GET  /api/history         — return log_history (deque maxlen 200)
  POST /api/command         — manually trigger an attack event
  POST /api/simulate        — toggle simulation {"action": "start"|"stop"|"toggle"}
  GET  /api/simulate/status — {"running": bool}
  GET  /stream              — SSE endpoint

Run:
  python3 server.py
  python3 server.py --port 5000 --config ../config.yaml

Install dependencies:
  pip install flask pyyaml
"""

import argparse
import json
import os
import queue
import random
import threading
import time
from collections import deque
from datetime import datetime

import yaml
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__)

# ── attack type registry ────────────────────────────────────────────────────
# Add a new attack type by appending one dict entry here.

ATTACK_TYPES = {
    "port_scan": {
        "label": "Port Scan",
        "severity": "low",
        "color": "#00ff41",
    },
    "syn_flood": {
        "label": "SYN Flood",
        "severity": "high",
        "color": "#ff6600",
    },
    "brute_force": {
        "label": "Brute Force",
        "severity": "medium",
        "color": "#f9e2af",
    },
    "arp_poison": {
        "label": "ARP Poisoning",
        "severity": "high",
        "color": "#ff6600",
    },
    "ping_sweep": {
        "label": "Ping Sweep",
        "severity": "low",
        "color": "#00ff41",
    },
    "dns_spoof": {
        "label": "DNS Spoofing",
        "severity": "medium",
        "color": "#f9e2af",
    },
    "mitm": {
        "label": "Man-in-the-Middle",
        "severity": "critical",
        "color": "#ff4444",
    },
    "os_detect": {
        "label": "OS Detection",
        "severity": "low",
        "color": "#00ff41",
    },
    "vuln_scan": {
        "label": "Vulnerability Scan",
        "severity": "medium",
        "color": "#f9e2af",
    },
}

# ── default config fallback ──────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "teams": {
        "blue": {
            "computers": {"c1": "192.168.1.11", "c2": "192.168.1.12"},
            "raspberry_pi": "192.168.1.10",
        },
        "red": {
            "computers": {"c1": "131.95.36.30", "c2": "131.95.36.22"},
            "raspberry_pi": "131.95.36.19",
        },
    },
    "settings": {
        "log_port": 5000,
        "scan_ports": "1-1024",
        "attack_interval": 60,
    },
}

# ── global state ─────────────────────────────────────────────────────────────

log_history: deque = deque(maxlen=200)
_subscribers: list[queue.Queue] = []
_lock = threading.Lock()
_config: dict = {}
node_states: dict = {}

# Simulation state
_sim_running = False
_sim_thread: threading.Thread | None = None

# ── config + node bootstrap ──────────────────────────────────────────────────

def load_config(path: str) -> dict:
    """Load YAML config file; fall back to DEFAULT_CONFIG on any error."""
    try:
        with open(path, "r") as fh:
            cfg = yaml.safe_load(fh)
        if cfg:
            return cfg
    except Exception as exc:
        print(f"[WARN] Could not load config {path!r}: {exc}. Using defaults.")
    return DEFAULT_CONFIG


def build_node_states(cfg: dict) -> dict:
    """Build node_states from config teams block."""
    states: dict = {}
    teams = cfg.get("teams", {})
    for team_name, team_data in teams.items():
        computers = team_data.get("computers", {})
        for comp_id, ip in computers.items():
            key = f"{team_name}.{comp_id}"
            states[key] = {
                "team": team_name,
                "computer": comp_id,
                "ip": ip,
                "status": "idle",       # idle | attacking | under_attack
                "last_event": None,
                "attack_count": 0,
                "attacker": None,
                "attack_type": None,
            }
    return states


# ── SSE broadcast ─────────────────────────────────────────────────────────────

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


def broadcast_nodes() -> None:
    """Push current node_states snapshot to all subscribers."""
    broadcast(json.dumps({"type": "nodes", "data": node_states}))


# ── event processing ──────────────────────────────────────────────────────────

def _reset_node_after(key: str, delay: float = 10.0) -> None:
    """Background thread: reset node status to idle after `delay` seconds."""
    def _run():
        time.sleep(delay)
        if key in node_states:
            node_states[key]["status"] = "idle"
            node_states[key]["attacker"] = None
            node_states[key]["attack_type"] = None
        broadcast_nodes()
    t = threading.Thread(target=_run, daemon=True)
    t.start()


def process_event(event: dict) -> dict:
    """
    Enrich event with attack metadata, update node_states,
    broadcast via SSE, and schedule idle reset.
    Returns the enriched event dict.
    """
    attack_type_key = event.get("attack_type", "port_scan")
    atype = ATTACK_TYPES.get(attack_type_key, ATTACK_TYPES["port_scan"])

    event["attack_label"] = atype["label"]
    event["severity"] = atype["severity"]
    event["color"] = atype["color"]
    event.setdefault("received_at", datetime.now().isoformat())
    event.setdefault("timestamp", event["received_at"])

    attacker_key = f"{event.get('attacker_team','?')}.{event.get('attacker_computer','?')}"
    target_key   = f"{event.get('target_team','?')}.{event.get('target_computer','?')}"

    # Update attacker node
    if attacker_key in node_states:
        node_states[attacker_key]["status"] = "attacking"
        node_states[attacker_key]["last_event"] = event["timestamp"]
        node_states[attacker_key]["attack_count"] += 1
        node_states[attacker_key]["attack_type"] = atype["label"]
        _reset_node_after(attacker_key, 10.0)

    # Update target node
    if target_key in node_states:
        node_states[target_key]["status"] = "under_attack"
        node_states[target_key]["last_event"] = event["timestamp"]
        node_states[target_key]["attacker"] = attacker_key
        node_states[target_key]["attack_type"] = atype["label"]
        _reset_node_after(target_key, 10.0)

    log_history.append(event)
    broadcast(json.dumps({"type": "event", "data": event}))
    broadcast_nodes()

    attacker = f"{event.get('attacker_team','?')}.{event.get('attacker_computer','?')}"
    target   = f"{event.get('target_team','?')}.{event.get('target_computer','?')} ({event.get('target_ip','?')})"
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {attacker} -> {target}  [{atype['label']}] [{atype['severity']}]")

    return event


# ── simulation ────────────────────────────────────────────────────────────────

# Ports commonly produced by relevant attack types
_PORT_MAP = {
    "port_scan":   ["22/tcp ssh", "80/tcp http", "443/tcp https", "3306/tcp mysql", "8080/tcp http-alt"],
    "syn_flood":   ["80/tcp http", "443/tcp https"],
    "brute_force": ["22/tcp ssh", "21/tcp ftp", "3389/tcp rdp"],
    "arp_poison":  [],
    "ping_sweep":  [],
    "dns_spoof":   ["53/udp dns"],
    "mitm":        ["80/tcp http", "443/tcp https", "8080/tcp http-alt"],
    "os_detect":   ["22/tcp ssh", "80/tcp http"],
    "vuln_scan":   ["21/tcp ftp", "22/tcp ssh", "23/tcp telnet", "80/tcp http", "443/tcp https",
                    "445/tcp smb", "3306/tcp mysql", "5432/tcp postgres"],
}


def _simulation_loop() -> None:
    global _sim_running
    attack_keys = list(ATTACK_TYPES.keys())

    # Gather teams
    teams_data: dict[str, list[tuple[str, str, str]]] = {}  # team -> [(comp, ip, key)]
    for key, ns in node_states.items():
        t = ns["team"]
        teams_data.setdefault(t, []).append((ns["computer"], ns["ip"], key))

    team_names = list(teams_data.keys())

    while _sim_running:
        wait = random.uniform(2, 7)
        time.sleep(wait)
        if not _sim_running:
            break

        if len(team_names) < 2:
            continue

        # Pick opposing teams
        atk_team = random.choice(team_names)
        tgt_candidates = [tn for tn in team_names if tn != atk_team]
        tgt_team = random.choice(tgt_candidates)

        atk_nodes = teams_data[atk_team]
        tgt_nodes = teams_data[tgt_team]
        if not atk_nodes or not tgt_nodes:
            continue

        atk_comp, _, _ = random.choice(atk_nodes)
        tgt_comp, tgt_ip, _ = random.choice(tgt_nodes)
        atype = random.choice(attack_keys)

        ports_pool = _PORT_MAP.get(atype, [])
        open_ports: list[str] = []
        if ports_pool:
            k = random.randint(1, min(4, len(ports_pool)))
            open_ports = random.sample(ports_pool, k)

        event = {
            "attacker_team": atk_team,
            "attacker_computer": atk_comp,
            "target_team": tgt_team,
            "target_computer": tgt_comp,
            "target_ip": tgt_ip,
            "attack_type": atype,
            "open_ports": open_ports,
            "timestamp": datetime.now().isoformat(),
            "source": "simulation",
        }
        process_event(event)


def start_simulation() -> None:
    global _sim_running, _sim_thread
    if _sim_running:
        return
    _sim_running = True
    _sim_thread = threading.Thread(target=_simulation_loop, daemon=True, name="sim-loop")
    _sim_thread.start()
    print("[SIM] Simulation started.")


def stop_simulation() -> None:
    global _sim_running
    _sim_running = False
    print("[SIM] Simulation stopped.")


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400
    process_event(data)
    return jsonify({"status": "ok"})


@app.route("/api/attack-types")
def api_attack_types():
    return jsonify(ATTACK_TYPES)


@app.route("/api/nodes")
def api_nodes():
    return jsonify(node_states)


@app.route("/api/config")
def api_config():
    return jsonify(_config)


@app.route("/api/history")
def api_history():
    return jsonify(list(log_history))


@app.route("/api/command", methods=["POST"])
def api_command():
    data = request.get_json(silent=True) or {}

    attack_type = data.get("attack_type", "port_scan")
    if attack_type not in ATTACK_TYPES:
        return jsonify({"error": f"unknown attack_type '{attack_type}'",
                        "valid": list(ATTACK_TYPES.keys())}), 400

    atk_team = data.get("attacker_team", "")
    atk_comp = data.get("attacker_computer", "")
    tgt_team = data.get("target_team", "")
    tgt_comp = data.get("target_computer", "")

    if not all([atk_team, atk_comp, tgt_team, tgt_comp]):
        return jsonify({"error": "attacker_team, attacker_computer, target_team, target_computer required"}), 400

    # Resolve target IP from config
    tgt_ip = (_config.get("teams", {})
                     .get(tgt_team, {})
                     .get("computers", {})
                     .get(tgt_comp, "unknown"))

    event = {
        "attacker_team": atk_team,
        "attacker_computer": atk_comp,
        "target_team": tgt_team,
        "target_computer": tgt_comp,
        "target_ip": tgt_ip,
        "attack_type": attack_type,
        "open_ports": data.get("open_ports", []),
        "timestamp": datetime.now().isoformat(),
        "source": "manual",
    }
    enriched = process_event(event)
    return jsonify({"status": "ok", "event": enriched})


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(silent=True) or {}
    action = data.get("action", "toggle")

    if action == "start":
        start_simulation()
    elif action == "stop":
        stop_simulation()
    elif action == "toggle":
        if _sim_running:
            stop_simulation()
        else:
            start_simulation()
    else:
        return jsonify({"error": f"unknown action '{action}'"}), 400

    return jsonify({"running": _sim_running})


@app.route("/api/simulate/status")
def api_simulate_status():
    return jsonify({"running": _sim_running})


@app.route("/stream")
def stream():
    """SSE endpoint — clients receive real-time events."""
    def generate():
        q: queue.Queue = queue.Queue(maxsize=50)
        with _lock:
            _subscribers.append(q)

        # Send init message immediately
        init_payload = json.dumps({
            "type": "init",
            "nodes": node_states,
            "attack_types": ATTACK_TYPES,
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
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    global _config, node_states

    parser = argparse.ArgumentParser(description="RedBlue Security Ops — Log Server")
    parser.add_argument("--port", type=int, default=5000, help="Listening port (default 5000)")
    parser.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "../config.yaml"),
                        help="Path to config.yaml")
    args = parser.parse_args()

    _config = load_config(args.config)
    node_states = build_node_states(_config)

    print(f"[BOOT] RedBlue Security Ops Server")
    print(f"[BOOT] Config  : {args.config}")
    print(f"[BOOT] Nodes   : {list(node_states.keys())}")
    print(f"[BOOT] Attacks : {list(ATTACK_TYPES.keys())}")
    print(f"[BOOT] Listening on 0.0.0.0:{args.port}")
    print(f"[BOOT] Dashboard: http://localhost:{args.port}/")

    app.run(host="0.0.0.0", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
