#!/usr/bin/env python3
"""
Log server for the Raspberry Pi.
- POST /log       — team machines push attack events here
- GET  /          — visual dashboard (auto-updates via SSE)
- GET  /stream    — Server-Sent Events stream
- GET  /history   — full event log as JSON

Run:
  python3 server.py
  python3 server.py --port 5000   # default

Install dependencies first:
  pip install flask pyyaml
"""

import argparse
import json
import queue
import threading
from collections import deque
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__)

# In-memory store — last 200 events
log_history: deque = deque(maxlen=200)
_subscribers: list[queue.Queue] = []
_lock = threading.Lock()


# ── helpers ─────────────────────────────────────────────────────────────────

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


# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/log", methods=["POST"])
def receive_log():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "expected JSON body"}), 400

    data.setdefault("received_at", datetime.now().isoformat())
    log_history.append(data)
    broadcast(json.dumps(data))

    attacker = f"{data.get('attacker_team','?')}.{data.get('attacker_computer','?')}"
    target   = f"{data.get('target_team','?')}.{data.get('target_computer','?')} ({data.get('target_ip','?')})"
    ports    = len(data.get("open_ports", []))
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {attacker} -> {target}  ({ports} open ports)")

    return jsonify({"status": "ok"})


@app.route("/history")
def get_history():
    return jsonify(list(log_history))


@app.route("/stream")
def stream():
    """SSE endpoint — clients subscribe and receive events in real time."""
    def generate():
        q: queue.Queue = queue.Queue(maxsize=50)
        with _lock:
            _subscribers.append(q)
        try:
            while True:
                try:
                    data = q.get(timeout=25)
                    yield f"data: {data}\n\n"
                except queue.Empty:
                    # Keepalive so the browser doesn't time out the connection
                    yield "data: {\"ping\":true}\n\n"
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


# ── entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print(f"Starting log server on 0.0.0.0:{args.port}")
    print("Dashboard: http://<pi-ip>:{args.port}/")
    app.run(host="0.0.0.0", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
