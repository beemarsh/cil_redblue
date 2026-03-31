#!/usr/bin/env python3
"""
Attack script — runs on team machines.
Scans all computers of the opposing team and ships results to the team's Raspberry Pi.

Usage:
  python3 attack.py --team blue --computer c1
  python3 attack.py --team red  --computer c2 --loop
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime

import requests
import yaml


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def opposing(team: str) -> str:
    return "red" if team == "blue" else "blue"


def nmap_scan(ip: str, ports: str) -> list[str]:
    """Run nmap and return a list of 'port/proto  state  service' strings."""
    try:
        result = subprocess.run(
            ["nmap", "-p", ports, "--open", "-T4", "--host-timeout", "20s", ip],
            capture_output=True,
            text=True,
            timeout=30,
        )
        open_ports = [
            line.strip()
            for line in result.stdout.splitlines()
            if "/tcp" in line or "/udp" in line
        ]
        return open_ports
    except FileNotFoundError:
        print("ERROR: nmap not installed. Run: sudo apt install nmap")
        return []
    except subprocess.TimeoutExpired:
        return ["scan timed out"]


def send_log(pi_ip: str, port: int, entry: dict) -> None:
    url = f"http://{pi_ip}:{port}/log"
    try:
        requests.post(url, json=entry, timeout=5)
        print(f"  -> log sent to Pi at {pi_ip}")
    except requests.exceptions.ConnectionError:
        print(f"  -> WARNING: could not reach Pi at {pi_ip} (is the server running?)")
    except Exception as e:
        print(f"  -> WARNING: log send failed: {e}")


def run_attack(config: dict, my_team: str, my_computer: str) -> None:
    enemy = opposing(my_team)
    targets: dict = config["teams"][enemy]["computers"]
    pi_ip: str = config["teams"][my_team]["raspberry_pi"]
    pi_port: int = config["settings"]["log_port"]
    scan_ports: str = config["settings"]["scan_ports"]

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {my_team}.{my_computer} attacking {enemy} team")

    for computer_id, target_ip in targets.items():
        print(f"  Scanning {enemy}.{computer_id} ({target_ip}) ports {scan_ports}...")
        open_ports = nmap_scan(target_ip, scan_ports)
        print(f"  Found {len(open_ports)} open port(s)")

        entry = {
            "timestamp": datetime.now().isoformat(),
            "attacker_team": my_team,
            "attacker_computer": my_computer,
            "target_team": enemy,
            "target_computer": computer_id,
            "target_ip": target_ip,
            "open_ports": open_ports,
        }
        send_log(pi_ip, pi_port, entry)


def main() -> None:
    parser = argparse.ArgumentParser(description="Port-scan the opposing team and log results.")
    parser.add_argument("--team", required=True, choices=["blue", "red"])
    parser.add_argument("--computer", required=True, help="This machine's ID, e.g. c1")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously at the interval defined in config.yaml",
    )
    args = parser.parse_args()

    config = load_config(args.config)

    if args.loop:
        interval = config["settings"]["attack_interval"]
        print(f"Loop mode: attacking every {interval}s. Ctrl+C to stop.")
        while True:
            try:
                run_attack(config, args.team, args.computer)
                time.sleep(interval)
            except KeyboardInterrupt:
                print("\nStopped.")
                sys.exit(0)
    else:
        run_attack(config, args.team, args.computer)


if __name__ == "__main__":
    main()
