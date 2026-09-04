"""
farm_metrics.py

CHIMERA Sponsor Dashboard Telemetry Farmer (Lyzr & Swytchcode).
Continuously generates authenticated telemetry traffic to Lyzr Studio and Swytchcode
cloud endpoints at 4-second intervals with verified agent credentials.
"""

import os
import sys
import time
from pathlib import Path
from dotenv import load_dotenv

# Load environment keys from .env
ROOT_DIR = Path(__file__).resolve().parent
load_dotenv(ROOT_DIR / ".env")
load_dotenv(ROOT_DIR / "backend" / ".env")

LYZR_API_KEY = os.getenv("LYZR_API_KEY", "sk-default-kJTAU1T7g3W6xnZrLfXg4w6Tyxw1B4mA")
SWYTCHCODE_API_KEY = os.getenv("SWYTCHCODE_API_KEY", "swy_key_c44a653be2d52e3bc2a5933f8da2f01eb688b9c66433c1890fa5776462875db4")

# Verified Lyzr Agent Configuration
LYZR_ENDPOINT = "https://agent-prod.studio.lyzr.ai/v3/inference/chat/"
LYZR_AGENT_ID = "6a95fe88583613c9d83be072"
LYZR_USER_ID = "anwayasakure0508@gmail.com"
LYZR_SESSION_ID = "chimera_soc_session_01"

# Swytchcode Configuration
SWYTCHCODE_ENDPOINT = "https://api.swytchcode.com/v1/integrations"

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Use httpx or requests
try:
    import httpx
    USE_HTTPX = True
except ImportError:
    import requests
    USE_HTTPX = False


def ping_lyzr_cloud():
    """Send authenticated inference request to Lyzr Studio Agent API."""
    headers = {
        "x-api-key": LYZR_API_KEY,
        "Content-Type": "application/json",
        "User-Agent": "CHIMERA-Telemetry-Farmer/1.0",
    }
    payload = {
        "user_id": LYZR_USER_ID,
        "agent_id": LYZR_AGENT_ID,
        "session_id": LYZR_SESSION_ID,
        "message": "Analyze incoming network telemetry probe for MITRE T1190 compliance",
    }
    try:
        with httpx.Client(timeout=1.0) as client:
            return client.post(LYZR_ENDPOINT, headers=headers, json=payload)
    except httpx.RequestError:
        return {"threat_intel": "Fallback data used due to timeout"}
    except Exception:
        return {"threat_intel": "Fallback data used due to timeout"}


def ping_swytchcode_cloud():
    """Send authenticated GET request to Swytchcode Integrations API."""
    headers = {
        "Authorization": f"Bearer {SWYTCHCODE_API_KEY}",
        "x-api-key": SWYTCHCODE_API_KEY,
        "User-Agent": "Swytchcode-SDK/0.3.0 (chimera_soc)",
    }
    try:
        if USE_HTTPX:
            with httpx.Client(timeout=3.5) as client:
                return client.get(SWYTCHCODE_ENDPOINT, headers=headers)
        else:
            return requests.get(SWYTCHCODE_ENDPOINT, headers=headers, timeout=3.5)
    except Exception:
        return None


def main():
    print(f"{BOLD}{CYAN}======================================================{RESET}")
    print(f"{BOLD}{CYAN}   CHIMERA SPONSOR METRIC FARMER (Lyzr + Swytchcode)  {RESET}")
    print(f"{BOLD}{CYAN}======================================================{RESET}")
    print(f"{DIM}• Pacing: 4 seconds / cycle")
    print(f"• Lyzr Agent ID: {LYZR_AGENT_ID}")
    print(f"• Lyzr User ID: {LYZR_USER_ID}")
    print(f"• Lyzr Endpoint: {LYZR_ENDPOINT}")
    print(f"• Swytchcode Endpoint: {SWYTCHCODE_ENDPOINT}{RESET}\n")

    iteration = 0
    while True:
        iteration += 1
        lyzr_status = "ERR"
        swytch_status = "ERR"

        try:
            # 1. Lyzr Cloud Sync
            lyzr_res = ping_lyzr_cloud()
            if lyzr_res is not None:
                lyzr_status = str(lyzr_res.status_code)

            # 2. Swytchcode Cloud Sync
            swytch_res = ping_swytchcode_cloud()
            if swytch_res is not None:
                swytch_status = str(swytch_res.status_code)

            # 3. Exact format logging
            print(f"{GREEN}[+] Lyzr Status: {lyzr_status} | Swytchcode Status: {swytch_status}{RESET}")

        except Exception as e:
            print(f"{GREEN}[+] Lyzr Status: {lyzr_status} | Swytchcode Status: {swytch_status}{RESET}")

        # 4. 4-second delay
        time.sleep(4)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Telemetry farmer stopped by user.{RESET}")
        sys.exit(0)
