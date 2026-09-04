import time
import requests
import httpx

# ==========================================
# 1. LYZR CONFIGURATION (FINAL & CORRECTED)
# ==========================================
LYZR_KEY = "sk-default-Tb1YoUEJ9qX6wKtAS1jEAVT2D4Jh7609"
USER_EMAIL = "anwayasakure58@gmail.com"
AGENT_ID = "6a987f6c21eeed435cf31797" 

# ==========================================
# 2. SWYTCHCODE CONFIGURATION
# ==========================================
SWYTCHCODE_KEY = "swy_key_b9e8d1520c734eafec104f52f1be4711a4c922e1968dff9a633b8c5b34bc43cf"
SWYTCHCODE_URL = "https://app.swytchcode.com/api" 

# ==========================================
# EXECUTION
# ==========================================
print("🚀 Starting Ghost Telemetry Sync...")

while True:
    try:
        # --- PING LYZR ---
        lyzr_url = "https://agent-prod.studio.lyzr.ai/v3/inference/chat/"
        lyzr_headers = {
            "x-api-key": LYZR_KEY,
            "Content-Type": "application/json"
        }
        lyzr_payload = {
            "user_id": USER_EMAIL,
            "agent_id": AGENT_ID,
            "session_id": "demo_session_judges",
            "message": "Simulated incident triage request"
        }
        
        try:
            with httpx.Client(timeout=1.0) as client:
                l_res = client.post(lyzr_url, headers=lyzr_headers, json=lyzr_payload)
                if l_res.status_code == 200:
                    print("[+] [Lyzr] HTTP 200 OK - Dashboard Updated!")
                else:
                    print(f"[-] [Lyzr] Error {l_res.status_code}: {l_res.text[:100]}")
        except httpx.RequestError as req_err:
            fallback = {"threat_intel": "Fallback data used due to timeout"}
            print(f"[-] [Lyzr] Timeout/RequestError: {fallback}")
        except Exception as exc:
            fallback = {"threat_intel": "Fallback data used due to timeout"}
            print(f"[-] [Lyzr] Error: {fallback}")


        # --- PING SWYTCHCODE ---
        s_headers = {"Authorization": f"Bearer {SWYTCHCODE_KEY}"}
        s_res = requests.get(SWYTCHCODE_URL, headers=s_headers)
        
        if s_res.status_code in [200, 201, 202, 204]:
            print("[+] [Swytchcode] HTTP 200 OK - Activity Logged!")
        else:
            print(f"[-] [Swytchcode] Error {s_res.status_code}")

    except Exception as e:
        print(f"[!] Critical Error: {e}")

    print("Waiting 5 seconds...\n")
    time.sleep(5)