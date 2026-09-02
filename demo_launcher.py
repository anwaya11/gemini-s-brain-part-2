import os
import subprocess
import time

print("=======================================================")
print(" 🚀 CHIMERA SOC - AUTOMATED DEMO INITIALIZATION ")
print("=======================================================")
print("[*] Preparing environment...")
time.sleep(1)

# --- OPTIONAL: CLEAR PAST DATA ---
# If your backend saves to a local database file (like SQLite), uncomment the lines below to delete it and start fresh.
if os.path.exists("database.db"):
    os.remove("database.db")
    print("[*] Old backend data purged. Starting fresh.")

# 1. START BACKEND
print("[+] Launching Backend Orchestrator...")
# UPDATE THIS COMMAND IF NEEDED (e.g., 'uvicorn main:app --reload')
subprocess.Popen('start cmd /k "title CHIMERA Backend && cls && cd backend && (if exist venv\\Scripts\\activate call venv\\Scripts\\activate) && python main.py"', shell=True)
time.sleep(2)

# 2. START FRONTEND
print("[+] Launching Frontend UI...")
# UPDATE THIS COMMAND IF NEEDED (e.g., 'npm start')
subprocess.Popen('start cmd /k "title CHIMERA Frontend && cls && cd frontend && npm run dev"', shell=True)
time.sleep(2)

# 3. START TELEMETRY (Lyzr, Swytchcode, n8n)
print("[+] Launching Telemetry Sync Pipeline...")
subprocess.Popen('start cmd /k "title Telemetry Sync && cls && python ghost_sync.py"', shell=True)
time.sleep(2)

print("\n=======================================================")
print("✅ ALL SYSTEMS ONLINE. DASHBOARDS ARE LIVE.")
print("=======================================================")
print("Judges are watching. Show them the UI and dashboards first.")

# 4. PAUSE UNTIL YOU ARE READY TO FIRE THE ATTACK
input(">>> Press ENTER when you are ready to launch the ATTACK SCRIPT... <<<")

print("🔥 Launching simulated attack sequence...")
# UPDATE THIS COMMAND TO MATCH YOUR ACTUAL ATTACK SCRIPT NAME
subprocess.Popen('start cmd /k "title Threat Simulation && color 4 && cls && cd backend && python attack_simulator.py"', shell=True)