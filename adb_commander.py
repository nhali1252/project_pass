# আপনার সফটওয়্যারে যুক্ত করার কোড স্যাম্পল (Python)
import requests
import time
import os

SERVER_URL = "https://api.alii.uk"
PASSWORD_TO_VERIFY = "admin123" # User manually inputs this in your software

def get_hardware_id():
    # (এই ফাংশনটি আপনি ইতিমধ্যে তৈরি করেছেন - আপনার লাইসেন্স জেনারেটর থেকে নিতে পারেন)
    return "unique_hardware_id_from_pc"

def main_flow():
    hardware_id = get_hardware_id()
    pc_name = socket.gethostname()

    # 1. Verify password with server
    verify_response = requests.post(f"{SERVER_URL}/api/client/verify", json={
        "pc_name": pc_name,
        "hardware_id": hardware_id,
        "password": PASSWORD_TO_VERIFY
    })
    data = verify_response.json()
    if not data.get("success"):
        print(f"❌ Error: {data.get('message')}")
        return # Close app

    session_token = data.get("session_token")
    print(f"✅ License Activated! Session: {session_token}")

    # 2. Keep checking status every 10 seconds
    while True:
        time.sleep(10)
        try:
            status_resp = requests.post(f"{SERVER_URL}/api/client/status", json={"session_token": session_token})
            if not status_resp.json().get("active"):
                print("❌ Account deactivated by admin! Closing software...")
                # এখানে আপনার সফটওয়্যারটি বন্ধ করার কোড বসিয়ে দিন
                os._exit(0)
        except:
            pass
