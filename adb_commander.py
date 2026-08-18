#!/usr/bin/env python3
"""
ADB Commander Client - Integrated with Live API
Author: The Onyx System
"""
import subprocess
import os
import sys
import time
import platform
import hashlib
import uuid
import socket
import threading
import requests
from datetime import datetime

# Try to import colorama
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
        CYAN = '\033[96m'; WHITE = '\033[97m'; RESET = '\033[0m'
    class Style:
        BRIGHT = '\033[1m'
    def init(*args, **kwargs): pass

# ================= কনফিগারেশন =================
SERVER_URL = "https://api.alii.uk"  # আপনার লাইভ সার্ভার
VERSION = "6.0.0"
SESSION_TOKEN = None
LICENSE_VALID = False
STOP_POLLING = False

# ================= হার্ডওয়্যার আইডি জেনারেটর =================
def get_pc_name():
    return socket.gethostname()

def get_hardware_id():
    try:
        identifiers = []
        try:
            mac = hex(uuid.getnode())
            identifiers.append(mac)
        except: pass
        
        if platform.system() == 'Windows':
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Cryptography")
                guid = winreg.QueryValueEx(key, "MachineGuid")[0]
                identifiers.append(guid)
            except: pass
        elif platform.system() == 'Linux':
            try:
                with open('/etc/machine-id', 'r') as f:
                    identifiers.append(f.read().strip())
            except: pass

        if not identifiers:
            identifiers.append(str(uuid.getnode()))
        
        combined = '|'.join(identifiers)
        return hashlib.sha256(combined.encode()).hexdigest()
    except:
        return hashlib.md5(str(uuid.getnode()).encode()).hexdigest()

# ================= API ইন্টিগ্রেশন =================
def verify_with_server(password):
    global SESSION_TOKEN, LICENSE_VALID
    
    print(Fore.YELLOW + "\n🔄 Verifying password with server...")
    try:
        response = requests.post(
            f"{SERVER_URL}/api/client/verify",
            json={
                "pc_name": get_pc_name(),
                "hardware_id": get_hardware_id(),
                "password": password
            },
            timeout=15
        )
        data = response.json()
        
        if data.get("success"):
            SESSION_TOKEN = data.get("session_token")
            LICENSE_VALID = True
            print(Fore.GREEN + f"✅ {data.get('message')}")
            return True
        else:
            print(Fore.RED + f"❌ {data.get('message')}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(Fore.RED + "❌ Cannot connect to server! Check internet.")
        return False
    except Exception as e:
        print(Fore.RED + f"❌ Error: {str(e)}")
        return False

def status_polling():
    global LICENSE_VALID, STOP_POLLING
    while not STOP_POLLING:
        time.sleep(10)  # ১০ সেকেন্ড পর পর চেক
        try:
            if SESSION_TOKEN:
                response = requests.post(
                    f"{SERVER_URL}/api/client/status",
                    json={"session_token": SESSION_TOKEN},
                    timeout=5
                )
                data = response.json()
                if not data.get("active"):
                    print(Fore.RED + "\n⛔️ Admin has deactivated your license! Closing software...")
                    LICENSE_VALID = False
                    STOP_POLLING = True
                    os._exit(0)  # সফটওয়্যার হঠাৎ বন্ধ করে দেবে
        except:
            pass

# ================= কমান্ড এক্সিকিউশন =================
def run_command(cmd):
    print(Fore.YELLOW + f"\n▶ Executing: {cmd}")
    print(Fore.CYAN + "-" * 60)
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout: print(Fore.GREEN + f"Output:\n{result.stdout}")
        if result.stderr: print(Fore.YELLOW + f"Stderr:\n{result.stderr}")
        return result.returncode == 0
    except Exception as e:
        print(Fore.RED + f"Error: {str(e)}")
        return False

# ================= মেইন মেনু =================
def show_menu():
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "  ADB COMMANDER - Client Edition")
    print(Fore.CYAN + "=" * 60)
    print(Fore.GREEN + f"  License Status: Active")
    print(Fore.CYAN + "=" * 60)
    print(Fore.WHITE + "\n  [1]  - Push preload.so")
    print(Fore.WHITE + "  [2]  - Set preload.so permissions")
    print(Fore.WHITE + "  [3]  - LD_PRELOAD escalation")
    print(Fore.WHITE + "  [4]  - Push su binary")
    print(Fore.WHITE + "  [5]  - Set su permissions")
    print(Fore.WHITE + "  [6]  - Test su with id")
    print(Fore.WHITE + "  [7]  - Get SELinux status")
    print(Fore.WHITE + "  [8]  - Push abl.elf")
    print(Fore.WHITE + "  [9]  - Flash abl_a (DANGEROUS!)")
    print(Fore.WHITE + "  [10] - Flash abl_b (DANGEROUS!)")
    print(Fore.WHITE + "  [11] - Reboot to bootloader")
    print(Fore.WHITE + "  [12] - Fastboot devices")
    print(Fore.WHITE + "  [13] - Erase FRP (DANGEROUS!)")
    print(Fore.WHITE + "  [14] - Flash gpt_both4.bin (DANGEROUS!)")
    print(Fore.WHITE + "  [Q]  - Quit")
    print(Fore.CYAN + "-" * 60)

# ================= মেইন লুপ =================
def main():
    global LICENSE_VALID, STOP_POLLING
    
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "  ADB COMMANDER - Client Edition")
    print(Fore.CYAN + "=" * 60)
    print(Fore.WHITE + f"  Version: {VERSION}")
    print(Fore.WHITE + f"  PC: {get_pc_name()}")
    print(Fore.CYAN + "=" * 60)

    # ১. গ্লোবাল পাসওয়ার্ড ইনপুট নেওয়া
    print(Fore.WHITE + "\n🔑 Enter the Global Password given by Admin:")
    password = input("Password: ").strip()

    # ২. সার্ভারে ভেরিফাই করা
    if not verify_with_server(password):
        input(Fore.RED + "\n❌ Press Enter to exit...")
        sys.exit(1)

    # ৩. পোলিং থ্রেড স্টার্ট করা (যাতে ডিএক্টিভেট হলে সাথে সাথে বন্ধ হয়)
    polling_thread = threading.Thread(target=status_polling, daemon=True)
    polling_thread.start()

    # ৪. মেইন মেনু লুপ
    while LICENSE_VALID:
        show_menu()
        choice = input(Fore.CYAN + "\nEnter choice: ").strip()

        if choice.upper() == 'Q':
            print(Fore.YELLOW + "\nExiting software...")
            STOP_POLLING = True
            break
        else:
            # কমান্ড ম্যাপিং (আপনার কমান্ড অনুযায়ী)
            commands = {
                '1': 'adb push preload.so /data/local/tmp/preload.so',
                '2': 'adb shell chmod 755 /data/local/tmp/preload.so',
                '3': 'adb shell "LD_PRELOAD=/data/local/tmp/preload.so id"',
                '4': 'adb push su /data/local/tmp/su',
                '5': 'adb shell chmod 755 /data/local/tmp/su',
                '6': 'adb shell "/data/local/tmp/su -c \'id\'"',
                '7': 'adb shell "/data/local/tmp/su -c \'getenforce\'"',
                '8': 'adb push abl.elf /data/local/tmp/abl',
                '9': 'adb shell "su -c dd if=/data/local/tmp/abl of=/dev/block/by-name/abl_a"',
                '10': 'adb shell "su -c dd if=/data/local/tmp/abl of=/dev/block/by-name/abl_b"',
                '11': 'adb reboot bootloader',
                '12': 'fastboot devices',
                '13': 'fastboot erase frp',
                '14': 'fastboot flash partition:4 gpt_both4.bin'
            }
            if choice in commands:
                if choice in ['9', '10', '13', '14']:
                    print(Fore.RED + Style.BRIGHT + "\n⚠️ DANGEROUS OPERATION!")
                    confirm = input(Fore.YELLOW + "Type 'YES' to continue: ")
                    if confirm.upper() != 'YES':
                        continue
                run_command(commands[choice])
            else:
                print(Fore.RED + "Invalid choice!")

    print(Fore.GREEN + "\n✅ Goodbye!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nInterrupted by user.")
        sys.exit(0)
