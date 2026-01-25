import subprocess
import threading
import time
import frida
import os
import pexpect
import re
from log_utils import add_log
import warnings
from datetime import datetime

warnings.filterwarnings("ignore", category=UserWarning, module='pkg_resources')

def get_latest_apk_file(apk_dir="../apk"):
    apk_files = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]
    if not apk_files:
        return None
    latest_file = max(apk_files, key=lambda f: os.path.getmtime(os.path.join(apk_dir, f)))
    return os.path.join(apk_dir, latest_file)

def reinstall_apk(package_name, apk_path):
    try:
        add_log(f"\n\n$ adb uninstall {package_name}")
        uninstall = subprocess.run(["adb", "uninstall", package_name],
                                   capture_output=True, text=True)
        if uninstall.returncode == 0:
            add_log(f"✅ Uninstalled {package_name}")
        else:
            add_log(f"⚠️ Uninstall failed or app not found: {uninstall.stderr.strip()}")

        add_log(f"\n\n$ adb install {apk_path}")
        install = subprocess.run(["adb", "install", apk_path],
                                 capture_output=True, text=True)
        if install.returncode == 0:
            add_log(f"✅ Installed new APK: {apk_path}")
        else:
            add_log(f"❌ Install failed: {install.stderr.strip()}")

        return install.returncode == 0

    except Exception as e:
        add_log(f"❌ Error during reinstall: {str(e)}")
        return False

def adb_su(cmd: str, timeout: int = 30) -> str:
    out = subprocess.check_output(["adb", "shell", "su", "-c", cmd], text=True, timeout=timeout)
    return out


def read_maps(pid: str) -> str:
    return adb_su(f"cat /proc/{pid}/maps | grep libfrida-gadget.so", timeout=30)

def run_tampering_check(package_name, flutter_yn):
    try:
        # 1. Patch APK
        apk_path = get_latest_apk_file("apk")
        add_log(f"\n\n $ objection patchapk --source {apk_path} --skip-resources --ignore-nativelibs")
        
        patch_process = subprocess.run(
            ["objection", "patchapk", "--source", apk_path, "--skip-resources", "--ignore-nativelibs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        add_log(patch_process.stdout)


        reinstall_apk(package_name, get_latest_apk_file("apk"))
        time.sleep(15)


        # 2. Check frida Library Injection
        
        check_command = f"cat /proc/{pid}/maps | grep libfrida-gadget.so"
        add_log(f"\n $ adb shell su -c '{check_command}'")
        check_process = subprocess.run(
            ["adb", "shell", "su", "-c", check_command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )
        
        add_log(check_process.stdout)
        
        if "frida" not in check_process.stdout.lower():
            return False, "❌ Tampering with Frida Library Injection not confirmed."

        time.sleep(1)

        # 3. Screenshot
        add_log("🚨 Turn on the screen, will take a screenshot")
        time.sleep(10)
        screenshot_path = "tampering_test_" + package_name
        add_log(f"\n $ adb shell screencap -p /data/local/tmp/{screenshot_path}.png")
        subprocess.run(["adb", "shell", "screencap", "-p", f"/data/local/tmp/{screenshot_path}.png"], check=True)

        os.makedirs("static/screenshots", exist_ok=True)
        add_log(f"\n $ adb pull /data/local/tmp/{screenshot_path}.png static/screenshots/{screenshot_path}.png")
        subprocess.run(["adb", "pull",f"/data/local/tmp/{screenshot_path}.png", f"static/screenshots/{screenshot_path}.png"], check=True)
        add_log(f"✅ Tampering check screenshot was saved in static/screenshots/{screenshot_path}.png. ")
        add_log(f"✅ Check simple tampering detection. (e.g. the application show alert or exit the application)")


        return True, "✅ Tampering check completed successfully."

    except subprocess.CalledProcessError as cpe:
        error_msg = f"❌ Command failed: {cpe.cmd}\nOutput: {cpe.output}"
        add_log(error_msg)
        return False, error_msg

    except Exception as e:
        error_msg = f"❌ Error during tampering check: {str(e)}"
        add_log(error_msg)
        return False, error_msg
