import subprocess
import threading
import time
import frida
from log_utils import add_log
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='pkg_resources')


def list_adb_devices():
    try:
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.strip().splitlines()
        
        device_lines = output[1:]

        devices = []
        for line in device_lines:
            if line.strip(): 
                parts = line.split()
                if len(parts) == 2 and parts[1] == 'device':
                    devices.append(parts[0])  

        return devices
    except Exception as e:
        return f"Error: {str(e)}"

def run_pinning_bypass(package_name):
    try:
        list_adb_devices()
        print(f"[*] Starting objection for {package_name} (no adb launch)")
        add_log("[DEBUG] before Popen")
        process = subprocess.Popen(["frida", "-U", "-f", package_name, "-l", "./static/tools/frida-multiple-unpinning.js"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        add_log("[DEBUG] after Popen")
        add_log(f"\n $ frida -U -f {package_name} --codeshare akabe1/frida-multiple-unpinning")
        output_lines = []
        devices = frida.get_device_manager().enumerate_devices()
        for d in devices:
            print(f"🧩 ID: {d.id}, NAME: {d.name}, TYPE: {d.type}")
        def read_output():
            for line in process.stdout:
                add_log(line.strip())
                output_lines.append(line)

        # Start output reading and command sending in background
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()

        # Wait until finished
        process.wait(timeout=20)

        return True, "".join(output_lines)

    except subprocess.TimeoutExpired:
        process.kill()
        return False, "Objection command timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"



