import subprocess
import threading
import time
import frida
from log_utils import add_log
import warnings
import os

warnings.filterwarnings("ignore", category=UserWarning, module='pkg_resources')

def run_root_check(package_name):
    try:
        print(f"[*] Starting objection for {package_name} (root simulation)")
        process = subprocess.Popen(
            ["objection", "-n", package_name, "start"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        
        add_log(f"\n\n $ objection -n {package_name} start")

        output_lines = []
        devices = frida.get_device_manager().enumerate_devices()
        for d in devices:
            print(f"🧩 ID: {d.id}, NAME: {d.name}, TYPE: {d.type}")

        def read_output():
            for line in process.stdout:
                add_log(line.strip())
                output_lines.append(line)
                if "no root detection" in line.lower() or "rooted" in line.lower():
                    break

        def send_commands():
            time.sleep(4)
            # Detection Logic

            process.stdin.write("android root simulate\n")
            process.stdin.flush()
            add_log("🚨 Turn on the screenshot. will take a screenshot.\n\n")
            time.sleep(3)
            screens_dir = os.path.join(server_dir, "static", "screenshots")
            
            screenshot_path = f"rooting_test_{package_name}.png"
            local_path = os.path.join(screens_dir, screenshot_path)

            process.stdin.write(f"android ui screenshot {local_path}\n")
            add_log(f"\n$ android ui screenshot {local_path}\n")
            process.stdin.flush()
            add_log(f"✅ Rooting check screenshot was saved in {local_path}.")
            add_log(f"✅ Check simple root detection. (e.g. the application show alert or exit the application)")
        

        reader_thread = threading.Thread(target=read_output, daemon=True)
        sender_thread = threading.Thread(target=send_commands, daemon=True)

        reader_thread.start()
        sender_thread.start()
        
        return True, "".join(output_lines)

    except subprocess.TimeoutExpired:
        process.kill()
        return False, "Objection command timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"
