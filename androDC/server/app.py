from flask import Flask, request, jsonify, render_template, send_from_directory
import os, threading, subprocess, shlex, time, pexpect, shutil, logging, traceback, importlib.util, urllib.request
from werkzeug.utils import secure_filename
from datetime import datetime
from utils.analysis.pinning_check import run_pinning_bypass
from utils.analysis.root_check import run_root_check
from utils.analysis.tampering_check import run_tampering_check, reinstall_apk
from log_utils import get_log, add_log
from pathlib import Path

app = Flask(
    __name__,
    template_folder='../templates',      
    static_folder='../frontend'          
)

class IgnorePaths(logging.Filter):
    def __init__(self, *paths):
        super().__init__()
        self.paths = set(paths)

    def filter(self, record):
        msg = record.getMessage()
        return not any(
            f'"GET {p} ' in msg or f'"POST {p} ' in msg or f'"HEAD {p} ' in msg
            for p in self.paths
        )

logging.getLogger("werkzeug").addFilter(IgnorePaths("/get_log"))


@app.route("/get_log", methods=["GET","POST"])
def get_logs():
    return jsonify(get_log())

    
@app.route('/')
def index():
    get_log(clear=True)
    set_adb_proxy("","0",False)
    add_log("✅ Manual proxy setting was resolved.")
    result = subprocess.run(["adb", "kill-server"],
            capture_output=True,
            text=True,
            timeout=100 
    )
    return render_template('index.html')

def pull_apk_background(apk_path, local_path, flutter_yn, proxy_ip, package_name):
    try:
        frida_server_install()
        result1 = subprocess.run(["adb", "start-server"],
            capture_output=True,
            text=True,
            timeout=100 
        )
        result2 = subprocess.run(["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=100  
        )
        result3 = subprocess.run(
            ["adb", "pull", apk_path, local_path],
            capture_output=True,
            text=True,
            timeout=180  
        )
        if (result1.returncode != 0) or (result2.returncode != 0) or (result3.returncode != 0):
            parts = []
            if result1.returncode != 0: parts.append(f"adb start-server: {result1.stderr.strip()}")
            if result2.returncode != 0: parts.append(f"adb devices: {result2.stderr.strip()}")
            if result3.returncode != 0: parts.append(f"adb pull: {result3.stderr.strip()}")
            add_log("❌ Sending APK failed. " + " | ".join(p for p in parts if p))
        else:
            add_log(f"✅ Sending APK successfully: {local_path}")
        

        if flutter_yn == True:
            dest = run_reflutter(local_path, proxy_ip)
            add_log("[+] APK local path :")
            add_log(local_path)
            add_log("[+] reinstall the updated app by reflutter...")

            ks = generate_test_keystore(
                static_dir="static/tools",
                keystore_name="my-test-key.jks",
                alias="myalias",
                storepass="keypass123",
                keypass="keypass123",
                overwrite=True  
            )
            print("Keystore created at:", ks)
            signed_apk = sign_apk_with_uber(
                apk_path = dest,
                keystore_path=ks,
                alias="myalias",
                keypass="keypass123",
                storepass="keypass123"
            )
            final_signed_path = os.path.splitext(dest)[0] + "-aligned-signed.apk"
            
            reinstall_apk(package_name, final_signed_path) 
            set_adb_proxy(proxy_ip, 8083, flutter_yn)
            thread = threading.Thread(target=run_pinning_bypass, args=(package_name,)) 
            thread.start() 

        else: 
            set_adb_proxy(proxy_ip, 8080, flutter_yn)
            thread = threading.Thread(target=run_pinning_bypass, args=(package_name,)) 
            thread.start()
            
    except Exception as e:
        print("❌ Background pull failed:", e)
        result = subprocess.run(["adb", "kill-server"],
            capture_output=True,
            text=True,
            timeout=100  
        )
        if result.returncode != 0:
            print("❌ Kill failed:", result.stderr)
        else:
            print("✅ kill successfully:", local_path)


def frida_server_install(static_tools_dir: str = "static/tools"):
    os.makedirs(static_tools_dir, exist_ok=True)
    frida_server_path = os.path.abspath(os.path.join(static_tools_dir, "frida-server"))
    result1 = subprocess.run(["adb", "push", str(frida_server_path), "/data/local/tmp/frida-server"],
        capture_output=True,
        text=True,
        timeout=60 
    )
    result2 = subprocess.run(["adb", "shell", "su", "-c", '"chmod 755 /data/local/tmp/frida-server"'],
        capture_output=True,
        text=True
    )
    result3 = subprocess.run(["adb", "shell", "su", "-c", '"/data/local/tmp/frida-server &"'],
        capture_output=True,
        text=True
    )
    if (result1.returncode != 0) and (result2.returncode != 0) and (result3.returncode != 0):
        add_log("❌ frida-server install failed.", result.stderr)
    else:
        print("✅ frida-server installed successfully.")


def ensure_uber_apk_signer(static_tools_dir: str = "static/tools") -> str:
    os.makedirs(static_tools_dir, exist_ok=True)
    jar_path = os.path.abspath(os.path.join(static_tools_dir, "uber-apk-signer.jar"))
    uber_url = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
    if not os.path.exists(jar_path):
        urllib.request.urlretrieve(uber_url, jar_path)
    return jar_path

def generate_test_keystore(
    static_dir: str = "static/tools",
    keystore_name: str = "my-test-key.jks",
    alias: str = "myalias",
    storepass: str = "storepass123",
    keypass: str = "keypass123",
    keytool_path: str = "keytool",
    overwrite: bool = False,
) -> str:
    """Create PKCS12 keystore for testing and return its absolute path."""
    os.makedirs(static_dir, exist_ok=True)
    keystore_path = os.path.abspath(os.path.join(static_dir, keystore_name))
    if os.path.exists(keystore_path):
        os.remove(keystore_path)

    # ensure keytool exists
    subprocess.run([keytool_path, "-help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    cmd = [
        keytool_path, "-genkeypair", "-v",
        "-storetype", "PKCS12",
        "-keystore", keystore_path,
        "-alias", alias,
        "-storepass", storepass,
        "-keypass", keypass,
        "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "3650",
        "-dname", "CN=Test, OU=Test, O=Test, L=Seoul, S=Seoul, C=KR",
    ]
    subprocess.run(cmd, check=True)
    return keystore_path

def sign_apk_with_uber(apk_path: str, keystore_path: str, alias: str, keypass: str, storepass: str,
                       static_tools_dir: str = "static/tools") -> str:
    jar_path = ensure_uber_apk_signer(static_tools_dir)
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")
    if not os.path.exists(keystore_path):
        raise FileNotFoundError(f"Keystore not found: {keystore_path}")

    cmd = [
        "java", "-jar", jar_path,
        "--apks", apk_path,
        "--ks", keystore_path,
        "--ksAlias", alias,
        "--ksKeyPass", keypass,
        "--ksPass", storepass,
        "--ksType", "PKCS12",     
    ]
    subprocess.run(cmd, check=True)

    signed_apk_path = apk_path.replace(".apk", "-aligned-signed.apk")
    if not os.path.exists(signed_apk_path):
        raise FileNotFoundError("Signed APK not found. Check signer output.")
    return signed_apk_path


def run_reflutter(apk_path, proxy_ip="192.168.0.100", proxy_port=8083):
    try:
        add_log("[+] Execute Reflutter...it may take around 5mins")
        
        os.environ["REPROXY"] = f"{proxy_ip}:{proxy_port}"
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        apk_full_path = os.path.join(parent_dir, apk_path)

        child = pexpect.spawn(f"reflutter {apk_full_path}", encoding="utf-8", timeout=300)

        idx = child.expect([
            "Please enter your BurpSuite IP:", 
            pexpect.EOF,                        
            pexpect.TIMEOUT                     
        ])

        if idx == 0:
            child.sendline(proxy_ip)
            child.expect(pexpect.EOF) 
        elif idx == 1:
            pass
        else:
            child.close(force=True)
            raise TimeoutError("❌ reflutter timed out before asking for BurpSuite IP (or it hung).")

        output = child.before or ""  
        exitstatus = child.exitstatus
        output_apk = Path("release.RE.apk")  
        if not output_apk.exists():
            raise FileNotFoundError(f"❌ reflutter output not found at {output_apk}")
        dest_dir = parent_dir
        print(apk_path)
        a = apk_path[:apk_path.find(".apk")-1]
        print(a)

        dest = dest_dir +"/"+a+"_reflutter.apk"
        
        dest = os.path.abspath(os.path.join(dest_dir, a + "_reflutter.apk"))
        shutil.move(output_apk, dest)
        add_log("[+] Reflutter apk was successfully saved in "+dest)
        return dest

    except Exception as e:
        print(f"❌ Error : {e}, Plz note that if you run reflutter several time within a short period, it will be blocked for few minuets.")
        add_log(f"❌ Error : {e}, Plz note that if you run reflutter several time within a short period, it will be blocked for few minuets.")
        return None


#@app.route("/set_adb_proxy", methods=["POST"])
def set_adb_proxy(proxy_ip, proxy_port, flutter_yn = False):
    proxy_string = f"{proxy_ip}:{proxy_port}"
    cmd = ["adb", "shell", "su", "-c", f"'settings put global http_proxy {proxy_string}'"]
    print()
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        #add_log("✅ Global proxy setting done: "+proxy_string)
        if flutter_yn == True:
            proxy_string2 = f"{proxy_ip}:8083"
            cmd2 = ["adb", "shell", "su", "-c", f"'iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination {proxy_string2}'"]
            subprocess.run(cmd2, capture_output=True, text=True, check=True)
            cmd3 = ["adb", "shell", "su", "-c", f"'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination {proxy_string2}'"]
            subprocess.run(cmd3, capture_output=True, text=True, check=True)
            add_log("✅ Iptable setting for flutter was set: "+proxy_string2)

    except subprocess.CalledProcessError as e:
        add_log("❌ Failed to set proxy, Confirm android connection")
        print("Error:", e.stderr)


'''@app.route("/pinning_bypass", methods=["POST"])
def pinning_bypass():
    data = request.get_json()
    package_name = data.get("package")
    ip = data.get("ip")
    flutter_yn = data.get("flutter_yn")
    print(package_name)
    print(ip)
    if not package_name:
        return jsonify({"message": "No package name provided"}), 400
    
    set_adb_proxy(ip, 8080, flutter_yn)
    
    thread = threading.Thread(target=run_pinning_bypass, args=(package_name,))
    thread.start()
    return jsonify({
        "success": True,
        "message": f"Started SSL pinning bypass for {package_name} in background."
    }), 200'''



@app.route("/root_check", methods=["POST"])
def root_check():
    data = request.get_json()
    package_name = data.get("package")
    print(package_name)
    if not package_name:
        return jsonify({"message": "No package name provided"}), 400
    thread = threading.Thread(target=run_root_check, args=(package_name,))
    thread.start()
    return jsonify({
        "success": True,
        "message": f"Started root simulation for {package_name} in background."
    }), 200

@app.route("/tampering_check", methods=["POST"])
def tampering_check():
    data = request.get_json()
    package_name = data.get("package")
    flutter_yn = data.get("flutter_yn")
    thread = threading.Thread(target=run_tampering_check, args=(package_name, flutter_yn))
    thread.start()
    return jsonify({"success": True, "message": f"Started tampering check for {package_name} in background."}), 200


# Request routing
@app.route("/pull_apk", methods=["POST"])
def pull_apk():
    data = request.get_json()
    apk_path = data.get("apkPath")
    selectedPackage = data.get("selectedPackage")
    flutter_yn = data.get("flutter_yn")
    proxy_ip = data.get("proxyIP")

    if not apk_path:
        return jsonify({"error": "No APK path provided"}), 400

    try:
        # download path
        os.makedirs("apk", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        filename = secure_filename(selectedPackage + ".apk")
        local_path = os.path.join("apk", f"{selectedPackage}_{timestamp}.apk") 
        
        # thread start
        thread = threading.Thread(
            target=pull_apk_background,
            args=(apk_path, local_path, flutter_yn, proxy_ip, selectedPackage),
            daemon=True  # exit
        )
        thread.start()
            
        return jsonify({
            "status": "started",
            "apk_path": local_path
        })
        
            

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/static_check", methods=["POST"])
def static_check():
    data = request.get_json()
    apk_path = data.get("local_path")   ## update for local_path
    if not apk_path:
        return jsonify({"error": "apkPath is required"}), 400

    '''def run_check():
        try:
            report = run_static_check(apk_path)
            add_log(f"[+] Static obfuscation report: {report}")
            print(report)
        except Exception as e:
            add_log(f"❌ Static check failed: {e}")
            print("Static check error:", e)

    threading.Thread(target=run_check, daemon=True).start()
    return jsonify({"success": True, "message": f"Started static check for {apk_path}"}), 200'''


@app.route('/images/<path:filename>')
def serve_image(filename):
    return send_from_directory('../frontend/images', filename)

'''if __name__ == '__main__':
    #Setting of tool
    print("🔧 Checking tool installation status...")
    tools = ToolManager()
    tools.setup()
    
    #Execute a server
    print("🚀 Starting web server...")
    app.run(host='0.0.0.0', port=8886, debug=True)'''


