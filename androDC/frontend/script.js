import {
  AdbDaemonWebUsbDeviceManager,
  AdbDaemonWebUsbDevice,
} from "https://cdn.jsdelivr.net/npm/@yume-chan/adb-daemon-webusb/+esm";
import {
  AdbDaemonTransport,
  Adb,
} from "https://cdn.jsdelivr.net/npm/@yume-chan/adb/+esm";
import AdbWebCredentialStore from "https://cdn.jsdelivr.net/npm/@yume-chan/adb-credential-web/+esm";
import { TextDecoderStream } from "https://cdn.jsdelivr.net/npm/@yume-chan/stream-extra/+esm";

// ADB Manager Setup
const manager = AdbDaemonWebUsbDeviceManager.BROWSER;
const credentialStore = new AdbWebCredentialStore("MyBrowserADBKey");
let selectedPackage;
let adb;
let device;
let transport;

function appendOutput(message) {
  const outputBox = document.getElementById("outputBox");
  const newLine = document.createElement("div");
  newLine.textContent = message;
  outputBox.appendChild(newLine);
  outputBox.scrollTop = outputBox.scrollHeight;
}
let flutter_yn = false;
let previousLogs = new Set();
const SENTINEL = "Select application";

setInterval(async () => {
  const pkg = (document.getElementById("app-select")?.value || "").trim();
  const opts =
    !pkg || pkg === SENTINEL
      ? {}
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ package: pkg, timeout: 10, only_updates: 1 }),
        };

  const res = await fetch("/get_log", opts);
  if (!res.ok || res.status === 204) return;

  const data = await res.json().catch(() => ({}));
  const lines = Array.isArray(data) ? data : data.output || data.logs || [];
  (lines || []).forEach(appendOutput);
}, 1000);

window.connect = async function (device) {
  try {
    return await device.connect();
  } catch (error) {
    if (error instanceof AdbDaemonWebUsbDevice.DeviceBusyError) {
      console.log(
        "The device is already in use by another program. Please close the program and try again."
      );
    }
    // It might also throw other errors
    throw error;
  }
};

window.connectAdb = async function () {
  const outputBox = document.getElementById("outputBox");
  outputBox.innerHTML = "";
  try {
    // 1) Pick device & connect (must be called directly from a click handler)
    device = await manager.requestDevice();
    if (!device) {
      alert("❌ No device selected, Plesae confirm the connection.");
      return;
    }

    const devices = await manager.getDevices();
    if (!devices.length) {
      alert("❌ No device connected");
      return;
    }

    device = devices[0];
    const connection = await connect(device);

    // 2) If user hasn’t confirmed USB debugging yet, show a gentle reminder (don’t fail)
    const reminderId = setTimeout(() => {
      appendOutput("⏳ Please confirm 'Allow USB debugging' on your phone…");
    }, 10000);

    try {
      // 3) Authenticate (wait until user approves on the phone)
      transport = await AdbDaemonTransport.authenticate({
        serial: device.serial ?? "my-device",
        connection,
        credentialStore,
      });
    } finally {
      clearTimeout(reminderId);
    }
    //appendOutput("✅ Authenticated with ADB");

    // 4) Create ADB client
    adb = new Adb(transport);
    appendOutput("✅ ADB Connection established");

    // 5) Show device model
    const model = (
      await adb.subprocess.noneProtocol.spawnWaitText(
        "getprop ro.product.model"
      )
    ).trim();
    //appendOutput(`📱 Android device model: ${model}`);

    // 6) Populate device-select
    const select = document.getElementById("device-select");
    select.innerHTML = "";
    const modelOpt = document.createElement("option");
    modelOpt.textContent = model;
    modelOpt.value = model;
    select.appendChild(modelOpt);
    select.disabled = false;

    // 7) List user-installed packages and populate app-select
    const packagesRaw = await adb.subprocess.noneProtocol.spawnWaitText(
      "pm list packages -3"
    );
    const packages = packagesRaw
      .split("\n")
      .map((p) => p.replace("package:", "").trim())
      .filter(Boolean)
      .sort();

    appendOutput(`📦 Found ${packages.length} packages. Select APK.\n`);

    const appSelect = document.getElementById("app-select");
    appSelect.innerHTML = "";
    const defaultOption = document.createElement("option");
    defaultOption.textContent = "Select application";
    defaultOption.value = "";
    defaultOption.disabled = true;
    defaultOption.selected = true;
    appSelect.appendChild(defaultOption);

    for (const pkg of packages) {
      const opt = document.createElement("option");
      opt.textContent = pkg;
      opt.value = pkg;
      appSelect.appendChild(opt);
    }
    appSelect.disabled = false;
  } catch (e) {
    console.error("❌ Failed to connect:", e);
    alert(
      "An error occurred: " +
        e.message +
        "\n1. Try running on your laptop:\n    adb kill-server\n2. Confirm the connection between kali and android phone"
    );
  }
};

window.proxyIP = "";

window.validateProxyIP = async function (ip) {
  const ipv4PortRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/;
  const ipv6PortRegex = /^\[?([a-fA-F0-9:]+)\]?:\d{1,5}$/;
  return ipv4PortRegex.test(ip) || ipv6PortRegex.test(ip);
};

window.appendOutput = async function (msg) {
  const output = document.getElementById("outputBox");
  output.innerHTML += `<div>${msg}</div>`;
  output.scrollTop = output.scrollHeight;
};

window.UploadAPK = async function () {
  
  flutter_yn = false;
  selectedPackage = document.getElementById("app-select").value;

  if (!selectedPackage || selectedPackage === "Select application") {
    alert("Please select an application first.");
    return;
  }

  try {
    const pathResult = await adb.subprocess.noneProtocol.spawnWaitText(
      `pm list packages -f | grep ${selectedPackage}`
    );

    const apkPath2 = pathResult.trim().split(":")[1];
    const apkPath = apkPath2.replace("=" + selectedPackage, "").trim();
    const apkp = pathResult.trim().split(":")[1];
    const libpath = apkp.substring(0, apkp.indexOf("base.apk")) + "lib";
    

    const ip_field = document.getElementById("proxy-ip");
    if (ip_field.value == "") {
      alert("❗️ Enter your proxy IP, then select the application again.");
      appendOutput(
        "❗️ Enter your proxy IP, then select the application again."
      );
      ip_field.focus({ preventScroll: true });
      const selectedPackage2 = document.getElementById("app-select");
      selectedPackage2.selectedIndex = 0;
      return;
    }


    const flutter_check = await adb.subprocess.noneProtocol.spawnWaitText(
      `cd ${libpath} && find . -name libflutter.so`
    );
    if (flutter_check.includes("libflutter.so")) {
      appendOutput("✅ Flutter app detected. will proceed with pinning bypass.");
      flutter_yn = true;
    } else {
      appendOutput("🔧 No Flutter engine found (Not a Flutter app)");
      flutter_yn = false;
    }
    

    window.proxyIP = document.getElementById("proxy-ip").value.trim();
    appendOutput(`🌏 Proxy IP ${window.proxyIP} was set.`);

    //disconnect for connection on the server-side
    try {
      const devices = await manager.getDevices();
      device = devices[0];
      device.raw.forget();
      console.log("✅ USB device closed. will work on a backend(laptop).");
      appendOutput(
        "✅ Sending APK path and connection will work on a backend(laptop)."
      );
      const response = await fetch("/pull_apk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apkPath, selectedPackage, flutter_yn, proxyIP }),
      });
      const result = await response.json();

      if (result.status === "started") {
        appendOutput(
          `🚀 Started APK processing...\nSaved to: ${result.apk_path}`
        );
      } else {
        appendOutput(
          `❌ Failed to start APK processing: ${
            result.error || "Unknown error"
          }`
        );
      }
    } catch (err) {
      console.error("UploadAPK error:", err);
      alert("❌ Server error: " + err.message);
    }
  } catch (e) {
    document.getElementById(
      "outputBox"
    ).textContent = `❌ Error: ${e.message}`;
    alert("❌ Error: access https://127.0.0.1:5000 again to set up adb again");
  }
};


window.rooting = async function rooting() {
  const selectedPackage = document.getElementById("app-select").value;
  if (!selectedPackage || selectedPackage === "Select application") {
    alert("Please select a package first.");
    return;
  }
  appendOutput("🚀 Started Rooting Bypass");

  fetch("/root_check", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ package: selectedPackage }),
  })
    .then((res) => res.json())
    .then((data) => {
      appendOutput("✅ " + data.message);
      if (data.detail) appendOutput(data.detail);
    })
    .catch((err) =>
      appendOutput("❌ Failed to start Rooting bypass: " + err.message)
    );
};

window.tampering = async function tampering() {
  const selectedPackage = document.getElementById("app-select").value;
  if (!selectedPackage || selectedPackage === "Select application") {
    alert("Please select a package first.");
    return;
  }
  appendOutput("🚀 Started Tampering Bypass");
  
  
  fetch("/tampering_check", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ package: selectedPackage, flutter_yn: flutter_yn}),
  })
    .then((res) => res.json())
    .then((data) => {
      appendOutput("✅ " + data.message);
      if (data.detail) appendOutput(data.detail);
    })
    .catch((err) =>
      appendOutput("❌ Failed to start Tampering bypass: " + err.message)
    );
};

function fetchPinningLogs() {
  fetch("/pinning_logs")
    .then((response) => response.json())
    .then((data) => {
      document.getElementById("outputBox").textContent = data.logs;
    });
}

window.pinning = async function pinning() {
  const selectedPackage = document.getElementById("app-select").value;
  if (!selectedPackage || selectedPackage === "Select application") {
    alert("Please select a package first.");
    return;
  }

  //Flutter check
  

  //IP check
  const ip_field = document.getElementById("proxy-ip");
  if (ip_field.value == "") {
    alert("❗️ Enter your proxy IP, then select the application again.");
    appendOutput("❗️ Enter your proxy IP, then select the application again.");
    ip_field.focus({ preventScroll: true });
    const selectedPackage2 = document.getElementById("app-select");
    selectedPackage2.selectedIndex = 0;
    return;
  }
  fetch("/pinning_bypass", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      package: selectedPackage,
      ip: ip_field.value,
      flutter: flutter_yn,
    }),
  })
    .then((response) => response.json())
    .then((data) => {
      document.getElementById("outputBox").textContent =
        "Started pinning bypass...\n";

      const intervalId = setInterval(() => {
        fetchPinningLogs();
      }, 2000);

      setTimeout(() => {
        clearInterval(intervalId);
      }, 30000);
    });
};
