#!/usr/bin/env sh
set -eu

# ========== Logging helpers ==========
log()  { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" 1>&2; }

# ========== Kali APT key & sources quick-fix ==========
fix_kali_apt_keys() {
  log "Fixing Kali APT key & sources..."
  sudo apt-get install -y --no-install-recommends curl gnupg ca-certificates
  sudo tee /etc/apt/sources.list >/dev/null <<'EOF'
deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] http://http.kali.org/kali kali-rolling main non-free non-free-firmware contrib
EOF
  sudo rm -f /usr/share/keyrings/kali-archive-keyring.gpg
  curl -fsSL https://archive.kali.org/archive-key.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg
  sudo apt-get clean
  sudo rm -rf /var/lib/apt/lists/*
}

# ========== APT install wrapper (PEP 668 safe) ==========
apt_install_kali() {
  if ! sudo apt-get update; then
    fix_kali_apt_keys
    sudo apt-get update
  fi
  sudo env PIP_BREAK_SYSTEM_PACKAGES=1 apt-get install -y "$@"
}

# ========== macOS: Android SDK(cmdline-tools) Setting ==========
setup_android_sdk_macos() {
  if ! command -v sdkmanager >/dev/null 2>&1; then
    brew install --cask android-commandlinetools || true
  fi
  : "${ANDROID_SDK_ROOT:=$HOME/Library/Android/sdk}"
  mkdir -p "$ANDROID_SDK_ROOT" "$HOME/.android"
  [ -f "$HOME/.android/repositories.cfg" ] || touch "$HOME/.android/repositories.cfg"
  for d in \
    "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin" \
    /opt/homebrew/share/android-commandlinetools/bin \
    /usr/local/share/android-commandlinetools/bin \
    /opt/homebrew/Caskroom/android-commandlinetools/latest/cmdline-tools/bin \
    /usr/local/Caskroom/android-commandlinetools/latest/cmdline-tools/bin
  do [ -d "$d" ] && PATH="$d:$PATH"; done
  yes | sdkmanager --licenses >/dev/null 2>&1 || true
  sdkmanager "platform-tools" "build-tools;34.0.0" || true
  [ -d "$ANDROID_SDK_ROOT/platform-tools" ] && PATH="$ANDROID_SDK_ROOT/platform-tools:$PATH"
  export ANDROID_SDK_ROOT PATH
  SHELL_RC="$HOME/.zshrc"; [ -n "${SHELL:-}" ] && echo "$SHELL" | grep -qi bash && SHELL_RC="$HOME/.bashrc"
  if ! grep -q "ANDROID_SDK_ROOT" "$SHELL_RC" 2>/dev/null; then
    {
      echo ""; echo "# Android SDK (added by setup.sh)"
      echo "export ANDROID_SDK_ROOT=\"$ANDROID_SDK_ROOT\""
      echo "export PATH=\"\$ANDROID_SDK_ROOT/platform-tools:\$PATH\""
      echo "export PATH=\"\$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:\$PATH\""
    } >> "$SHELL_RC"
  fi
  command -v adb >/dev/null 2>&1 || warn "adb not on PATH yet; open a new shell or source your RC."
}

# ========== OS ==========
OS="$(uname)"
log "Installing required Android tools..."
if [ "$OS" = "Darwin" ]; then
  command -v brew >/dev/null 2>&1 || err "Install Homebrew first: https://brew.sh/"
  setup_android_sdk_macos
  log "Note: apktool install → https://apktool.org/docs/install"
elif [ "$OS" = "Linux" ]; then
  apt_install_kali aapt adb apksigner zipalign
  log "apktool install → https://apktool.org/docs/install"
fi

# ========== Settings ==========
set -e

V=2.11.0
apt install -y wget default-jdk default-jre
cp ./static/tools/apktool.jar /usr/local/bin/apktool.jar
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool
echo "[+] Apktool $V installed"

: "${PYENV_PYTHON:=3.11.13}"   
VENV_DIR="${VENV_DIR:-.venv}"  
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-requirements.txt}"
FLASK_APP_PATH="${FLASK_APP_PATH:-server/app.py}"
: "${PORT:=5000}"

# ========== Install Java if missing ==========
install_java() {
  command -v java >/dev/null 2>&1 && { log "Java is already installed."; return; }
  log "Java not found. Installing..."
  if [ "$OS" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    brew install openjdk
    if [ -d "/opt/homebrew/opt/openjdk/bin" ]; then
      export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
      grep -q 'opt/openjdk/bin' "$HOME/.zshrc" 2>/dev/null || echo 'export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"' >> "$HOME/.zshrc"
    fi
  elif [ "$OS" = "Linux" ] && command -v apt-get >/dev/null 2>&1; then
    apt_install_kali default-jdk
  else
    err "Could not detect package manager. Please install Java manually."
  fi
  log "Java installed successfully."
}
install_java

# ========== Pyenv + Python 3.11 bootstrap ==========
ensure_pyenv_311() {
  export PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
  export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"

  if ! command -v pyenv >/dev/null 2>&1; then
    log "pyenv not found. Installing…"
    if [ "$OS" = "Linux" ] && command -v apt-get >/dev/null 2>&1; then
      apt_install_kali make build-essential libssl-dev zlib1g-dev \
        libbz2-dev libreadline-dev libsqlite3-dev curl llvm \
        libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev \
        libffi-dev liblzma-dev git
    fi
    curl -fsSL https://pyenv.run | bash
    export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"
  fi

  pyenv install -s "$PYENV_PYTHON"
  pyenv local "$PYENV_PYTHON"
  hash -r

  log "pyenv python -> $(command -v python) ($(python -V 2>&1))"

  
  SHELL_RC="$HOME/.zshrc"; [ -n "${SHELL:-}" ] && echo "$SHELL" | grep -qi bash && SHELL_RC="$HOME/.bashrc"
  if ! grep -q 'PYENV_ROOT=.*/.pyenv' "$SHELL_RC" 2>/dev/null; then
    {
      echo ''
      echo '# >>> pyenv (added by setup.sh) >>>'
      echo 'export PYENV_ROOT="$HOME/.pyenv"'
      echo 'export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"'
      echo '# <<< pyenv <<<'
    } >> "$SHELL_RC"
  fi
}
ensure_pyenv_311

# ========== Create/Recreate virtual environment (must be 3.11) ==========
need_recreate=0
if [ -d "$VENV_DIR" ]; then
  if ! "$VENV_DIR/bin/python" -c 'import sys; exit(0 if sys.version_info[:2]==(3,11) else 1)'; then
    warn "Existing venv is not Python 3.11 → recreating."
    need_recreate=1
  fi
else
  need_recreate=1
fi

if [ "$need_recreate" -eq 1 ]; then
  rm -rf "$VENV_DIR"
  python -m venv "$VENV_DIR" || {  
    python -m ensurepip --upgrade
    python -m venv "$VENV_DIR"
  }
fi

# shellcheck disable=SC1090
. "$VENV_DIR/bin/activate"

# ========== Install Python packages (STRICT: requirements.txt only) ==========
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel setuptools
if [ -f "$REQUIREMENTS_FILE" ]; then
  log "Installing from $REQUIREMENTS_FILE..."
  "$VENV_DIR/bin/python" -m pip install -r requirements.txt
  "$VENV_DIR/bin/python" -m pip install frida==16.1.4
  "$VENV_DIR/bin/python" -m pip install frida-tools==12.3.0
  echo "$VENV_DIR/bin/python -m pip install -r requirements.txt"
else
  err "$REQUIREMENTS_FILE not found. Add it or set REQUIREMENTS_FILE env var."
  exit 1
fi

# ========== Run Flask ==========
[ -f "$FLASK_APP_PATH" ] || { err "Flask app file not found at $FLASK_APP_PATH."; exit 1; }

export FLASK_APP="$FLASK_APP_PATH"
log "Starting Flask on http://127.0.0.1:$PORT"
exec "$VENV_DIR/bin/python" -m flask --app "$FLASK_APP" --debug run --host 0.0.0.0 --port "$PORT"
