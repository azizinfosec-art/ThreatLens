#!/usr/bin/env bash
set -Eeuo pipefail

# Create a local, isolated toolchain in .venv (no system PATH changes)
# - Go tools installed to .venv/bin via GOBIN
# - Python tools installed into a venv at .venv/py
# - Wrapper placed at .venv/bin/threatlens that sets PATH and executes repo script

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
BIN_DIR="$VENV_DIR/bin"
PY_DIR="$VENV_DIR/py"

mkdir -p "$BIN_DIR"

echo "[+] Preparing Python virtual environment at $PY_DIR"
python3 -m venv "$PY_DIR"
"$PY_DIR/bin/pip" install --upgrade pip wheel setuptools >/dev/null

echo "[+] Installing Python tools (uro, ParamSpider)"
if ! "$PY_DIR/bin/pip" install uro >/dev/null 2>&1; then
  echo "[!] PyPI 'uro' install failed, trying from git..."
  "$PY_DIR/bin/pip" install "git+https://github.com/s0md3v/uro.git" >/dev/null
fi
# ParamSpider is not published on PyPI; install from GitHub
if ! "$PY_DIR/bin/pip" install "git+https://github.com/devanshbatham/ParamSpider.git" >/dev/null 2>&1; then
  echo "[-] Failed to install ParamSpider from GitHub. Please ensure 'git' and internet access are available." >&2
  exit 1
fi

echo "[+] Preparing Go local toolchain under $VENV_DIR"
export GOPATH="$VENV_DIR/go"
export GOBIN="$BIN_DIR"
export PATH="$BIN_DIR:$PY_DIR/bin:$PATH"

if ! command -v git >/dev/null 2>&1; then
  echo "[-] Git is not installed. On Kali: sudo apt-get install git" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "[-] Go is not installed. On Kali: sudo apt-get install golang-go" >&2
  exit 1
fi

echo "[+] Installing Go-based tools into $BIN_DIR"
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
if ! go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null; then
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
fi

echo "[+] Writing activation script: $VENV_DIR/activate"
cat > "$VENV_DIR/activate" <<'ACT'
# shellcheck shell=bash
VENV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GOPATH="$VENV_ROOT/go"
export PATH="$VENV_ROOT/bin:$VENV_ROOT/py/bin:$PATH"
echo "(.venv) environment active"
ACT

echo "[+] Writing wrapper: $BIN_DIR/threatlens"
cat > "$BIN_DIR/threatlens" <<'WRAP'
#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export GOPATH="$REPO_ROOT/.venv/go"
export PATH="$REPO_ROOT/.venv/bin:$REPO_ROOT/.venv/py/bin:$PATH"
exec "$REPO_ROOT/threatlens.sh" "$@"
WRAP
chmod +x "$BIN_DIR/threatlens"

echo "[+] Done. Use one of the following options:\n"
echo "Option A: ephemeral"
echo "  $ $BIN_DIR/threatlens -t example.com"
echo "\nOption B: activate and run"
echo "  $ source $VENV_DIR/activate"
echo "  (.venv) $ threatlens -t example.com"
