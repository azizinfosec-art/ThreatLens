#!/usr/bin/env bash
set -Eeuo pipefail

# Install all requirements into an already-created Python venv at .venv
# User must create .venv: python3 -m venv .venv

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
BIN_DIR="$VENV_DIR/bin"

if [ ! -x "$BIN_DIR/pip" ]; then
  echo "[-] .venv not found. Please create it first:"
  echo "    python3 -m venv .venv && source .venv/bin/activate"
  exit 1
fi

echo "[+] Upgrading pip/setuptools/wheel in .venv"
"$BIN_DIR/pip" install --upgrade pip wheel setuptools >/dev/null

echo "[+] Installing Python tools (uro, ParamSpider) into .venv"
if ! "$BIN_DIR/pip" install uro >/dev/null 2>&1; then
  echo "[!] PyPI 'uro' install failed, trying from git..."
  "$BIN_DIR/pip" install "git+https://github.com/s0md3v/uro.git" >/dev/null
fi
if ! "$BIN_DIR/pip" install "git+https://github.com/devanshbatham/ParamSpider.git" >/dev/null 2>&1; then
  echo "[-] Failed to install ParamSpider from GitHub. Ensure 'git' and internet access are available." >&2
  exit 1
fi

echo "[+] Preparing Go local toolchain under .venv"
export GOPATH="$VENV_DIR/go"
export GOBIN="$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

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

echo "[+] Writing wrapper: $BIN_DIR/threatlens"
cat > "$BIN_DIR/threatlens" <<'WRAP'
#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export GOPATH="$REPO_ROOT/.venv/go"
export PATH="$REPO_ROOT/.venv/bin:$PATH"
exec "$REPO_ROOT/threatlens.sh" "$@"
WRAP
chmod +x "$BIN_DIR/threatlens"

echo "[+] Done. Activate your venv and run:"
echo "    source .venv/bin/activate"
echo "    threatlens -t example.com"
