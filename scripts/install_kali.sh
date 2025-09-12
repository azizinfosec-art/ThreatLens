#!/usr/bin/env bash
set -Eeuo pipefail

echo "[+] Installing ThreatLens dependencies on Kali Linux"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  SUDO=sudo
else
  SUDO=
fi

${SUDO} apt-get update -y
${SUDO} apt-get install -y --no-install-recommends \
  build-essential git curl wget jq python3 python3-pip ca-certificates \
  golang-go

# Prefer user-local installs for Python CLIs
python3 -m pip install --user --upgrade pip
python3 -m pip install --user uro paramspider

# Ensure Go paths available during this session
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

echo "[+] Installing Go-based tools via 'go install'"
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei path has changed across versions; try v3 first then v2 as fallback
if ! go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null; then
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
fi

echo "[+] Verifying installations (versions)"
command -v katana && katana -version || true
command -v waybackurls && waybackurls -version 2>/dev/null || true
command -v gauplus && gauplus -version 2>/dev/null || true
command -v hakrawler && hakrawler -version 2>/dev/null || true
command -v httpx && httpx -version || true
command -v nuclei && nuclei -version || true
command -v paramspider && paramspider -h >/dev/null 2>&1 && echo "paramspider ok" || echo "paramspider installed in ~/.local/bin"
command -v uro >/dev/null 2>&1 && echo "uro ok" || echo "uro installed in ~/.local/bin"

cat <<EOF

Done. Ensure your PATH includes Go and user-local bin paths:

  export GOPATH=
  export PATH=\$PATH:\$GOPATH/bin:\$HOME/.local/bin

You can add these lines to your shell profile (e.g., ~/.bashrc) for persistence.

Then run:

  ./threatlens.sh -t example.com

EOF

