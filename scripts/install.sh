#!/usr/bin/env bash
set -Eeuo pipefail

echo "[+] Installing ThreatLens and dependencies"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  SUDO=sudo
else
  SUDO=
fi

OS_UNAME=$(uname -s || true)

install_debian_like() {
  ${SUDO} apt-get update -y
  ${SUDO} apt-get install -y --no-install-recommends \
    build-essential git curl wget jq python3 python3-pip ca-certificates \
    golang-go

  python3 -m pip install --user --upgrade pip
  python3 -m pip install --user uro paramspider

  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/bp0lr/gauplus@latest
  go install github.com/hakluke/hakrawler@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  if ! go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null; then
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  fi

  ${SUDO} install -m 0755 threatlens.sh /usr/local/bin/threatlens
}

install_macos() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required. Install from https://brew.sh" >&2
    exit 1
  fi
  brew update
  brew install go jq python git
  python3 -m pip install --user --upgrade pip
  python3 -m pip install --user uro paramspider

  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/bp0lr/gauplus@latest
  go install github.com/hakluke/hakrawler@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  if ! go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null; then
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  fi

  ${SUDO} install -m 0755 threatlens.sh /usr/local/bin/threatlens
}

if [ "${OS_UNAME}" = "Linux" ] && [ -f /etc/os-release ]; then
  . /etc/os-release
  if echo "${ID} ${ID_LIKE:-}" | grep -qiE "debian|ubuntu|kali"; then
    install_debian_like
  else
    echo "Unsupported Linux distribution. Please install dependencies manually." >&2
    exit 1
  fi
elif [ "${OS_UNAME}" = "Darwin" ]; then
  install_macos
else
  echo "Unsupported OS: ${OS_UNAME}. Please install dependencies manually." >&2
  exit 1
fi

cat <<EOF

Setup complete.

Ensure PATH includes Go and user-local bin paths for your shell session:
  export GOPATH=
  export PATH=\$PATH:\$GOPATH/bin:\$HOME/.local/bin

You can add these lines to ~/.bashrc or ~/.zshrc.

Now run:
  threatlens -t example.com

EOF

