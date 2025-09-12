#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENVBIN="$ROOT_DIR/.venv/bin"
WRAP="$VENVBIN/threatlens"
ENGINE="$ROOT_DIR/threatlens.sh"

banner() {
  echo "ThreatLens CLI"
}

need_venv() {
  if [ ! -x "$VENVBIN/pip" ]; then
    echo "[-] .venv not found. Create and activate it first:" >&2
    echo "    python3 -m venv .venv && source .venv/bin/activate" >&2
    exit 1
  fi
}

cmd_deps() {
  need_venv
  bash "$ROOT_DIR/scripts/bootstrap_env.sh"
}

cmd_doctor() {
  need_venv
  local ok=true
  echo "[+] Checking tools in .venv/bin"
  for bin in katana waybackurls gauplus hakrawler httpx nuclei; do
    if [ ! -x "$VENVBIN/$bin" ] && ! command -v "$bin" >/dev/null 2>&1; then
      echo "[!] Missing: $bin"; ok=false
    else
      echo "[ok] $bin"
    fi
  done
  echo "[+] Checking Python tools in .venv"
  if ! "$VENVBIN/python" -c 'import pkgutil,sys;sys.exit(0 if pkgutil.find_loader("uro") else 1)'; then echo "[!] Missing: uro"; ok=false; else echo "[ok] uro"; fi
  if ! "$VENVBIN/python" -c 'import pkgutil,sys;sys.exit(0 if pkgutil.find_loader("paramspider") else 1)'; then echo "[!] Missing: ParamSpider"; ok=false; else echo "[ok] ParamSpider"; fi
  local tdir="$ROOT_DIR/nuclei-templates"
  if find "$tdir" -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .; then
    echo "[ok] templates present in $tdir"
  else
    echo "[!] templates missing in $tdir"
  fi
  $ok || exit 1
}

cmd_scan() {
  # Prefer wrapper if exists, else call engine directly
  local runner
  if [ -x "$WRAP" ]; then runner="$WRAP"; else runner="$ENGINE"; fi
  exec "$runner" "$@"
}

cmd_clean() {
  rm -rf "$ROOT_DIR/output" && echo "[+] Cleaned output/"
}

usage() {
  banner
  echo "Usage: ./tl <command> [args]"
  echo "Commands:"
  echo "  deps      Install requirements into existing .venv"
  echo "  doctor    Preflight checks (env/tools/templates)"
  echo "  scan      Run the scanner (forwards args to threatlens.sh)"
  echo "  clean     Remove output/"
  echo "  help      Show this help"
}

main() {
  local cmd="${1:-help}"; shift || true
  case "$cmd" in
    deps) cmd_deps "$@" ;;
    doctor) cmd_doctor "$@" ;;
    scan) cmd_scan "$@" ;;
    clean) cmd_clean ;;
    help|--help|-h) usage ;;
    *) echo "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"

