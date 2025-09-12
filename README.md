ThreatLens
===========

Brief
- Lightweight web recon orchestrator. Collects URLs (Katana, Waybackurls, Gauplus, Hakrawler, ParamSpider), deduplicates (uro), checks liveness (httpx), and scans with Nuclei. Outputs per target with JSONL findings and a short summary.

Install (local .venv only)
- Prereqs (Kali/Debian): `sudo apt update && sudo apt install -y golang-go python3-venv python3-pip jq git`
- Clone: `git clone <REPO_URL> && cd ThreatLens`
- Create env: `make env` (or `bash scripts/bootstrap_env.sh`)
- Run:
  - `./.venv/bin/threatlens -t example.com`
  - or `source .venv/activate` then `threatlens -t example.com`

Outputs
- `output/<target>/{raw,alive,results,logs}`
- `results/nuclei.jsonl`, `results/summary.{txt,json}`

Notes
- Use `--dry-run` to preview commands.
- Keep scans within authorized scope.

