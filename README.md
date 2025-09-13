ThreatLens
===========

Overview
- Lightweight recon → normalize → inputs-only → prioritize → (optional) probe → DAST orchestrator.
- Collects URLs from multiple sources, deduplicates/normalizes, extracts GET inputs, prioritizes, and optionally scans with nuclei.
- Version: v0.2.2

Key Features
- Multi-source collectors: katana, waybackurls, gauplus, hakrawler, paramspider (configurable via `--sources`).
- Normalization + dedupe: `uro` pipeline to collapse duplicates.
- Inputs extraction: GET URLs with parameters into `inputs_get.txt` and optional `fuzz_get.txt`.
- Prioritization: heuristic ranking (`inputs_ranked.txt`) with optional httpx meta re-rank (`--rerank`).
- Target shaping: cap first wave per host (`--top-per-host N`).
- Scanning: nuclei integration with pass-through args (`--nuclei-args`), JSONL output and optional HTML report (`--html-report`).
- Workflow control: phases (`--phase collect|live|scan|all`), resume (`--resume`), parallel targets (`--parallel N`).

Install

Option A — System install (Linux/macOS)
- Linux/macOS: `bash scripts/install.sh`
- Kali (convenience): `bash scripts/install_kali.sh`
- Places `threatlens` in `/usr/local/bin` and installs required tools (Go+Python CLIs).

Option B — User‑local venv (recommended for dev)
- Prereqs (Debian/Kali): `sudo apt update && sudo apt install -y golang-go python3-venv python3-pip jq git`
- Clone: `git clone https://github.com/azizinfosec-art/ThreatLens.git && cd ThreatLens`
- Create and activate venv:
  - `python3 -m venv .venv`
  - `source .venv/bin/activate`
- Bootstrap tools into `.venv/bin`:
  - `bash scripts/bootstrap_env.sh`
  - Optional helper: `./tl deps` (wraps the same bootstrap)
- Preflight: `./tl doctor`

Quick Start
- Inputs only (GET URLs):
  - `./threatlens.sh -t example.com --inputs-only`
- Inputs + FUZZ list:
  - `./threatlens.sh -t example.com --inputs-only --fuzzify`
- Full pipeline with recommended nuclei args:
  - `./threatlens.sh -t example.com --threads 80 \
      --nuclei-args "-dast -tags xss,sqli,lfi,redirect,ssrf -severity medium,high,critical -rl 50 -c 50"`
- Prioritize with re-rank and cap per host:
  - `./threatlens.sh -t example.com --rerank --top-per-host 200`
- Use custom input list for nuclei:
  - `./threatlens.sh -t example.com --phase scan \
      --nuclei-input urls_with_params.txt --nuclei-args "-dast -tags sqli,xss"`
- Parallelize across targets list:
  - `./threatlens.sh -l examples/targets.txt --parallel 5 --threads 80`

Important Flags
- `--sources CSV`: pick sources, default `katana,wayback,gau,hakrawler` (allow: `katana,wayback,gau,hakrawler,paramspider`).
- `--phase`: `collect | live | scan | all` (default `all`).
- `--scan-raw`: feed deduped URLs to nuclei directly (skip httpx/alive set).
- `--rerank`: add a lightweight rank boost from httpx metadata (needs `jq`).
- `--top-per-host N`: cap first-wave candidates per host.
- `--nuclei-args "..."`: passed verbatim to nuclei.
- `--html-report`: render a simple HTML table from nuclei JSONL (needs `jq`).
- `--resume`: reuse existing artifacts when present.
- `--dry-run`: print commands, do not execute.

Outputs
- Per target: `output/<target>/{raw,alive,results,logs}`
- Core artifacts:
  - `urls.deduped.txt`
  - `results/inputs_get.txt`
  - `results/inputs_ranked.txt` and optionally `results/inputs_ranked.v2.txt`, `results/inputs_ranked.top.txt`
  - If nuclei runs: `results/nuclei.jsonl`, `results/summary.{txt,json}`, optional `results/nuclei.html`

Examples
- Basic single target: `examples/01_basic_single_target.sh`
- Targets list: `examples/02_targets_list.sh`
- Include subs + threads: `examples/03_include_subs_threads.sh`
- Custom templates dir: `examples/04_custom_templates_dir.sh`
- Dry run with nuclei args: `examples/05_dry_run_with_nuclei_args.sh`

Windows Notes
- Prefer WSL (Ubuntu/Kali) for best compatibility. From PowerShell:
  - `wsl bash -lc 'cd /mnt/c/Users/<you>/ThreatLens && bash scripts/install.sh && threatlens -t example.com --inputs-only'`
- Git Bash can work if Go/Python tools are in the PATH; some collectors may behave differently on native Windows.

Troubleshooting
- Missing tools: run `./tl deps` (venv) or `bash scripts/install.sh` (system). Then `./tl doctor`.
- Zero results: expand `--sources`, try another target, or verify network access. Inspect `output/<target>/raw/*.txt`.
- Long first run: nuclei templates update and collectors may take time; subsequent runs are faster.
- Dry-run: prints commands only; artifacts will be empty by design.

Legal
- For authorized security testing only. Respect scope and local laws.
