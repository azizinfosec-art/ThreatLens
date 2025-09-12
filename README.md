ThreatLens
===========

```
==============================
 ThreatLens - Recon Orchestrator
==============================
```

Lightweight, scriptable web recon and scan orchestrator.

ThreatLens collects URLs from multiple sources, deduplicates them, checks liveness, and runs Nuclei to identify vulnerabilities. It structures output per target, produces JSONL findings and a concise summary with severity counts, and supports a dry‑run mode for safe previews.

Features
- URL collection: Katana, Waybackurls, Gauplus, Hakrawler, ParamSpider
- Deduplication with `uro`
- Liveness check via `httpx`
- Vulnerability scanning using `nuclei` (JSONL output)
- Template update before scan (`nuclei -ut -ud <templates>`)
- Strict bash mode and safe temp handling
- Dry‑run (`--dry-run`) to print commands
- Structured output: `./output/<target>/{raw,alive,results,logs}`
- Summary: counts, severities, and timings

Installation
- Dependencies (CLI tools):
  - `katana`, `waybackurls`, `gauplus`, `hakrawler`, `paramspider`, `uro`, `httpx`, `nuclei`, `jq`
- Clone and make executable:
  - `git clone <this-repo-url>`
  - `cd ThreatLens`
  - `chmod +x threatlens.sh`
- Optional: install globally (Linux/macOS):
  - `sudo install -m 0755 threatlens.sh /usr/local/bin/threatlens`

Quick Start
- Single target domain:
  - `./threatlens.sh -t example.com`
- Targets from file:
  - `./threatlens.sh -l targets.txt --include-subs`

Usage
- `./threatlens.sh [options] (-t <target> | -l targets.txt)`
- Targets can be domains or URLs. Each target gets its own directory under `./output`.

Key Options
- `-t, --target VALUE`  Add a target (repeatable)
- `-l, --list FILE`     Read targets (one per line)
- `-o, --outdir DIR`    Root output directory (default: `./output`)
- `--templates-dir DIR` Path for nuclei templates (default: `./nuclei-templates`)
- `--include-subs`      Include subdomains where supported
- `--httpx-codes LIST`  Status codes considered alive (default common set)
- `--threads N`         Concurrency (default: 50)
- `--nuclei-args "..."` Extra args passed to nuclei (quoted)
- `--dry-run`           Print commands without executing

Outputs
- `raw/`     Raw aggregated URLs from each collector
- `urls.deduped.txt`  Unified, deduped URLs (via `uro`)
- `alive/alive.txt`    Liveness-checked URLs (via `httpx`)
- `results/nuclei.jsonl`   Nuclei findings (JSONL)
- `results/summary.txt`    Human-readable summary
- `results/summary.json`   Machine-readable summary
- `logs/threatlens.log`    Per-target log (also mirrors to `<target>.log`)

Examples
- See `examples/` for sample commands.

Best Practices
- Keep your nuclei templates up to date (ThreatLens runs `-ut -ud` automatically).
- Start with `--dry-run` to validate scope before executing.
- Use `--include-subs` thoughtfully; it can dramatically increase scope and time.
- Pin `--nuclei-args` such as `-severity high,critical` when triaging high-signal findings.

Troubleshooting
- Missing tools: ensure all dependencies are in `PATH`.
- ParamSpider issues: verify Python environment and its CLI is installed.
- Empty results: check `logs/threatlens.log` under the target directory.
- Very large scopes: reduce `--threads` or split targets into smaller sets.
- JSON parsing: `jq` is required for severity counts in the summary.

Security Notes
- Validate scope ownership and authorization before scanning.
- Store outputs securely if they may contain sensitive URLs or data.

License
- See `LICENSE` in this repository.
