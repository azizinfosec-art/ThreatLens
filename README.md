ThreatLens
===========

Brief
- Lightweight web recon orchestrator. Collects URLs (Katana, Waybackurls, Gauplus, Hakrawler, ParamSpider), deduplicates (uro), and extracts GET-parameterized inputs for DAST. You can run nuclei directly from this tool (via `--nuclei-args`) or outside it. Outputs per target with a concise summary.

Install (user creates .venv)
- Prereqs (Kali/Debian): `sudo apt update && sudo apt install -y golang-go python3-venv python3-pip jq git`
- Clone: `git clone https://github.com/azizinfosec-art/ThreatLens.git && cd ThreatLens`
- Create venv (user action):
  - `python3 -m venv .venv`
  - `source .venv/bin/activate`
- Install requirements into .venv:
  - `./tl deps`
- Run (common patterns):
  - Inputs only (GET URLs): `./threatlens.sh -t example.com --inputs-only`
  - Inputs + FUZZ list: `./threatlens.sh -t example.com --inputs-only --fuzzify`
  - Full pipeline with nuclei (recommended args):
    - `./threatlens.sh -t example.com --phase all --threads 80 \
       --nuclei-args "-dast -tags xss,sqli,lfi,redirect,ssrf -severity low,medium,high,critical -rl 50 -c 50"`
  - Custom nuclei list: `./threatlens.sh -t example.com --phase scan \
       --nuclei-input urls_with_params.txt --nuclei-args "-dast -tags sqli,xss"`

Outputs
- `output/<target>/{raw,alive,results,logs}`
- `results/inputs_get.txt` (GET URLs) and optionally `results/fuzz_get.txt`
- If nuclei is used: `results/nuclei.jsonl`, `results/summary.{txt,json}`

GET Inputs Mode
- Produce GET-parameterized inputs only (stop after extraction):
  - `./threatlens.sh -t example.com --inputs-only`
- Also produce a FUZZ list for fuzz-oriented templates/tools:
  - `./threatlens.sh -t example.com --inputs-only --fuzzify`
- Full pipeline (recommendation for nuclei args):
  - `./threatlens.sh -t example.com --phase all --threads 80 \
     --nuclei-args "-dast -tags xss,sqli,lfi,redirect,ssrf -severity low,medium,high,critical -rl 50 -c 50"`
- Use a custom list for nuclei and skip extraction:
  - `./threatlens.sh -t example.com --phase scan \
     --nuclei-input urls_with_params.txt --nuclei-args "-dast -tags sqli,xss"`

Notes
- Use `--dry-run` to preview commands.
- Keep scans within authorized scope.
