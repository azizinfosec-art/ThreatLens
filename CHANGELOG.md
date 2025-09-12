# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-09-12
- Rename and refactor tool as "ThreatLens".
- Add strict bash mode (`set -Eeuo pipefail`).
- Safe temp handling via `mktemp -d` + `trap`.
- Add `--dry-run` mode to print commands.
- Per-target structured outputs: `./output/<target>/{raw,alive,results,logs}`.
- Nuclei JSONL output and machine-readable + human summary.
- Template update before scan (`nuclei -ut -ud <templates-dir>`).
- Document installation, usage, troubleshooting, and best practices.
- Provide examples and Makefile with common targets.

## [0.2.0] - 2025-09-12
- Add GET-focused inputs phase:
  - `--inputs-only` produces `results/inputs_get.txt` and exits with summary.
  - `--fuzzify` also produces `results/fuzz_get.txt` by replacing values with `FUZZ`.
- Default scan input now prefers `results/inputs_get.txt` (unless `--scan-raw` or `--nuclei-input` is provided).
- Keep nuclei options user-supplied via `--nuclei-args`.
