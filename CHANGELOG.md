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

