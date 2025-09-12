#!/usr/bin/env bash
set -euo pipefail
./threatlens.sh -t example.com --dry-run --nuclei-args "-severity high,critical -rate-limit 200"

