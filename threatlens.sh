#!/usr/bin/env bash

# ThreatLens - lightweight web recon + scan orchestrator
# Core: URL collection -> dedupe -> liveness -> nuclei

set -Eeuo pipefail

TOOL_NAME="ThreatLens"
VERSION="0.1.0"

# Globals configured by flags
OUTDIR_ROOT="./output"
TARGETS=()
TARGETS_FILE=""
TEMPLATES_DIR="./nuclei-templates"
HTTPX_MATCH_CODES="200,204,301,302,307,401,403"
INCLUDE_SUBS=false
DRY_RUN=false
THREADS=50
NUCLEI_EXTRA_ARGS=()

# Runtime globals
WORKDIR=""
START_TS="$(date +%s)"

ascii_art() {
  cat << 'EOF'
==============================
 ThreatLens - Recon Orchestrator
==============================
EOF
}

log() { # level, message
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  {
    echo "[$ts] [$level] $msg" >> "$WORKDIR/logs/$TOOL_BASENAME.log" 2>/dev/null || true
    echo "[$ts] [$level] $msg" >> "$WORKDIR/logs/threatlens.log" 2>/dev/null || true
  } || true
}

die() { echo "Error: $*" >&2; exit 1; }

run() { # print+run (honors dry-run)
  echo "+ $*" | tee -a "$WORKDIR/logs/$TOOL_BASENAME.log" >/dev/null
  if [ "$DRY_RUN" = true ]; then
    return 0
  fi
  "$@"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

usage() {
  ascii_art
  cat << EOF
$TOOL_NAME v$VERSION

Usage: ./threatlens.sh [options] (-t <target> | -l targets.txt)

Targets can be domains or URLs. Each target gets structured outputs:
  ./output/<target>/{raw,alive,results,logs}

Options:
  -t, --target VALUE         Add a target (repeatable)
  -l, --list FILE            Read targets (one per line)
  -o, --outdir DIR           Root output directory (default: ./output)
      --templates-dir DIR    Nuclei templates directory (default: ./nuclei-templates)
      --include-subs         Include subdomains for collectors that support it
      --httpx-codes LIST     Comma list of HTTP status codes considered alive
      --threads N            Concurrency for tools that support it (default: 50)
      --nuclei-args "..."    Extra args passed to nuclei (quote the string)
      --dry-run              Print commands instead of running
  -h, --help                 Show this help

Dependencies:
  katana, waybackurls, gauplus, hakrawler, paramspider, uro, httpx, nuclei, jq

Examples:
  ./threatlens.sh -t example.com
  ./threatlens.sh -l targets.txt --include-subs --threads 100
EOF
}

sanitize_name() { # make filesystem-safe name from target
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's#^https?://##; s#[^a-z0-9._-]+#-#g; s#-+#-#g; s#^[-.]+##; s#[-.]+$##'
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -t|--target)
        [ $# -ge 2 ] || die "--target requires a value"
        TARGETS+=("$2"); shift 2;;
      -l|--list)
        [ $# -ge 2 ] || die "--list requires a file"
        TARGETS_FILE="$2"; shift 2;;
      -o|--outdir)
        OUTDIR_ROOT="$2"; shift 2;;
      --templates-dir)
        TEMPLATES_DIR="$2"; shift 2;;
      --include-subs)
        INCLUDE_SUBS=true; shift;;
      --httpx-codes)
        HTTPX_MATCH_CODES="$2"; shift 2;;
      --threads)
        THREADS="$2"; shift 2;;
      --nuclei-args)
        # shellcheck disable=SC2206
        NUCLEI_EXTRA_ARGS=($2); shift 2;;
      --dry-run)
        DRY_RUN=true; shift;;
      -h|--help)
        usage; exit 0;;
      *)
        die "Unknown option: $1";;
    esac
  done

  if [ -n "$TARGETS_FILE" ]; then
    [ -f "$TARGETS_FILE" ] || die "Target file not found: $TARGETS_FILE"
    while IFS= read -r line; do
      [ -n "${line// /}" ] || continue
      TARGETS+=("$line")
    done < "$TARGETS_FILE"
  fi

  [ ${#TARGETS[@]} -gt 0 ] || die "No targets specified"
}

prepare_templates() {
  mkdir -p "$TEMPLATES_DIR"
  run nuclei -ut -ud "$TEMPLATES_DIR"
}

collect_urls() { # target, target_dir
  local target="$1"; shift
  local tdir="$1"; shift
  local rawdir="$tdir/raw"

  mkdir -p "$rawdir"

  # Katana (URLs)
  run katana -rl "$THREADS" -u "$target" -silent -o "$rawdir/katana.txt" || true

  # waybackurls (domain)
  run bash -lc "echo '$target' | sed -E 's#^https?://##' | waybackurls > '$rawdir/waybackurls.txt'" || true

  # gauplus (domain)
  local subsFlag=""
  [ "$INCLUDE_SUBS" = true ] && subsFlag="-subs"
  run bash -lc "echo '$target' | sed -E 's#^https?://##' | gauplus $subsFlag -t $THREADS -random-agent > '$rawdir/gauplus.txt'" || true

  # hakrawler (seed URL)
  run bash -lc "echo '$target' | hakrawler -plain -depth 2 -t $THREADS > '$rawdir/hakrawler.txt'" || true

  # ParamSpider (domain)
  local domain
  domain="$(echo "$target" | sed -E 's#^https?://##; s#/.*$##')"
  run paramspider -d "$domain" -o "$rawdir/paramspider.txt" || true
}

dedupe_urls() { # tdir
  local tdir="$1"; shift
  local rawdir="$tdir/raw"
  mkdir -p "$tdir"
  # uro collapses and dedupes
  run bash -lc "cat '$rawdir/'*.txt 2>/dev/null | sort -u | uro | sort -u > '$tdir/urls.deduped.txt'"
}

check_liveness() { # tdir
  local tdir="$1"; shift
  local alivedir="$tdir/alive"
  mkdir -p "$alivedir"
  run httpx -l "$tdir/urls.deduped.txt" -silent -status-code -follow-redirects -mc "$HTTPX_MATCH_CODES" -threads "$THREADS" -o "$alivedir/alive.txt"
}

run_nuclei() { # tdir
  local tdir="$1"; shift
  local resdir="$tdir/results"
  mkdir -p "$resdir"
  if [ ! -s "$tdir/alive/alive.txt" ]; then
    log WARN "No alive URLs for $(basename "$tdir"). Skipping nuclei."
    : > "$resdir/nuclei.jsonl"
    return 0
  fi

  run nuclei -l "$tdir/alive/alive.txt" -jsonl -o "$resdir/nuclei.jsonl" -irr -du -stats -silent -retries 1 -bulk-size "$THREADS" -ud "$TEMPLATES_DIR" "${NUCLEI_EXTRA_ARGS[@]}"
}

write_summary() { # tdir
  local tdir="$1"; shift
  local resdir="$tdir/results"
  local alive_file="$tdir/alive/alive.txt"
  local urls_file="$tdir/urls.deduped.txt"
  local jsonl="$resdir/nuclei.jsonl"
  local summary_txt="$resdir/summary.txt"
  local summary_json="$resdir/summary.json"

  local end_ts
  end_ts="$(date +%s)"
  local duration
  duration=$(( end_ts - START_TS ))

  # Defaults
  local total_urls=0 alive_urls=0 total_findings=0
  [ -f "$urls_file" ] && total_urls=$(wc -l < "$urls_file" | tr -d ' ')
  [ -f "$alive_file" ] && alive_urls=$(wc -l < "$alive_file" | tr -d ' ')
  [ -s "$jsonl" ] && total_findings=$(wc -l < "$jsonl" | tr -d ' ')

  # Severity counts via jq if available
  local sev_json='{}'
  if command -v jq >/dev/null 2>&1 && [ -s "$jsonl" ]; then
    sev_json=$(jq -r '.["info"].severity // .info.severity? // empty' "$jsonl" 2>/dev/null | \
      awk '{a[tolower($0)]++} END{printf("{"); i=0; for (k in a){if(i++) printf(","); printf("\"%s\":%d",k,a[k])} printf("}") }')
  fi

  # Write human summary
  {
    echo "$TOOL_NAME v$VERSION summary"
    echo "Target: $(basename "$tdir")"
    echo "Duration: ${duration}s"
    echo "URLs (deduped): $total_urls"
    echo "Alive URLs: $alive_urls"
    echo "Findings (total): $total_findings"
    if [ "$sev_json" != '{}' ]; then
      echo "Severity breakdown: $sev_json"
    fi
  } > "$summary_txt"

  # Write JSON summary
  {
    echo -n '{'
    echo -n '"tool":"'$TOOL_NAME'","version":"'$VERSION'",'
    echo -n '"target":"'"$(basename "$tdir")"'",'
    echo -n '"duration_sec":'$duration','
    echo -n '"urls_total":'$total_urls','
    echo -n '"urls_alive":'$alive_urls','
    echo -n '"findings_total":'$total_findings','
    echo -n '"severity_counts":'$sev_json
    echo '}'
  } > "$summary_json"
}

process_target() { # target
  local target="$1"
  local safe
  safe="$(sanitize_name "$target")"

  WORKDIR="$OUTDIR_ROOT/$safe"
  export TOOL_BASENAME="$safe"
  mkdir -p "$WORKDIR" "$WORKDIR/raw" "$WORKDIR/alive" "$WORKDIR/results" "$WORKDIR/logs"

  # Temp dir per target
  local tmpdir
  tmpdir="$(mktemp -d -t threatlens.XXXXXX)"
  trap 'rm -rf "$tmpdir"' EXIT

  log INFO "Starting processing for $target -> $WORKDIR"
  collect_urls "$target" "$WORKDIR" || true
  dedupe_urls "$WORKDIR"
  check_liveness "$WORKDIR"
  run_nuclei "$WORKDIR"
  write_summary "$WORKDIR"
  log INFO "Completed $target"
}

main() {
  parse_args "$@"

  # Verify dependencies early
  for bin in katana waybackurls gauplus hakrawler paramspider uro httpx nuclei jq; do
    require_tool "$bin"
  done

  mkdir -p "$OUTDIR_ROOT"
  prepare_templates

  for t in "${TARGETS[@]}"; do
    process_target "$t"
  done
}

main "$@"
