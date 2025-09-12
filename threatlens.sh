#!/usr/bin/env bash

# ThreatLens - lightweight web recon + scan orchestrator
# Core: URL collection -> dedupe -> liveness -> nuclei

set -Eeuo pipefail
IFS=$'\n\t'

TOOL_NAME="ThreatLens"
VERSION="0.1.0"

# Globals configured by flags
OUTDIR_ROOT="./output"
TARGETS=()
TARGETS_FILE=""
TEMPLATES_DIR="./nuclei-templates"
HTTPX_MATCH_CODES="200,204,301,302,307,401,403,405,500,502,503,504"
INCLUDE_SUBS=false
DRY_RUN=false
THREADS=50
NUCLEI_EXTRA_ARGS=()
# Provide a custom input list to nuclei (one URL per line)
NUCLEI_INPUT_FILE=""
# Nuclei input source: "alive" (default via httpx) or "raw" (deduped URLs directly)
SCAN_SOURCE="alive"
PHASE="all" # collect|live|scan|all
RESUME=false
PARALLEL=1
FUZZ_MODE=false
FUZZ_ADD_PARAMS=false
PARAM_WORDLIST="./wordlists/params.txt"
SIGNAL_SEVERITY=""
HTML_REPORT=false
INPUTS_ONLY=false
FUZZIFY=false

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
  # Always print to stdout
  echo "[$ts] [$level] $msg"
  # If per-target logs directory exists, write there as well
  if [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR/logs" ]; then
    local base="${TOOL_BASENAME:-global}"
    echo "[$ts] [$level] $msg" >> "$WORKDIR/logs/$base.log" 2>/dev/null || true
    echo "[$ts] [$level] $msg" >> "$WORKDIR/logs/threatlens.log" 2>/dev/null || true
  fi
}

die() { echo "Error: $*" >&2; exit 1; }

run() { # print+run (honors dry-run)
  if [ -n "${WORKDIR:-}" ] && [ -d "$WORKDIR/logs" ]; then
    echo "+ $*" | tee -a "$WORKDIR/logs/$TOOL_BASENAME.log" >/dev/null || true
  else
    echo "+ $*"
  fi
  if [ "$DRY_RUN" = true ]; then
    return 0
  fi
  "$@"
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing dependency: $1" >&2
    echo "Hint: Create .venv and install requirements:" >&2
    echo "  python3 -m venv .venv && source .venv/bin/activate" >&2
    echo "  bash scripts/bootstrap_env.sh" >&2
    die "See README.md for setup instructions."
  fi
}

usage() {
  ascii_art
  cat << EOF
$TOOL_NAME v$VERSION

Usage: ./threatlens.sh [options] (-t <target> | -l targets.txt)

Targets can be domains or URLs. This tool only collects URLs from multiple sources and writes a deduplicated list; no probing or scanning is performed.
Each target gets structured outputs:
  ./output/<target>/{raw,alive,results,logs}

Options:
  -t, --target VALUE         Add a target (repeatable)
  -l, --list FILE            Read targets (one per line)
  -o, --outdir DIR           Root output directory (default: ./output)
      --templates-dir DIR    Nuclei templates directory (default: ./nuclei-templates)
      --include-subs         Include subdomains for collectors that support it
      --httpx-codes LIST     Comma list of HTTP status codes considered alive
      --threads N            Concurrency for tools that support it (default: 50)
      --dry-run              Print commands instead of running
      --inputs-only          Produce results/inputs_get.txt (GET URLs) and exit
      --fuzzify              Also produce results/fuzz_get.txt (replace values with FUZZ)
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
      --nuclei-input)
        NUCLEI_INPUT_FILE="$2"; shift 2;;
      --inputs-only)
        INPUTS_ONLY=true; shift;;
      --fuzzify)
        FUZZIFY=true; shift;;
      --dry-run)
        DRY_RUN=true; shift;;
      --scan-raw|--no-probe)
        SCAN_SOURCE="raw"; shift;;
      --phase)
        PHASE="$2"; shift 2;;
      --resume)
        RESUME=true; shift;;
      --parallel)
        PARALLEL="$2"; shift 2;;
      --fuzz)
        FUZZ_MODE=true; shift;;
      --fuzz-add-params)
        FUZZ_ADD_PARAMS=true; shift;;
      --param-wordlist)
        PARAM_WORDLIST="$2"; shift 2;;
      --signal)
        SIGNAL_SEVERITY="$2"; shift 2;;
      --html-report)
        HTML_REPORT=true; shift;;
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

  if [ ${#TARGETS[@]} -eq 0 ]; then
    die "No targets specified"
  fi
}

# No templates management needed in collect-only mode

collect_urls() { # target, target_dir
  local target="$1"; shift
  local tdir="$1"; shift
  local rawdir="$tdir/raw"

  mkdir -p "$rawdir"

  # Katana (URLs)
  run katana -rl "$THREADS" -u "$target" -silent -o "$rawdir/katana.txt" || true

  # waybackurls (domain)
  run bash -c "echo '$target' | sed -E 's#^https?://##' | waybackurls > '$rawdir/waybackurls.txt'" || true

  # gauplus (domain)
  local subsFlag=""
  [ "$INCLUDE_SUBS" = true ] && subsFlag="-subs"
  run bash -c "echo '$target' | sed -E 's#^https?://##' | gauplus $subsFlag -t $THREADS -random-agent > '$rawdir/gauplus.txt'" || true

  # hakrawler (seed URL)
  run bash -c "echo '$target' | hakrawler -plain -depth 2 -t $THREADS > '$rawdir/hakrawler.txt'" || true

  # ParamSpider (domain)
  local domain
  domain="$(echo "$target" | sed -E 's#^https?://##; s#/.*$##')"
  # ParamSpider (stdout -> file); use -s if include-subs is enabled
  if [ "$INCLUDE_SUBS" = true ]; then
    run bash -c "paramspider -d '$domain' -s | tee '$rawdir/paramspider.txt' >/dev/null" || true
  else
    run bash -c "paramspider -d '$domain' | tee '$rawdir/paramspider.txt' >/dev/null" || true
  fi
}

dedupe_urls() { # tdir
  local tdir="$1"; shift
  local rawdir="$tdir/raw"
  mkdir -p "$tdir"
  # uro collapses and dedupes
  run bash -c "if compgen -G '$rawdir/*.txt' > /dev/null; then cat '$rawdir/'*.txt | uro | sort -u > '$tdir/urls.deduped.txt'; else : > '$tdir/urls.deduped.txt'; fi"
}

extract_inputs_get() { # tdir -> creates results/inputs_get.txt
  local tdir="$1"; shift
  local in="$tdir/urls.deduped.txt"
  local out="$tdir/results/inputs_get.txt"
  mkdir -p "$tdir/results"
  if [ ! -s "$in" ]; then
    log WARN "No deduped URLs at $in"
    : > "$out"; return 0
  fi
  grep -Ei '\?[A-Za-z0-9_.%-]+=' "$in" | sort -u > "$out" || true
  log INFO "inputs_get.txt: $(wc -l < "$out" | tr -d ' ') URLs with parameters"
}

prepare_fuzz_list() { # tdir -> creates results/fuzz_get.txt from inputs_get.txt
  local tdir="$1"; shift
  local in="$tdir/results/inputs_get.txt"
  local out="$tdir/results/fuzz_get.txt"
  if [ ! -s "$in" ]; then
    log WARN "No inputs_get.txt at $in"
    : > "$out"; return 0
  fi
  grep -F '?' "$in" | sed -E 's/=[^&#?]*/=FUZZ/g' | sort -u > "$out" || true
  log INFO "fuzz_get.txt: $(wc -l < "$out" | tr -d ' ') FUZZ-ready URLs"
}

check_liveness() { :; }

fuzz_prepare() { # tdir
  local tdir="$1"; shift
  local fdir="$tdir/fuzz"
  mkdir -p "$fdir"
  local alive="$tdir/alive/alive.txt"
  [ -s "$alive" ] || { log WARN "No alive URLs to fuzz"; return; }

  # Replace existing parameter values with FUZZ marker
  run bash -c "grep -F '?' '$alive' | sed -E 's/=[^&#?]*/=FUZZ/g' | sort -u > '$fdir/fuzz_base.txt'" || true

  # Optionally add common parameters to URLs without query part
  if [ "$FUZZ_ADD_PARAMS" = true ] && [ -f "$PARAM_WORDLIST" ]; then
    run bash -c "grep -v '?' '$alive' | while read -r u; do while read -r p; do echo \"$u?$p=FUZZ\"; done < '$PARAM_WORDLIST'; done | sort -u > '$fdir/fuzz_added.txt'" || true
  else
    : > "$fdir/fuzz_added.txt"
  fi

  # Combine
  run bash -c "cat '$fdir/fuzz_base.txt' '$fdir/fuzz_added.txt' 2>/dev/null | sort -u > '$fdir/fuzz_urls.txt'" || true
}

run_nuclei_fuzz() { :; }

run_nuclei() {
  local tdir="$1"; shift
  local resdir="$tdir/results"
  mkdir -p "$resdir"
  local input_list
  if [ -n "$NUCLEI_INPUT_FILE" ]; then
    input_list="$NUCLEI_INPUT_FILE"
  elif [ "$SCAN_SOURCE" = "raw" ]; then
    input_list="$tdir/urls.deduped.txt"
  else
    input_list="$tdir/alive/alive.txt"
  fi
  if [ ! -s "$input_list" ]; then
    log WARN "No input URLs for nuclei at $input_list"
    : > "$resdir/nuclei.jsonl"
    return 0
  fi
  run nuclei -l "$input_list" -jsonl -o "$resdir/nuclei.jsonl" "${NUCLEI_EXTRA_ARGS[@]}"
}

write_summary() { # tdir, duration_sec
  local tdir="$1"; shift
  local duration="$1"; shift || true
  local resdir="$tdir/results"
  local alive_file="$tdir/alive/alive.txt"
  local urls_file="$tdir/urls.deduped.txt"
  local jsonl="$resdir/nuclei.jsonl"
  local summary_txt="$resdir/summary.txt"
  local summary_json="$resdir/summary.json"
  local inputs_file="$resdir/inputs_get.txt"

  # Defaults
  local total_urls=0 alive_urls=0 total_findings=0
  [ -f "$urls_file" ] && total_urls=$(wc -l < "$urls_file" | tr -d ' ')
  [ -f "$alive_file" ] && alive_urls=$(wc -l < "$alive_file" | tr -d ' ')
  [ -s "$jsonl" ] && total_findings=$(wc -l < "$jsonl" | tr -d ' ')
  local inputs_count=0
  [ -f "$inputs_file" ] && inputs_count=$(wc -l < "$inputs_file" | tr -d ' ')

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
    echo "Inputs (GET URLs): $inputs_count"
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

  # Optional HTML rendering of JSONL findings (simple table)
  if [ "$HTML_REPORT" = true ] && command -v jq >/dev/null 2>&1 && [ -s "$jsonl" ]; then
    local html="$resdir/nuclei.html"
    {
      printf '<!doctype html><meta charset="utf-8"><title>Nuclei Report - %s</title>' "$(basename "$tdir")"
      printf '<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #ddd;padding:6px}th{background:#f3f3f3;text-align:left}tr:nth-child(even){background:#fafafa}.critical{color:#d32f2f}.high{color:#e65100}.medium{color:#f9a825}.low{color:#1976d2}</style>'
      printf '<h1>Nuclei Report - %s</h1>' "$(basename "$tdir")"
      printf '<p>Deduped: %s • Alive: %s • Findings: %s • Duration: %ss</p>' "$total_urls" "$alive_urls" "$total_findings" "$duration"
      printf '<table><thead><tr><th>Severity</th><th>Name</th><th>Template</th><th>Matched</th></tr></thead><tbody>'
      jq -r 'def esc(s): (s // "") | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;"); . as $r | "<tr class=\"" + ((($r.info.severity // $r.severity // "")|ascii_downcase)) + "\"><td>" + esc($r.info.severity // $r.severity) + "</td><td>" + esc($r.info.name) + "</td><td>" + esc($r.templateID) + "</td><td>" + esc($r."matched-at" // $r.matchedAt // $r.url // $r.host) + "</td></tr>"' "$jsonl"
      printf '</tbody></table>'
    } > "$html" || true
  fi
}

process_target() { # target
  local target="$1"
  # Ensure scheme for tools that expect URLs (default to https://)
  local target_url="$target"
  case "$target_url" in
    http://*|https://*) ;; 
    *) target_url="https://$target_url" ;;
  esac
  local safe
  safe="$(sanitize_name "$target")"

  WORKDIR="$OUTDIR_ROOT/$safe"
  export TOOL_BASENAME="$safe"
  mkdir -p "$WORKDIR" "$WORKDIR/raw" "$WORKDIR/alive" "$WORKDIR/results" "$WORKDIR/logs"

  # Temp dir per target
  local tmpdir
  tmpdir="$(mktemp -d -t threatlens.XXXXXX)"
  # Cleanup on script exit as a fallback; safe with set -u
  trap 'if [ -n "${tmpdir-}" ]; then rm -rf -- "$tmpdir"; fi' EXIT
  local start_ts end_ts duration
  start_ts="$(date +%s)"

  log INFO "Starting processing for $target -> $WORKDIR (phase=$PHASE resume=$RESUME)"

  # If a custom nuclei input file is provided, skip recon/probe and go straight to nuclei
  if [ -n "$NUCLEI_INPUT_FILE" ]; then
    # Make summary counts meaningful by mirroring input into urls.deduped.txt
    if [ ! -s "$WORKDIR/urls.deduped.txt" ]; then
      mkdir -p "$WORKDIR"
      cp -f "$NUCLEI_INPUT_FILE" "$WORKDIR/urls.deduped.txt" 2>/dev/null || true
    fi
  else
  # Phase: collect (also needed before live/scan)
  if [ "$PHASE" = "all" ] || [ "$PHASE" = "collect" ] || [ "$PHASE" = "live" ]; then
    if [ "$RESUME" = true ] && compgen -G "$WORKDIR/raw/*.txt" > /dev/null; then
      log INFO "Resume: raw/*.txt exists, skipping collect"
    else
      collect_urls "$target_url" "$WORKDIR" || true
    fi
  fi

  # Phase: dedupe (required before live/scan)
  if [ "$PHASE" = "all" ] || [ "$PHASE" = "collect" ] || [ "$PHASE" = "live" ]; then
    if [ "$RESUME" = true ] && [ -s "$WORKDIR/urls.deduped.txt" ]; then
      log INFO "Resume: urls.deduped.txt exists, skipping dedupe"
    else
      dedupe_urls "$WORKDIR"
    fi
  fi

  # --- GET inputs extraction ---
  extract_inputs_get "$WORKDIR"
  [ "$FUZZIFY" = true ] && prepare_fuzz_list "$WORKDIR"

  # Stop here if inputs-only or phase=collect requested
  if [ "$INPUTS_ONLY" = true ] || [ "$PHASE" = "collect" ]; then
    log INFO "Inputs ready: $WORKDIR/results/inputs_get.txt"
    end_ts="$(date +%s)"; duration=$(( end_ts - start_ts ))
    write_summary "$WORKDIR" "$duration"
    rm -rf "$tmpdir" || true; trap - EXIT; return 0
  fi
  fi

  # Phase: scan (default to inputs_get.txt if not overridden and not using scan-raw)
  if [ "$PHASE" = "all" ] || [ "$PHASE" = "scan" ]; then
    local default_inputs="$WORKDIR/results/inputs_get.txt"
    if [ -z "$NUCLEI_INPUT_FILE" ] && [ "$SCAN_SOURCE" != "raw" ] && [ -s "$default_inputs" ]; then
      NUCLEI_INPUT_FILE="$default_inputs"
    fi
    run_nuclei "$WORKDIR"
  fi

  end_ts="$(date +%s)"
  duration=$(( end_ts - start_ts ))
  # Minimal summary
  if [ "$DRY_RUN" != true ]; then
    local count_dedup=0
    [ -f "$WORKDIR/urls.deduped.txt" ] && count_dedup=$(wc -l < "$WORKDIR/urls.deduped.txt" | tr -d ' ')
    echo "--- Collect Summary for: $target ---"
    echo "Deduped URLs: $count_dedup"
    echo "List:         $WORKDIR/urls.deduped.txt"
    echo "Logs:         $WORKDIR/logs"
  fi
  log INFO "Completed $target"
  rm -rf "$tmpdir" || true
  # Clear trap so EXIT doesn’t reference a now-unset local var
  trap - EXIT
}

main() {
  parse_args "$@"

  # Verify dependencies early based on the requested mode
  if [ -n "$NUCLEI_INPUT_FILE" ]; then
    # nuclei-only mode
    for bin in nuclei jq; do require_tool "$bin"; done
  else
    # recon and/or probe pipeline
    require_tool katana
    require_tool uro
    # optional recon sources: warn-only if missing by gating calls
    for opt in waybackurls gauplus hakrawler paramspider; do
      if ! command -v "$opt" >/dev/null 2>&1; then
        log WARN "Optional tool missing: $opt (continuing without it)"
      fi
    done
    # probe/scan deps
    require_tool httpx
    require_tool nuclei
    command -v jq >/dev/null 2>&1 || log WARN "jq missing: severity breakdown and HTML report may be limited"
  fi

  mkdir -p "$OUTDIR_ROOT"
  prepare_templates

  if [ "$PARALLEL" -le 1 ] || [ "$DRY_RUN" = true ]; then
    for t in "${TARGETS[@]}"; do
      process_target "$t"
    done
  else
    for t in "${TARGETS[@]}"; do
      process_target "$t" &
      # Limit concurrent jobs
      while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do
        wait -n || true
      done
    done
    wait || true
  fi
}

main "$@"
