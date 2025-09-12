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
      --phase VALUE          Phase to run: collect|live|scan|all (default: all)
      --resume               Skip phases with existing outputs
      --parallel N           Process up to N targets concurrently (default: 1)
      --scan-raw             Feed nuclei with deduped URLs directly (skip httpx)
      --fuzz                 Enable fuzz-style scanning (NucleiFuzzer-like)
      --fuzz-add-params     Add common params to URLs without query
      --param-wordlist FILE Wordlist of parameter names (default: ./wordlists/params.txt)
      --signal LIST          Nuclei severities (e.g., high,critical)
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
      --phase)
        PHASE="$2"; shift 2;;
      --resume)
        RESUME=true; shift;;
      --parallel)
        PARALLEL="$2"; shift 2;;
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

  if [ ${#TARGETS[@]} -eq 0 ] && [ -z "${NUCLEI_INPUT_FILE}" ]; then
    die "No targets specified (or provide --nuclei-input <file>)"
  fi
}

templates_present() {
  find "$TEMPLATES_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) -print -quit | grep -q .
}

prepare_templates() {
  mkdir -p "$TEMPLATES_DIR"
  # In dry-run, only print intended actions and skip presence checks
  if [ "$DRY_RUN" = true ]; then
    log INFO "dry-run: skipping templates update/clone and presence checks"
    run nuclei -update -update-directory "$TEMPLATES_DIR" || true
    run nuclei -ut -ud "$TEMPLATES_DIR" || true
    return 0
  fi
  # Try modern nuclei flags first, then legacy as fallback
  if ! run nuclei -update -update-directory "$TEMPLATES_DIR"; then
    run nuclei -ut -ud "$TEMPLATES_DIR" || true
  fi
  # If still empty, fallback to cloning the official templates repo
  if ! templates_present; then
    if command -v git >/dev/null 2>&1; then
      log WARN "Templates directory appears empty. Cloning official nuclei-templates..."
      run git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$TEMPLATES_DIR" || true
    fi
  fi
  # Final check
  if ! templates_present; then
    die "No nuclei templates found in '$TEMPLATES_DIR'. Ensure network access and rerun, or manually populate templates (git clone https://github.com/projectdiscovery/nuclei-templates.git)."
  fi
}

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

check_liveness() { # tdir
  local tdir="$1"; shift
  local alivedir="$tdir/alive"
  mkdir -p "$alivedir"
  run httpx -l "$tdir/urls.deduped.txt" -silent -follow-redirects -timeout 10 -retries 1 -mc "$HTTPX_MATCH_CODES" -threads "$THREADS" -o "$alivedir/alive.txt"
}

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

run_nuclei_fuzz() { # tdir
  local tdir="$1"; shift
  local fdir="$tdir/fuzz"
  mkdir -p "$fdir"
  if [ ! -s "$fdir/fuzz_urls.txt" ]; then
    log WARN "No fuzz URLs prepared for $(basename "$tdir")"
    return 0
  fi
  local sev_args=()
  if [ -n "$SIGNAL_SEVERITY" ]; then sev_args=( -severity "$SIGNAL_SEVERITY" ); fi
  # Use tags likely aligned with fuzzing templates
  run nuclei -l "$fdir/fuzz_urls.txt" -t "$TEMPLATES_DIR" -tags xss,sqli,lfi,ssrf,open-redirect -jsonl -o "$fdir/nuclei_fuzz.jsonl" -irr -stats -silent -retries 1 -bulk-size "$THREADS" "${sev_args[@]}" "${NUCLEI_EXTRA_ARGS[@]}"
}

run_nuclei() { # tdir
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
    log WARN "No input URLs (source=$SCAN_SOURCE) for $(basename "$tdir"). Skipping nuclei."
    : > "$resdir/nuclei.jsonl"
    return 0
  fi

  local sev_args=()
  if [ -n "$SIGNAL_SEVERITY" ]; then sev_args=( -severity "$SIGNAL_SEVERITY" ); fi
  # Prefer DAST mode if supported by installed nuclei
  local dast_flag=()
  if nuclei -h 2>&1 | grep -q -- "-dast"; then
    dast_flag=( -dast )
  fi
  run nuclei -l "$input_list" -t "$TEMPLATES_DIR" "${dast_flag[@]}" -jsonl -o "$resdir/nuclei.jsonl" -irr -stats -silent -retries 1 -c "$THREADS" "${sev_args[@]}" "${NUCLEI_EXTRA_ARGS[@]}"
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

  # Phase: live (skip entirely if scanning raw URLs)
  if [ "$SCAN_SOURCE" != "raw" ]; then
    if [ "$PHASE" = "all" ] || [ "$PHASE" = "live" ]; then
      if [ "$RESUME" = true ] && [ -s "$WORKDIR/alive/alive.txt" ]; then
        log INFO "Resume: alive/alive.txt exists, skipping liveness"
      else
        check_liveness "$WORKDIR"
      fi
    fi
  else
    log INFO "Skipping httpx probe (scan_source=raw)"
  fi
  fi

  # Phase: scan
  if [ "$PHASE" = "all" ] || [ "$PHASE" = "scan" ]; then
    if [ "$RESUME" = true ] && [ -s "$WORKDIR/results/nuclei.jsonl" ]; then
      log INFO "Resume: results/nuclei.jsonl exists, skipping nuclei"
    else
      run_nuclei "$WORKDIR"
    fi
    # Optional FUZZ mode: generate FUZZ URLs from alive list and run fuzz-focused templates
    if [ "$FUZZ_MODE" = true ]; then
      fuzz_prepare "$WORKDIR"
      run_nuclei_fuzz "$WORKDIR"
    fi
  fi
  end_ts="$(date +%s)"
  duration=$(( end_ts - start_ts ))
  write_summary "$WORKDIR" "$duration"
  # Show a concise findings preview on stdout (top 20)
  if [ -s "$WORKDIR/results/nuclei.jsonl" ] && [ "$DRY_RUN" != true ]; then
    echo "--- Findings (top 20) for: $target ---"
    if command -v jq >/dev/null 2>&1; then
      jq -r 'select(.!=null) | [(.info.severity // .severity // ""), (.info.name // ""), (.matchedAt // ."matched-at" // .host // .url // "")] | @tsv' "$WORKDIR/results/nuclei.jsonl" 2>/dev/null | head -n 20 || true
    else
      sed -n '1,20p' "$WORKDIR/results/nuclei.jsonl" || true
    fi
  fi

  # Print a concise final summary to stdout so results are obvious
  if [ "$DRY_RUN" != true ]; then
    echo "--- Scan Summary for: $target ---"
    cat "$WORKDIR/results/summary.txt" 2>/dev/null || true
    echo "Results JSONL: $WORKDIR/results/nuclei.jsonl"
    echo "Logs:          $WORKDIR/logs"
  else
    echo "[dry-run] Would show summary and results paths here"
  fi
  log INFO "Completed $target (nuclei is the final stage)"
  rm -rf "$tmpdir" || true
  # Clear trap so EXIT doesn’t reference a now-unset local var
  trap - EXIT
}

main() {
  parse_args "$@"

  # Verify dependencies early
  for bin in katana waybackurls gauplus hakrawler paramspider uro httpx nuclei jq; do
    require_tool "$bin"
  done

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
