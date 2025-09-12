#!/usr/bin/env bash
# ThreatLens - recon → normalize → inputs-only → prioritize → (optional) probe → DAST
# v0.2.2  (GET-focused, multi-source, ranked)
# For authorized security testing only.

set -Eeuo pipefail
IFS=$'\n\t'

TOOL_NAME="ThreatLens"
VERSION="0.2.2"

# ---------- Defaults / Globals ----------
OUTDIR_ROOT="./output"
TARGETS=()
TARGETS_FILE=""
TEMPLATES_DIR="./nuclei-templates"
HTTPX_MATCH_CODES="200,204,301,302,307,401,403,405,500,502,503,504"
INCLUDE_SUBS=false
DRY_RUN=false
THREADS=50
SOURCES="katana,wayback,gau,hakrawler"   # CSV tokens: katana,wayback,gau,hakrawler,paramspider
NUCLEI_EXTRA_ARGS=()                      # e.g. --nuclei-args "-dast -tags xss,sqli -severity high,critical"
NUCLEI_INPUT_FILE=""                      # if set, skip recon/probe and feed directly
SCAN_SOURCE="alive"                       # alive | raw
PHASE="all"                               # collect | live | scan | all
RESUME=false
PARALLEL=1
INPUTS_ONLY=false                         # --inputs-only
FUZZIFY=false                             # --fuzzify
SIGNAL_SEVERITY=""                        # low|medium|high|critical => exit 2 if present
HTML_REPORT=false                         # --html-report
RERANK=false                              # --rerank (micro re-rank after httpx meta)
TOP_PER_HOST=0                            # --top-per-host N (0 = unlimited)

# ---------- Runtime ----------
WORKDIR=""
START_TS="$(date +%s)"

ascii_art() {
  cat << 'EOF'
==============================
 ThreatLens - Recon Orchestrator
==============================
EOF
}

log() { # level, message...
  local level="$1"; shift
  local msg="$*"
  local ts; ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[$ts] [$level] $msg"
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
  [ "$DRY_RUN" = true ] && return 0
  "$@"
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing dependency: $1" >&2
    die "Install required tools and retry."
  fi
}

sanitize_name() { # filesystem-safe
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's#^https?://##; s#[^a-z0-9._-]+#-#g; s#-+#-#g; s#^[-.]+##; s#[-.]+$##'
}

usage() {
  ascii_art
  cat << EOF
$TOOL_NAME v$VERSION

Usage: ./threatlens.sh [options] (-t <target> | -l targets.txt)

Pipeline:
  collect -> dedupe -> inputs-only -> prioritize -> (optional) live -> scan
  Phases via --phase: collect | live | scan | all   (default: all)

Outputs per target:
  ./output/<target>/{raw,alive,results,logs}

Options:
  -t, --target VALUE         Add a target (repeatable)
  -l, --list FILE            Read targets (one per line)
  -o, --outdir DIR           Root output (default: ./output)
      --templates-dir DIR    Nuclei templates (default: ./nuclei-templates)
      --include-subs         Include subdomains where supported
      --httpx-codes LIST     CSV HTTP codes considered alive
      --threads N            Concurrency (default: 50)
      --sources CSV          Recon sources (default: katana,wayback,gau,hakrawler)
                             Allowed: katana,wayback,gau,hakrawler,paramspider
      --nuclei-args "ARGS"   Extra args passed verbatim to nuclei
      --nuclei-input FILE    Skip recon/probe; nuclei -l FILE
      --scan-raw             Scan deduped URLs directly (skip httpx)
      --phase PHASE          collect | live | scan | all
      --resume               Reuse existing artifacts if present
      --parallel N           Max targets to process concurrently (default: 1)
      --inputs-only          Produce results/inputs_get.txt and stop
      --fuzzify              Also produce results/fuzz_get.txt (values -> FUZZ)
      --rerank               Micro re-rank after httpx meta (requires jq)
      --top-per-host N       Cap first-wave per host (0=unlimited)
      --signal LEVEL         Exit 2 if any finding >= level (low|medium|high|critical)
      --html-report          Render simple HTML from nuclei JSONL (needs jq)
      --dry-run              Print commands without executing
  -h, --help                 Show this help

Recommended nuclei args for GET-focused DAST:
  -dast -tags xss,sqli,lfi,redirect,ssrf -severity medium,high,critical -rl 50 -c 50

Examples:
  ./threatlens.sh -t example.com --threads 80 --nuclei-args "-dast -tags xss,sqli,lfi,redirect,ssrf -severity medium,high,critical"
  ./threatlens.sh -t example.com --sources wayback,gau --inputs-only
  ./threatlens.sh -l targets.txt --include-subs --threads 100 --parallel 5 --rerank --top-per-host 200
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -t|--target)       TARGETS+=("${2:?}"); shift 2;;
      -l|--list)         TARGETS_FILE="${2:?}"; shift 2;;
      -o|--outdir)       OUTDIR_ROOT="${2:?}"; shift 2;;
      --templates-dir)   TEMPLATES_DIR="${2:?}"; shift 2;;
      --include-subs)    INCLUDE_SUBS=true; shift;;
      --httpx-codes)     HTTPX_MATCH_CODES="${2:?}"; shift 2;;
      --threads)         THREADS="${2:?}"; shift 2;;
      --sources)         SOURCES="${2:?}"; shift 2;;
      --nuclei-args)     # shellcheck disable=SC2206
                         NUCLEI_EXTRA_ARGS=($2); shift 2;;
      --nuclei-input)    NUCLEI_INPUT_FILE="${2:?}"; shift 2;;
      --dry-run)         DRY_RUN=true; shift;;
      --scan-raw|--no-probe)
                         SCAN_SOURCE="raw"; shift;;
      --phase)           PHASE="${2:?}"; shift 2;;
      --resume)          RESUME=true; shift;;
      --parallel)        PARALLEL="${2:?}"; shift 2;;
      --inputs-only)     INPUTS_ONLY=true; shift;;
      --fuzzify)         FUZZIFY=true; shift;;
      --signal)          SIGNAL_SEVERITY="${2:?}"; shift 2;;
      --html-report)     HTML_REPORT=true; shift;;
      --rerank)          RERANK=true; shift;;
      --top-per-host)    TOP_PER_HOST="${2:?}"; shift 2;;
      -h|--help)         usage; exit 0;;
      *)                 die "Unknown option: $1";;
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

# ---------- Pipeline Stages ----------

prepare_templates() {
  mkdir -p "$TEMPLATES_DIR" || true
  if command -v nuclei >/dev/null 2>&1; then
    run nuclei -ut -ud "$TEMPLATES_DIR" || log WARN "Templates update failed or unavailable"
  fi
}

_has_source() {
  case ",$SOURCES," in
    *",$1,") return 0 ;;
    *) return 1 ;;
  esac
}

collect_urls() { # target_url, tdir
  local target="$1"; shift
  local tdir="$1"; shift
  local rawdir="$tdir/raw"; mkdir -p "$rawdir"

  # Helpers
  local domain; domain="$(echo "$target" | sed -E 's#^https?://##; s#/.*$##')"

  if _has_source "katana"; then
    run katana -rl "$THREADS" -u "$target" -silent -jc -jsl -aff -fx -timeout 10 -o "$rawdir/katana.txt" || true
  fi

  if _has_source "wayback"; then
    run bash -c "echo '$domain' | waybackurls > '$rawdir/waybackurls.txt'" || true
  fi

  if _has_source "gau"; then
    local subsFlag=""; [ "$INCLUDE_SUBS" = true ] && subsFlag="-subs"
    run bash -c "echo '$domain' | gauplus $subsFlag -t $THREADS -random-agent > '$rawdir/gauplus.txt'" || true
  fi

  if _has_source "hakrawler"; then
    run bash -c "echo '$target' | hakrawler -plain -depth 2 -t $THREADS > '$rawdir/hakrawler.txt'" || true
  fi

  if _has_source "paramspider"; then
    if command -v paramspider >/dev/null 2>&1; then
      if [ "$INCLUDE_SUBS" = true ]; then
        run bash -c "paramspider -d '$domain' -s | tee '$rawdir/paramspider.txt' >/dev/null" || true
      else
        run bash -c "paramspider -d '$domain' | tee '$rawdir/paramspider.txt' >/dev/null" || true
      fi
    else
      log WARN "Optional tool missing: paramspider (continuing)"
    fi
  fi
}

post_filter_inputs() { # keep any URL with ?k=v; drop obvious static/binary
  local in="$1"; local out="$2"
  awk '
    # Keep anything that has a query parameter
    /[?][A-Za-z0-9_.%-]+=/ { print; next }

    # Otherwise, drop common static/binary extensions at the end (optionally with ? or # tail)
    {
      line = $0
      # Case-insensitive check by lowering a copy (portable across awk variants)
      low = tolower(line)
      if (low ~ /[.](png|jpe?g|gif|webp|svg|ico|css|js|woff2?|ttf|otf|eot|mp4|mpe?g|avi|mov|pdf|zip|gz|tar|7z)([?#].*)?$/) next
      print
    }
  ' "$in" | sort -u > "$out"
}


dedupe_urls() { # tdir
  local tdir="$1"; shift
  local rawdir="$tdir/raw"; mkdir -p "$tdir"
  local tmp="$tdir/.urls.tmp"
  run bash -c "if compgen -G '$rawdir/*.txt' > /dev/null; then cat '$rawdir/'*.txt | uro | sort -u > '$tmp'; else : > '$tmp'; fi"
  post_filter_inputs "$tmp" "$tdir/urls.deduped.txt"
  rm -f "$tmp" || true
}

extract_inputs_get() { # tdir -> results/inputs_get.txt
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

rank_inputs() { # tdir -> results/inputs_ranked.txt (enhanced scoring v2)
  local tdir="$1"; shift
  local in="$tdir/results/inputs_get.txt"
  local out="$tdir/results/inputs_ranked.txt"
  [ -s "$in" ] || { : > "$out"; return 0; }

  awk -v IGNORECASE=1 -F'\?' '
  function b64ish(v){ return (length(v)>=8 && match(v, "^[A-Za-z0-9+/_%-]+={0,2}$")) }
  function urlish(v){ return match(v, "^(https?|ftp)://") }
  function pathish(v){ return (index(v, "/") || match(v, "%2[fF]")) }
  function dotdot(v){ return (index(v, "..") || match(v, "%2[eE]%2[eE]")) }

  function score_param(p, v,    s){
    s=0
    # names
    if(p ~ /(^|_)(url|redirect|return|dest|next|file|path|include|template)(_|$)/) s+=4
    if(p ~ /(^|_)(id|uid|pid|user|page|product|order|cat|endpoint|feed)(_|$)/)     s+=3
    if(p ~ /(^|_)(q|s|search|query|keyword|message|comment|content)(_|$)/)         s+=2
    # values
    if(v ~ /^[0-9]+$/) s+=1
    if(urlish(v))      s+=3
    if(pathish(v))     s+=1
    if(dotdot(v))      s+=2
    if(b64ish(v))      s+=1
    if(v ~ /[{][^}]*[}]/) s+=1
    return s
  }

  function host(url,    h){
    if (match(url, "^[Hh][Tt][Tt][Pp][Ss]?://")) url = substr(url, RSTART+RLENGTH)
    h=url
    if (match(h, "/")) h = substr(h, 1, RSTART-1)
    return h
  }
  function path(url,    p){
    p=url
    if (match(p, "^[Hh][Tt][Tt][Pp][Ss]?://")) p = substr(p, RSTART+RLENGTH)
    if (match(p, "/")) p = substr(p, RSTART); else p=""
    if (match(p, "[?]")) p = substr(p, 1, RSTART-1)
    if(p=="") p="/"
    return p
  }
  function ext(p,    e){ e=p; sub("^.*\\.","",e); if(e==p) return ""; return tolower(e) }
  function depth(p,   n){ n=split(p,a,"/"); return (n>0? n-1:0) }

  {
    url=$0
    h=host(url); p=path(url); e=ext(p); d=depth(p)

    base=0
    if(h ~ /(^|\.)(dev|staging|test|qa|beta|internal)\./) base+=2
    if(h ~ /(^|\.)api\./) base+=1
    if(p ~ /(admin|api|debug|render|export|download|include|template)/) base+=2
    if(e ~ /^(php|aspx|jsp|cgi|pl)$/) base+=2
    else if(e ~ /^(do)$/) base+=1
    if(d>=3) base+=1

    q=""; if(split($0,parts,"\?")==2) q=parts[2]
    n=split(q, kvs, /[&]/)
    maxp=0
    for(i=1;i<=n;i++){
      split(kvs[i], kv, /=/)
      kp=tolower(kv[1]); kvv=(length(kv)>1? kv[2]:"")
      sp=score_param(kp, kvv)
      if(sp>maxp) maxp=sp
    }

    sc=base + maxp
    printf("%d\t%s\n", sc, url)
  }' "$in" | sort -rnk1,1 | cut -f2- > "$out"

  log INFO "inputs_ranked.txt: $(wc -l < "$out" | tr -d ' ') prioritized URLs"
}

rerank_after_httpx() { # tdir -> results/inputs_ranked.v2.txt (requires jq)
  local tdir="$1"; shift
  local ranked="$tdir/results/inputs_ranked.txt"
  local out="$tdir/results/inputs_ranked.v2.txt"
  local meta="$tdir/alive/meta.json"
  [ -s "$ranked" ] || { : > "$out"; return 0; }
  command -v jq >/dev/null 2>&1 || { log WARN "jq missing, skip --rerank"; cp "$ranked" "$out" 2>/dev/null || :; return 0; }

  mkdir -p "$tdir/alive"
  run httpx -l "$ranked" -follow-redirects -status-code -content-type -tech-detect -title -json -silent > "$meta" || true

  # Join a simple boost score onto the original ranked list and resort
  jq -r '
    def boost:
      ( ( .status_code|tostring|tonumber ) as $s
      | (if ($s>=200 and $s<400 or $s==401 or $s==403 or ($s>=500 and $s<600)) then 2
         elif $s==404 then -1 else 0 end)
      + ( if (.content_type|ascii_downcase|test("html|json|xml")) then 1 else 0 end )
      + ( if (.tech|tostring|ascii_downcase|test("php|asp\.?net|jsp|spring|express")) then 1 else 0 end )
      );
    [ .url, (boost) ] | @tsv
  ' "$meta" \
  | awk 'NR==FNR{b[$1]=$2; next} {u=$0; s=(u in b? b[u]:0); print s "\t" u}' - "$ranked" \
  | awk '{print ($1+0) "\t" $2}' \
  | sort -rnk1,1 | cut -f2- > "$out"

  log INFO "inputs_ranked.v2.txt: $(wc -l < "$out" | tr -d ' ') re-ranked URLs"
}

cap_top_per_host() { # in -> out, cap per host
  local in="$1"; local out="$2"; local cap="$3"
  [ "$cap" -gt 0 ] || { cp "$in" "$out" 2>/dev/null || :; return 0; }
  awk -v CAP="$cap" -F/ '
  function host(u,  h){ h=u; sub(/^https?:\/\/(www\.)?/,"",h); sub(/\/.*$/,"",h); return h }
  { h=host($0); c[h]++; if(c[h]<=CAP) print }' "$in" > "$out"
}

prepare_fuzz_list() { # tdir -> results/fuzz_get.txt
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

check_liveness() { # tdir
  local tdir="$1"; shift
  local urls="$tdir/urls.deduped.txt"
  local alive_dir="$tdir/alive"; mkdir -p "$alive_dir"
  local out="$alive_dir/alive.txt"
  if [ ! -s "$urls" ]; then
    log WARN "No URLs to probe at $urls"; : > "$out"; return 0
  fi
  run httpx -silent -follow-redirects -mc "$HTTPX_MATCH_CODES" -retries 1 -timeout 10 -l "$urls" | sort -u > "$out"
  log INFO "Alive URLs: $(wc -l < "$out" | tr -d ' ')"
}

run_nuclei() { # tdir
  local tdir="$1"; shift
  local resdir="$tdir/results"; mkdir -p "$resdir"

  local resolved=""
  if [ -n "$NUCLEI_INPUT_FILE" ]; then
    resolved="$NUCLEI_INPUT_FILE"
  else
    # selection priority
    if   [ -s "$tdir/results/inputs_ranked.v2.txt" ]; then resolved="$tdir/results/inputs_ranked.v2.txt"
    elif [ -s "$tdir/results/inputs_ranked.top.txt" ]; then resolved="$tdir/results/inputs_ranked.top.txt"
    elif [ -s "$tdir/results/inputs_ranked.txt" ];    then resolved="$tdir/results/inputs_ranked.txt"
    elif [ -s "$tdir/results/inputs_get.txt" ];       then resolved="$tdir/results/inputs_get.txt"
    elif [ "$SCAN_SOURCE" = "alive" ] && [ -s "$tdir/alive/alive.txt" ]; then
         resolved="$tdir/alive/alive.txt"
    else resolved="$tdir/urls.deduped.txt"
    fi
  fi

  if [ ! -s "$resolved" ]; then
    log WARN "No input URLs for nuclei at $resolved"
    : > "$resdir/nuclei.jsonl"; return 0
  fi

  local base_args=(-l "$resolved" -t "$TEMPLATES_DIR" -jsonl -o "$resdir/nuclei.jsonl" -stats -rl "$THREADS" -c "$THREADS")
  if [ ${#NUCLEI_EXTRA_ARGS[@]} -gt 0 ]; then
    # shellcheck disable=SC2068
    base_args+=(${NUCLEI_EXTRA_ARGS[@]})
  fi
  run nuclei "${base_args[@]}"
}

write_summary() { # tdir, duration_sec
  local tdir="$1"; shift
  local duration="${1:-0}"; shift || true
  local resdir="$tdir/results"; mkdir -p "$resdir"
  local dedup="$tdir/urls.deduped.txt"
  local alive="$tdir/alive/alive.txt"
  local in_get="$tdir/results/inputs_get.txt"
  local in_rank="$tdir/results/inputs_ranked.txt"
  local in_rank_v2="$tdir/results/inputs_ranked.v2.txt"
  local in_rank_top="$tdir/results/inputs_ranked.top.txt"
  local jsonl="$resdir/nuclei.jsonl"
  local summary_txt="$resdir/summary.txt"
  local summary_json="$resdir/summary.json"

  local c_dedup=0 c_alive=0 c_in_get=0 c_in_rank=0 c_in_rank_v2=0 c_in_rank_top=0 c_find=0
  [ -f "$dedup" ] && c_dedup=$(wc -l < "$dedup" | tr -d ' ')
  [ -f "$alive" ] && c_alive=$(wc -l < "$alive" | tr -d ' ')
  [ -f "$in_get" ] && c_in_get=$(wc -l < "$in_get" | tr -d ' ')
  [ -f "$in_rank" ] && c_in_rank=$(wc -l < "$in_rank" | tr -d ' ')
  [ -f "$in_rank_v2" ] && c_in_rank_v2=$(wc -l < "$in_rank_v2" | tr -d ' ')
  [ -f "$in_rank_top" ] && c_in_rank_top=$(wc -l < "$in_rank_top" | tr -d ' ')
  [ -s "$jsonl" ] && c_find=$(wc -l < "$jsonl" | tr -d ' ')

  local sev_json='{}'
  if command -v jq >/dev/null 2>&1 && [ -s "$jsonl" ]; then
    sev_json=$(jq -r '. ["info"].severity // .info.severity? // empty' "$jsonl" 2>/dev/null | \
      awk '{a[tolower($0)]++} END{printf("{"); i=0; for (k in a){if(i++) printf(","); printf("\"%s\":%d",k,a[k])} printf("}") }')
  fi

  {
    echo "$TOOL_NAME v$VERSION summary"
    echo "Target: $(basename "$tdir")"
    echo "Duration: ${duration}s"
    echo "URLs (deduped): $c_dedup"
    echo "Alive URLs: $c_alive"
    echo "Inputs (GET): $c_in_get"
    echo "Ranked v1: $c_in_rank"
    echo "Ranked v2: $c_in_rank_v2"
    [ "$c_in_rank_top" -gt 0 ] && echo "Top-per-host: $c_in_rank_top"
    echo "Findings (total): $c_find"
    [ "$sev_json" != '{}' ] && echo "Severity breakdown: $sev_json"
  } > "$summary_txt"

  {
    echo -n '{'
    printf '"tool":"%s","version":"%s",' "$TOOL_NAME" "$VERSION"
    printf '"target":"%s",' "$(basename "$tdir")"
    printf '"duration_sec":%s,' "$duration"
    printf '"urls_total":%s,' "$c_dedup"
    printf '"urls_alive":%s,' "$c_alive"
    printf '"inputs_get":%s,' "$c_in_get"
    printf '"inputs_ranked":%s,' "$c_in_rank"
    printf '"inputs_ranked_v2":%s,' "$c_in_rank_v2"
    printf '"inputs_top_per_host":%s,' "$c_in_rank_top"
    printf '"findings_total":%s,' "$c_find"
    printf '"severity_counts":%s' "$sev_json"
    echo -n '}'
  } > "$summary_json"

  if [ "$HTML_REPORT" = true ] && command -v jq >/dev/null 2>&1 && [ -s "$jsonl" ]; then
    local html="$resdir/nuclei.html"
    {
      printf '<!doctype html><meta charset="utf-8"><title>Nuclei Report - %s</title>' "$(basename "$tdir")"
      printf '<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #ddd;padding:6px}th{background:#f3f3f3;text-align:left}tr:nth-child(even){background:#fafafa}.critical{color:#d32f2f}.high{color:#e65100}.medium{color:#f9a825}.low{color:#1976d2}</style>'
      printf '<h1>Nuclei Report - %s</h1>' "$(basename "$tdir")"
      printf '<p>Deduped: %s • Alive: %s • Inputs: %s • Ranked: %s • Findings: %s • Duration: %ss</p>' \
        "$c_dedup" "$c_alive" "$c_in_get" "$c_in_rank_v2" "$c_find" "$duration"
      printf '<table><thead><tr><th>Severity</th><th>Name</th><th>Template</th><th>Matched</th></tr></thead><tbody>'
      jq -r 'def esc(s): (s // "") | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;");
              . as $r | "<tr class=\"" + ((($r.info.severity // $r.severity // "")|ascii_downcase)) +
              "\"><td>" + esc($r.info.severity // $r.severity) + "</td><td>" + esc($r.info.name) +
              "</td><td>" + esc($r.templateID) + "</td><td>" + esc($r."matched-at" // $r.matchedAt // $r.url // $r.host) + "</td></tr>"' "$jsonl"
      printf '</tbody></table>'
    } > "$html" || true
  fi
}

# ---------- Driver ----------

process_target() { # target
  local target="$1"
  local target_url="$target"
  case "$target_url" in http://*|https://*) ;; *) target_url="https://$target_url";; esac
  local safe; safe="$(sanitize_name "$target")"

  WORKDIR="$OUTDIR_ROOT/$safe"; export TOOL_BASENAME="$safe"
  mkdir -p "$WORKDIR" "$WORKDIR/raw" "$WORKDIR/alive" "$WORKDIR/results" "$WORKDIR/logs"

  local tmpdir; tmpdir="$(mktemp -d -t threatlens.XXXXXX)"
  trap 'if [ -n "${tmpdir-}" ]; then rm -rf -- "$tmpdir"; fi' EXIT
  local start_ts end_ts duration; start_ts="$(date +%s)"

  log INFO "Processing $target -> $WORKDIR (phase=$PHASE resume=$RESUME sources=$SOURCES)"

  # If user provided nuclei input, mirror to dedup for summary consistency
  if [ -n "$NUCLEI_INPUT_FILE" ] && [ ! -s "$WORKDIR/urls.deduped.txt" ]; then
    cp -f "$NUCLEI_INPUT_FILE" "$WORKDIR/urls.deduped.txt" 2>/dev/null || true
  fi

  # PHASE: collect + dedupe + inputs + rank
  if [[ "$PHASE" =~ ^(all|collect|live|scan)$ ]]; then
    if [ -z "$NUCLEI_INPUT_FILE" ]; then
      if [ "$RESUME" = true ] && compgen -G "$WORKDIR/raw/*.txt" > /dev/null; then
        log INFO "Resume: raw/*.txt exists, skip collect"
      else
        collect_urls "$target_url" "$WORKDIR" || true
      fi
      if [ "$RESUME" = true ] && [ -s "$WORKDIR/urls.deduped.txt" ]; then
        log INFO "Resume: urls.deduped.txt exists, skip dedupe"
      else
        dedupe_urls "$WORKDIR"
      fi
      extract_inputs_get "$WORKDIR"
      rank_inputs "$WORKDIR"
      if [ "$RERANK" = true ]; then
        rerank_after_httpx "$WORKDIR"
      fi
      if [ "$TOP_PER_HOST" -gt 0 ] && [ -s "$WORKDIR/results/inputs_ranked.txt" ]; then
        local src="$WORKDIR/results/inputs_ranked.txt"
        [ -s "$WORKDIR/results/inputs_ranked.v2.txt" ] && src="$WORKDIR/results/inputs_ranked.v2.txt"
        cap_top_per_host "$src" "$WORKDIR/results/inputs_ranked.top.txt" "$TOP_PER_HOST"
      fi
    fi
  fi

  # Stop after inputs-only
  if [ "$INPUTS_ONLY" = true ]; then
    log INFO "Inputs ready: $WORKDIR/results/inputs_get.txt"
    [ "$FUZZIFY" = true ] && prepare_fuzz_list "$WORKDIR"
    end_ts="$(date +%s)"; duration=$(( end_ts - start_ts ))
    write_summary "$WORKDIR" "$duration"
    rm -rf "$tmpdir" || true; trap - EXIT; return 0
  fi

  # PHASE: live probe (only if using alive)
  if [[ "$PHASE" =~ ^(all|live|scan)$ ]]; then
    if [ "$SCAN_SOURCE" = "alive" ] && [ -z "$NUCLEI_INPUT_FILE" ]; then
      if [ "$RESUME" = true ] && [ -s "$WORKDIR/alive/alive.txt" ]; then
        log INFO "Resume: alive.txt exists, skip probe"
      else
        check_liveness "$WORKDIR"
      fi
    fi
  fi

  # Optional fuzz list
  [ "$FUZZIFY" = true ] && prepare_fuzz_list "$WORKDIR"

  # PHASE: scan
  if [[ "$PHASE" =~ ^(all|scan)$ ]]; then
    run_nuclei "$WORKDIR"
  fi

  end_ts="$(date +%s)"; duration=$(( end_ts - start_ts ))
  write_summary "$WORKDIR" "$duration"

  # Severity signaling
  if [ -n "$SIGNAL_SEVERITY" ] && command -v jq >/dev/null 2>&1; then
    local jsonl="$WORKDIR/results/nuclei.jsonl"
    if [ -s "$jsonl" ]; then
      local rank_target
      case "$SIGNAL_SEVERITY" in
        low) rank_target=1;; medium) rank_target=2;; high) rank_target=3;; critical) rank_target=4;;
        *) rank_target=0;;
      esac
      if [ "$rank_target" -gt 0 ]; then
        local found
        found=$(jq -r 'def rank(s): if s=="low" then 1 elif s=="medium" then 2 elif s=="high" then 3 elif s=="critical" then 4 else 0 end;
                       select((.info.severity // .severity // "") as $s | rank($s) >= '"$rank_target"') | 1' "$jsonl" | head -n1)
        if [ -n "$found" ]; then
          log WARN "Findings >= $SIGNAL_SEVERITY present — exiting with code 2"
          exit 2
        fi
      fi
    fi
  fi

  rm -rf "$tmpdir" || true
  trap - EXIT
  log INFO "Completed $target"
}

main() {
  parse_args "$@"

  # Dependencies
  if [ -n "$NUCLEI_INPUT_FILE" ]; then
    require_tool nuclei
    command -v jq >/dev/null 2>&1 || log WARN "jq missing: severity breakdown/HTML limited"
  else
    # Required for recon/scan
    # katana+uro+httpx+nuclei are the core; archives/crawlers are optional
    require_tool uro
    require_tool nuclei
    require_tool httpx
    if _has_source "katana"; then require_tool katana; fi
    if _has_source "wayback" && ! command -v waybackurls >/dev/null 2>&1; then log WARN "Optional tool missing: waybackurls"; fi
    if _has_source "gau"     && ! command -v gauplus    >/dev/null 2>&1; then log WARN "Optional tool missing: gauplus"; fi
    if _has_source "hakrawler" && ! command -v hakrawler >/dev/null 2>&1; then log WARN "Optional tool missing: hakrawler"; fi
    if _has_source "paramspider" && ! command -v paramspider >/dev/null 2>&1; then log WARN "Optional tool missing: paramspider"; fi
    command -v jq >/dev/null 2>&1 || log WARN "jq missing: some features (HTML, --signal, --rerank) limited"
  fi

  mkdir -p "$OUTDIR_ROOT"
  prepare_templates

  if [ "$PARALLEL" -le 1 ] || [ "$DRY_RUN" = true ]; then
    for t in "${TARGETS[@]}"; do process_target "$t"; done
  else
    for t in "${TARGETS[@]}"; do
      process_target "$t" &
      while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n || true; done
    done
    wait || true
  fi
}

main "$@"

