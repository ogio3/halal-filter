#!/usr/bin/env bash
# fetch_lists.sh — Download and cache community blocklists for filter.bin build.
#
# Usage:
#   ./scripts/fetch_lists.sh                    # standard tier (default)
#   ./scripts/fetch_lists.sh --tier extended    # standard + extended
#   ./scripts/fetch_lists.sh --force            # ignore cache, re-download all
#
# Downloads are cached in data/cache/ with 24h TTL.
# After fetching, run: cargo run --release --bin build_filter -- -o filter.bin data/cache/*.txt data/trackers/islamic_apps.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CACHE_DIR="$PROJECT_DIR/data/cache"
CACHE_TTL=86400  # 24 hours in seconds

TIER="standard"
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --tier)    TIER="$2"; shift 2 ;;
        --force)   FORCE=true; shift ;;
        -h|--help) echo "Usage: $0 [--tier standard|extended] [--force]"; exit 0 ;;
        *)         echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$CACHE_DIR"

# Sources: name, url, format, tier
# Parsed from sources.toml manually (avoids toml parser dependency)
declare -a SOURCES

# Standard tier
SOURCES+=(
    "steven-black-hosts|https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|hosts|standard"
    "peter-lowe-adservers|https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext|domains|standard"
    "adguard-dns|https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt|adblock|standard"
    "hagezi-pro|https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt|domains|standard"
    "1hosts-lite|https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt|domains|standard"
)

# Extended tier (only fetched if --tier extended)
SOURCES+=(
    "oisd-big|https://big.oisd.nl/domainswild2|domains|extended"
    "energized-blu|https://block.energized.pro/bluGo/formats/domains.txt|domains|extended"
    "hagezi-proplus|https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt|domains|extended"
)

fetch_count=0
skip_count=0
fail_count=0

for entry in "${SOURCES[@]}"; do
    IFS='|' read -r name url format source_tier <<< "$entry"

    # Skip extended-only sources unless requested
    if [[ "$source_tier" == "extended" && "$TIER" != "extended" ]]; then
        continue
    fi

    cache_file="$CACHE_DIR/${name}.txt"

    # Check cache freshness
    if [[ -f "$cache_file" && "$FORCE" != "true" ]]; then
        file_age=$(( $(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || stat -c %Y "$cache_file" 2>/dev/null) ))
        if [[ $file_age -lt $CACHE_TTL ]]; then
            line_count=$(wc -l < "$cache_file" | tr -d ' ')
            echo "  cached: $name ($line_count lines, ${file_age}s old)"
            skip_count=$((skip_count + 1))
            continue
        fi
    fi

    echo -n "  fetch:  $name ... "

    if curl -fsSL --max-time 60 --retry 2 -o "$cache_file.tmp" "$url" 2>/dev/null; then
        mv "$cache_file.tmp" "$cache_file"
        line_count=$(wc -l < "$cache_file" | tr -d ' ')
        echo "ok ($line_count lines)"
        fetch_count=$((fetch_count + 1))
    else
        echo "FAILED"
        rm -f "$cache_file.tmp"
        fail_count=$((fail_count + 1))
    fi
done

echo ""
echo "summary: $fetch_count fetched, $skip_count cached, $fail_count failed"
echo ""

# Count total available files
total_files=$(ls "$CACHE_DIR"/*.txt 2>/dev/null | wc -l | tr -d ' ')
echo "cache: $total_files list files in $CACHE_DIR/"
echo ""
echo "next step:"
echo "  cargo run --release --bin build_filter -- \\"
echo "    -o android/app/src/main/assets/filter.bin \\"
echo "    data/trackers/islamic_apps.txt \\"
echo "    $CACHE_DIR/*.txt"
