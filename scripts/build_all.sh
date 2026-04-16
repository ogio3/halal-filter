#!/usr/bin/env bash
# build_all.sh — Fetch lists + build filter.bin in one command.
#
# Usage:
#   ./scripts/build_all.sh                    # standard tier
#   ./scripts/build_all.sh --tier extended    # include extended lists
#   ./scripts/build_all.sh --force            # force re-download

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Step 1: Fetch blocklists ==="
"$SCRIPT_DIR/fetch_lists.sh" "$@"

echo ""
echo "=== Step 2: Build XOR16 filter ==="
cargo run --release --bin build_filter -- \
    -o android/app/src/main/assets/filter.bin \
    data/trackers/islamic_apps.txt \
    data/cache/*.txt

echo ""
echo "=== Step 3: Verify ==="
FILTER_SIZE=$(stat -f %z android/app/src/main/assets/filter.bin 2>/dev/null || stat -c %s android/app/src/main/assets/filter.bin 2>/dev/null)
echo "filter.bin: $FILTER_SIZE bytes ($(echo "scale=1; $FILTER_SIZE / 1024" | bc) KB)"
echo ""
echo "Done. Ready to build APK:"
echo "  cd android && ./gradlew assembleDebug"
