#!/bin/bash
set -Eeuo pipefail

#
# Packages this directory into cert-cleanup.xpi (a WebExtension is just a zip
# file with a particular layout). Run from anywhere; output goes to dist/
# next to this script.
#
# Usage:
#   ./build.sh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="${SCRIPT_DIR}/dist"
OUT="${DIST}/cert-cleanup.xpi"

mkdir -p "${DIST}"
rm -f "${OUT}"

cd "${SCRIPT_DIR}"

zip -r -X "${OUT}" \
    manifest.json \
    background.js \
    options.html \
    options.js \
    experiments \
    -x '*.DS_Store'

echo "Built: ${OUT}"
