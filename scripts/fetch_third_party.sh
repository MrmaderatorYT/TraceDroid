#!/usr/bin/env bash
# Fetches the pinned libyara source tree used by the native build (the only build-time download
# besides Gradle dependencies). The app itself never touches the network.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/app/src/main/cpp/third_party/yara"
VERSION="v4.5.2"
if [ -f "$DEST/libyara/libyara.c" ]; then
    echo "libyara already present at $DEST"
    exit 0
fi
mkdir -p "$(dirname "$DEST")"
git clone --depth 1 --branch "$VERSION" https://github.com/VirusTotal/yara.git "$DEST"
