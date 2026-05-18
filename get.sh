#!/bin/bash
# NetStrike one-line installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/the-priest/netstrike/main/get.sh | sudo bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run with sudo:"
    echo "    curl -fsSL https://raw.githubusercontent.com/the-priest/netstrike/main/get.sh | sudo bash"
    exit 1
fi

REPO="https://github.com/the-priest/netstrike.git"
TMPDIR="$(mktemp -d -t netstrike-XXXXXX)"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

if ! command -v git >/dev/null 2>&1; then
    echo "[*] Installing git..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git
fi

echo "[*] Cloning $REPO"
git clone --depth=1 "$REPO" "$TMPDIR/netstrike"

echo "[*] Running installer"
cd "$TMPDIR/netstrike"
chmod +x install.sh
./install.sh
