#!/bin/bash
# NetStrike installer
# Installs all dependencies, the binary, icon, and desktop entry.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run as root: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APT_PKGS="python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 \
aircrack-ng nmap iw policykit-1 \
hicolor-icon-theme desktop-file-utils"

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] This installer assumes a Debian/Kali system with apt."
    echo "    Install manually: $APT_PKGS"
    exit 1
fi

echo "[*] Updating package lists..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq

echo "[*] Installing dependencies..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $APT_PKGS

# Verify Python bindings actually work after install
if ! python3 -c "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1'); from gi.repository import Gtk, Adw" 2>/dev/null; then
    echo "[!] Python GTK4/libadwaita bindings still not importable after install."
    echo "    Check: python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1"
    exit 1
fi

echo "[*] Installing binary -> /usr/local/bin/netstrike"
install -m 755 "$SCRIPT_DIR/netstrike.py" /usr/local/bin/netstrike

echo "[*] Installing icon -> /usr/share/icons/hicolor/scalable/apps/"
install -D -m 644 "$SCRIPT_DIR/netstrike.svg" \
    /usr/share/icons/hicolor/scalable/apps/netstrike.svg

echo "[*] Installing desktop entry -> /usr/share/applications/"
install -m 644 "$SCRIPT_DIR/netstrike.desktop" \
    /usr/share/applications/netstrike.desktop

echo "[*] Refreshing caches..."
gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database /usr/share/applications 2>/dev/null || true

echo
echo "[+] Installed."
echo "    Launch from the app drawer, or run: pkexec /usr/local/bin/netstrike"
echo "    Activity log: ~/.config/netstrike/activity.log"
