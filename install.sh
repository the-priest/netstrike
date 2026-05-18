#!/bin/bash
# NetStrike installer
# Installs all dependencies, the binary, icon, and desktop entry.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run as root: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_PKGS="python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 \
aircrack-ng nmap iw \
hicolor-icon-theme desktop-file-utils libgtk-4-bin"

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[!] This installer assumes a Debian/Kali system with apt."
    echo "    Install manually: $BASE_PKGS pkexec"
    exit 1
fi

echo "[*] Updating package lists..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq

echo "[*] Installing base dependencies..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $BASE_PKGS

# pkexec lives in different packages across Debian releases:
#   bookworm+ / Kali rolling : 'pkexec'
#   bullseye and older       : 'policykit-1'
#   some derivatives         : 'polkitd' bundles it
echo "[*] Installing pkexec..."
PKEXEC_INSTALLED=0
if command -v pkexec >/dev/null 2>&1; then
    PKEXEC_INSTALLED=1
    echo "    -> already present"
else
    for pkg in pkexec policykit-1 polkitd; do
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" 2>/dev/null; then
                echo "    -> installed $pkg"
                PKEXEC_INSTALLED=1
                break
            fi
        fi
    done
fi

if [ "$PKEXEC_INSTALLED" -eq 0 ] && ! command -v pkexec >/dev/null 2>&1; then
    echo "[!] No pkexec package found in this apt repo."
    echo "    App will install — launch from terminal with: sudo netstrike"
fi

# Verify Python GTK4/libadwaita bindings actually import
if ! python3 -c "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1'); from gi.repository import Gtk, Adw" 2>/dev/null; then
    echo "[!] Python GTK4/libadwaita bindings not importable."
    echo "    Check: python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1"
    exit 1
fi

echo "[*] Installing binary -> /usr/local/bin/netstrike"
install -m 755 "$SCRIPT_DIR/netstrike.py" /usr/local/bin/netstrike

echo "[*] Installing icon -> /usr/share/icons/hicolor/scalable/apps/"
install -D -m 644 "$SCRIPT_DIR/netstrike.svg" \
    /usr/share/icons/hicolor/scalable/apps/netstrike.svg

echo "[*] Installing desktop entry -> /usr/share/applications/"
if command -v pkexec >/dev/null 2>&1; then
    install -m 644 "$SCRIPT_DIR/netstrike.desktop" \
        /usr/share/applications/netstrike.desktop
else
    # Strip pkexec from Exec line — user will have to launch with sudo
    sed 's|Exec=pkexec |Exec=|' "$SCRIPT_DIR/netstrike.desktop" \
        > /usr/share/applications/netstrike.desktop
    chmod 644 /usr/share/applications/netstrike.desktop
    echo "    -> pkexec missing; .desktop launches netstrike directly"
fi

echo "[*] Refreshing caches..."
gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database /usr/share/applications 2>/dev/null || true

echo
echo "[+] Installed."
if command -v pkexec >/dev/null 2>&1; then
    echo "    Launch: tap NetStrike in the app drawer (will prompt for root via pkexec)"
else
    echo "    Launch: sudo netstrike  (no pkexec available)"
fi
echo "    Activity log: ~/.config/netstrike/activity.log"
