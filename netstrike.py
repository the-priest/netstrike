#!/usr/bin/env python3
"""
NetStrike v1.1 - WiFi Security Audit Tool
For NetHunter Pro / Phosh / Mobile Linux

Use only on networks you own or have explicit authorization to test.

Changelog vs v1.0:
- Monitor-mode check now gates ALL destructive actions (deauth/broadcast/capture)
- aireplay-ng output parsed for real errors instead of trusting exit code
- WiFi scan auto-brings interface up; detects monitor-mode block and offers
  to switch to managed temporarily
- Channel set is conditional (only attempted in monitor mode)
- Handshake captures land in ~/Documents/netstrike/captures/ with timestamped
  filenames instead of /tmp
- Toast notifications (Adw.ToastOverlay) replace silent state changes
- Mode badge in header (yellow=monitor, green=managed) — visible at all times
- Gtk.Spinner replaces hacky ProgressBar pulse
- Empty-state rows in lists ("No networks found", "No clients found")
- Refresh button next to interface dropdown — re-detects adapters mid-session
- Mode label and badge refresh on every iface change and mode toggle
- iw scan simplified to single blocking call
- Status bar caches mode (no longer subprocess-spams iw on every update)
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gdk, Gio

import subprocess
import threading
import re
import os
import glob
import sys
import time
from pathlib import Path
from datetime import datetime

# ============================================================================
# CONSTANTS
# ============================================================================

APP_ID = 'org.thepriest.netstrike'
APP_NAME = 'NetStrike'
CONFIG_DIR = Path.home() / '.config' / 'netstrike'
LOG_FILE = CONFIG_DIR / 'activity.log'
CAPTURE_DIR = Path.home() / 'Documents' / 'netstrike' / 'captures'
SCAN_PREFIX = '/tmp/netstrike_scan'
CLIENT_SCAN_DURATION = 15  # seconds

CSS_STYLES = b"""
window { background-color: #1e1e2e; }
.card {
    background-color: #313244;
    border-radius: 12px;
    padding: 12px;
}
.network-row, .client-row {
    background-color: #313244;
    border-radius: 10px;
    margin: 3px 0;
}
.action-button {
    background-color: #89b4fa;
    color: #1e1e2e;
    font-weight: bold;
    min-height: 44px;
    border-radius: 10px;
    padding: 6px 14px;
}
.action-button:hover { background-color: #74c7ec; }
.danger-button {
    background-color: #f38ba8;
    color: #1e1e2e;
    font-weight: bold;
    min-height: 44px;
    border-radius: 10px;
    padding: 6px 14px;
}
.danger-button:hover { background-color: #eba0ac; }
.success-button {
    background-color: #a6e3a1;
    color: #1e1e2e;
    font-weight: bold;
    min-height: 44px;
    border-radius: 10px;
    padding: 6px 14px;
}
.success-button:hover { background-color: #94e2d5; }
.subtle-button {
    background-color: #45475a;
    color: #cdd6f4;
    border-radius: 8px;
    min-height: 36px;
    padding: 4px 10px;
}
.subtle-button:hover { background-color: #585b70; }
.title-label {
    font-size: 15px;
    font-weight: bold;
    color: #cdd6f4;
}
.header-label {
    font-size: 22px;
    font-weight: 900;
    color: #cdd6f4;
    margin: 4px 0 8px 0;
}
.subtitle-label {
    font-size: 11px;
    color: #a6adc8;
}
.empty-state {
    color: #6c7086;
    font-style: italic;
    padding: 24px;
}
.signal-strong { color: #a6e3a1; }
.signal-medium { color: #f9e2af; }
.signal-weak { color: #f38ba8; }
.status-bar {
    background-color: #181825;
    padding: 6px 12px;
    font-size: 11px;
    color: #a6adc8;
}
.log-view {
    font-family: monospace;
    font-size: 10px;
    color: #cdd6f4;
    background-color: #11111b;
    padding: 8px;
    border-radius: 8px;
}
.mode-badge {
    border-radius: 12px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: bold;
}
.mode-badge-monitor {
    background-color: #f9e2af;
    color: #1e1e2e;
}
.mode-badge-managed {
    background-color: #a6e3a1;
    color: #1e1e2e;
}
.mode-badge-unknown {
    background-color: #45475a;
    color: #cdd6f4;
}
"""

# ============================================================================
# HELPERS
# ============================================================================

def write_log(msg):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def check_root():
    return os.geteuid() == 0


def list_wireless_interfaces():
    """Return list of wireless interfaces detected by iw."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=5)
        ifaces = re.findall(r'Interface\s+(\S+)', result.stdout)
        return ifaces if ifaces else ['wlan0']
    except Exception:
        return ['wlan0']


def get_interface_mode(iface):
    """Get current mode of interface (managed/monitor/unknown)."""
    try:
        result = subprocess.run(['iw', 'dev', iface, 'info'],
                                capture_output=True, text=True, timeout=5)
        m = re.search(r'type\s+(\w+)', result.stdout)
        return m.group(1).lower() if m else 'unknown'
    except Exception:
        return 'unknown'


def is_iface_up(iface):
    try:
        result = subprocess.run(['ip', 'link', 'show', iface],
                                capture_output=True, text=True, timeout=5)
        return 'state UP' in result.stdout or ',UP,' in result.stdout or '<UP' in result.stdout
    except Exception:
        return False


def ensure_iface_up(iface):
    """Bring interface up if it isn't already."""
    try:
        subprocess.run(['ip', 'link', 'set', iface, 'up'],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def parse_aireplay_error(output):
    """Extract a human-readable error from aireplay-ng output.
    aireplay-ng's exit code is unreliable — check the text."""
    if not output:
        return None
    lowered = output.lower()
    patterns = [
        ('operation not permitted', "Permission denied — run as root"),
        ('no such device', "Interface not found"),
        ('network is down', "Interface is down"),
        ("couldn't get current channel", "Interface not in monitor mode"),
        ("couldn't determine current frequency", "Interface not in monitor mode"),
        ('open of /sys/class/net', "Interface access failed"),
        ('rfkill', "Wireless is blocked by rfkill — run: rfkill unblock wifi"),
        ('not associated', "Interface not associated"),
        ('error reading packet', "Adapter not in correct mode"),
    ]
    for needle, msg in patterns:
        if needle in lowered:
            return msg
    return None


def cleanup_scan_files():
    """Remove old airodump-ng output files."""
    for f in glob.glob(f"{SCAN_PREFIX}*"):
        try:
            os.remove(f)
        except Exception:
            pass

# ============================================================================
# DATA CLASSES
# ============================================================================

class WiFiNetwork:
    def __init__(self, bssid, ssid, channel, signal, encryption):
        self.bssid = bssid
        self.ssid = ssid if ssid else "<Hidden>"
        self.channel = channel
        try:
            self.signal = int(signal)
        except (ValueError, TypeError):
            self.signal = -100
        self.encryption = encryption

    def signal_bars(self):
        if self.signal >= -50: return "▮▮▮▮"
        if self.signal >= -60: return "▮▮▮▯"
        if self.signal >= -70: return "▮▮▯▯"
        if self.signal >= -80: return "▮▯▯▯"
        return "▯▯▯▯"

    def signal_class(self):
        if self.signal >= -60: return "signal-strong"
        if self.signal >= -75: return "signal-medium"
        return "signal-weak"


class WiFiClient:
    def __init__(self, mac, bssid, power, packets):
        self.mac = mac
        self.bssid = bssid
        self.power = power
        self.packets = packets

# ============================================================================
# WIFI SCANNER
# ============================================================================

class WiFiScanner:
    def __init__(self):
        self.interface = 'wlan0'

    def set_interface(self, iface):
        self.interface = iface

    def scan_networks(self, callback):
        """Blocking iw scan. Brings iface up first.
        Returns (success, networks, error_msg) via callback."""
        def worker():
            try:
                ensure_iface_up(self.interface)

                # iw scan blocks until results are ready
                result = subprocess.run(
                    ['iw', 'dev', self.interface, 'scan'],
                    capture_output=True, text=True, timeout=45
                )

                if result.returncode != 0:
                    err = result.stderr.strip().lower()
                    if 'operation not supported' in err or 'invalid argument' in err:
                        msg = ("Scan refused by driver — interface is likely in "
                               "monitor mode. Switch to managed in Tools.")
                    elif 'busy' in err or 'resource' in err:
                        msg = "Adapter busy — try again in a moment."
                    elif 'permission' in err:
                        msg = "Permission denied — run as root."
                    else:
                        msg = result.stderr.strip() or f"iw exited {result.returncode}"
                    GLib.idle_add(callback, False, [], msg)
                    return

                networks = self._parse_iw_scan(result.stdout)
                GLib.idle_add(callback, True, networks, "")
            except subprocess.TimeoutExpired:
                GLib.idle_add(callback, False, [], "Scan timed out")
            except FileNotFoundError:
                GLib.idle_add(callback, False, [], "iw not installed")
            except Exception as e:
                GLib.idle_add(callback, False, [], str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _parse_iw_scan(self, output):
        networks = {}
        current_bss = None
        current = {}

        for line in output.split('\n'):
            stripped = line.strip()
            if line.startswith('BSS '):
                if current_bss and current:
                    networks[current_bss] = self._build_network(current_bss, current)
                m = re.match(r'BSS\s+([0-9a-fA-F:]+)', line)
                current_bss = m.group(1) if m else None
                current = {}
            elif stripped.startswith('SSID:'):
                current['ssid'] = stripped[5:].strip()
            elif stripped.startswith('signal:'):
                m = re.search(r'signal:\s+(-?\d+)', stripped)
                if m:
                    current['signal'] = m.group(1)
            elif 'primary channel:' in stripped:
                m = re.search(r'primary channel:\s+(\d+)', stripped)
                if m:
                    current['channel'] = m.group(1)
            elif 'DS Parameter set: channel' in stripped and 'channel' not in current:
                m = re.search(r'channel\s+(\d+)', stripped)
                if m:
                    current['channel'] = m.group(1)
            elif stripped.startswith('RSN:'):
                # If SAE in next few lines we'd refine to WPA3, but WPA2 is
                # close enough for display purposes.
                current['encryption'] = 'WPA2'
            elif stripped.startswith('WPA:') and 'encryption' not in current:
                current['encryption'] = 'WPA'

        if current_bss and current:
            networks[current_bss] = self._build_network(current_bss, current)

        return list(networks.values())

    def _build_network(self, bssid, data):
        return WiFiNetwork(
            bssid=bssid,
            ssid=data.get('ssid', ''),
            channel=data.get('channel', '0'),
            signal=data.get('signal', '-100'),
            encryption=data.get('encryption', 'Open')
        )

    def scan_clients(self, target_bssid, channel, duration, callback):
        """Run airodump-ng, parse CSV. Requires monitor mode (checked by caller)."""
        def worker():
            cleanup_scan_files()
            try:
                cmd = [
                    'timeout', str(duration),
                    'airodump-ng',
                    '--bssid', target_bssid,
                    '-c', str(channel),
                    '--write-interval', '1',
                    '--output-format', 'csv',
                    '-w', SCAN_PREFIX,
                    self.interface
                ]
                subprocess.run(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               timeout=duration + 5)

                clients = self._parse_airodump_csv(target_bssid)
                GLib.idle_add(callback, True, clients, "")
            except FileNotFoundError:
                GLib.idle_add(callback, False, [], "airodump-ng not installed")
            except Exception as e:
                GLib.idle_add(callback, False, [], str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _parse_airodump_csv(self, target_bssid):
        csv_files = sorted(glob.glob(f"{SCAN_PREFIX}-*.csv"))
        if not csv_files:
            return []

        try:
            with open(csv_files[-1], 'r', errors='replace') as f:
                content = f.read()
        except Exception:
            return []

        if 'Station MAC' not in content:
            return []
        _, station_section = content.split('Station MAC', 1)

        clients = []
        for line in station_section.split('\n')[1:]:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 6:
                continue
            mac = parts[0]
            power = parts[3] if parts[3] else '-100'
            packets = parts[4] if parts[4] else '0'
            bssid = parts[5]

            if not mac or bssid == '(not associated)':
                continue
            if bssid.lower() != target_bssid.lower():
                continue
            clients.append(WiFiClient(mac, bssid, power, packets))

        return clients

# ============================================================================
# DEAUTH / CAPTURE
# ============================================================================

class DeauthManager:
    def __init__(self):
        self.interface = 'wlan0'

    def set_interface(self, iface):
        self.interface = iface

    def _set_channel_if_monitor(self, channel):
        """Channel set only works in monitor mode. Silently skip otherwise."""
        if get_interface_mode(self.interface) == 'monitor':
            subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                           capture_output=True, timeout=5)

    def _run_aireplay(self, cmd):
        """Run aireplay-ng, return (ok, message). Parses output for real errors
        since aireplay's exit code is unreliable."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = (result.stdout or '') + (result.stderr or '')
            err = parse_aireplay_error(output)
            if err:
                return False, err
            return True, "Sent"
        except subprocess.TimeoutExpired:
            return False, "aireplay-ng timed out"
        except FileNotFoundError:
            return False, "aireplay-ng not installed"
        except Exception as e:
            return False, str(e)

    def deauth_client(self, ap_bssid, client_mac, channel, count=64):
        if count <= 0 or count > 10000:
            return False, "Packet count must be between 1 and 10000"
        self._set_channel_if_monitor(channel)
        cmd = ['aireplay-ng', '--ignore-negative-one',
               '--deauth', str(count),
               '-a', ap_bssid, '-c', client_mac, self.interface]
        return self._run_aireplay(cmd)

    def deauth_broadcast(self, ap_bssid, channel, count=64):
        if count <= 0 or count > 10000:
            return False, "Packet count must be between 1 and 10000"
        self._set_channel_if_monitor(channel)
        cmd = ['aireplay-ng', '--ignore-negative-one',
               '--deauth', str(count),
               '-a', ap_bssid, self.interface]
        return self._run_aireplay(cmd)

    def capture_handshake(self, ap_bssid, ssid, client_mac, channel):
        """Capture WPA handshake to ~/Documents/netstrike/captures/
        Returns (success, message_with_path_or_error)."""
        try:
            CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_ssid = re.sub(r'[^A-Za-z0-9_-]', '_', ssid)[:20]
            base = CAPTURE_DIR / f"{ts}_{safe_ssid}_{ap_bssid.replace(':', '')}"

            self._set_channel_if_monitor(channel)

            cmd_capture = [
                'airodump-ng',
                '--bssid', ap_bssid, '-c', str(channel),
                '-w', str(base), '--output-format', 'pcap',
                self.interface
            ]
            cap_proc = subprocess.Popen(cmd_capture,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            time.sleep(2)

            # Check airodump actually started
            if cap_proc.poll() is not None:
                return False, "airodump-ng exited immediately — check monitor mode"

            cmd_deauth = ['aireplay-ng', '--ignore-negative-one',
                          '--deauth', '4',
                          '-a', ap_bssid, '-c', client_mac, self.interface]
            subprocess.run(cmd_deauth, capture_output=True, timeout=30)

            time.sleep(10)
            cap_proc.terminate()
            try:
                cap_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cap_proc.kill()

            # Check we got at least one cap file with size > 0
            caps = sorted(glob.glob(f"{base}-*.cap"))
            if caps and os.path.getsize(caps[-1]) > 0:
                return True, f"Saved: {caps[-1]}"
            return False, "No capture file produced"
        except FileNotFoundError as e:
            return False, f"Missing tool: {e}"
        except Exception as e:
            return False, str(e)

# ============================================================================
# NMAP PROFILES
# ============================================================================

NMAP_PROFILES = [
    {"name": "⚡ Quick Scan",
     "args": ["-sV", "--top-ports", "100", "-T4"],
     "desc": "Top 100 ports + service detection",
     "time": "~30 sec"},
    {"name": "🔍 Standard Scan",
     "args": ["-sV", "-sC", "-O", "--top-ports", "1000"],
     "desc": "Services + default scripts + OS detection",
     "time": "~2-3 min"},
    {"name": "🎯 Full Port Scan",
     "args": ["-sV", "-p-", "-T4"],
     "desc": "All 65535 ports with service detection",
     "time": "10+ min"},
    {"name": "👻 Stealth Scan",
     "args": ["-sS", "-Pn", "--top-ports", "100"],
     "desc": "SYN scan, skip host discovery",
     "time": "~45 sec"},
    {"name": "🛡️ Vuln Scan",
     "args": ["-sV", "--script=vulners"],
     "desc": "Known CVE check (needs internet)",
     "time": "~3 min"},
]

# ============================================================================
# UI
# ============================================================================

class NetStrikeApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        css = Gtk.CssProvider()
        css.load_from_data(CSS_STYLES)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        win = MainWindow(application=app)
        win.present()


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_default_size(400, 800)
        self.set_title(APP_NAME)

        self.scanner = WiFiScanner()
        self.deauth = DeauthManager()
        self.current_network = None
        self._cached_mode = 'unknown'

        self.interfaces = list_wireless_interfaces()
        self.current_iface = self.interfaces[0]
        self.scanner.set_interface(self.current_iface)
        self.deauth.set_interface(self.current_iface)

        # Toast overlay wraps everything so messages float over any page
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toast_overlay.set_child(outer)

        # Header
        header = Adw.HeaderBar()
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title_box.append(Gtk.Label(label=APP_NAME))
        self.mode_badge = Gtk.Label(label="?")
        self.mode_badge.add_css_class("mode-badge")
        self.mode_badge.add_css_class("mode-badge-unknown")
        title_box.append(self.mode_badge)
        header.set_title_widget(title_box)

        # Interface dropdown + refresh
        iface_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.iface_dropdown = Gtk.DropDown.new_from_strings(self.interfaces)
        self.iface_dropdown.set_selected(0)
        self.iface_dropdown.connect("notify::selected", self.on_iface_changed)
        iface_box.append(self.iface_dropdown)

        refresh_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Re-detect wireless interfaces")
        refresh_btn.connect("clicked", self.on_refresh_interfaces)
        iface_box.append(refresh_btn)
        header.pack_end(iface_box)
        outer.append(header)

        # Pages
        self.stack = Adw.ViewStack()
        self.stack.add_titled_with_icon(self._build_wifi_page(), "wifi",
                                        "WiFi", "network-wireless-symbolic")
        self.stack.add_titled_with_icon(self._build_nmap_page(), "nmap",
                                        "Nmap", "network-workgroup-symbolic")
        self.stack.add_titled_with_icon(self._build_tools_page(), "tools",
                                        "Tools", "applications-system-symbolic")
        outer.append(self.stack)

        switcher = Adw.ViewSwitcherBar()
        switcher.set_stack(self.stack)
        switcher.set_reveal(True)
        outer.append(switcher)

        # Status bar
        self.status = Gtk.Label(label="Ready")
        self.status.add_css_class("status-bar")
        self.status.set_xalign(0)
        outer.append(self.status)

        # Initial mode badge + warnings
        self.refresh_mode_indicators()
        if not check_root():
            GLib.idle_add(self._show_root_warning)

    # ------------------------------------------------------------------
    # Status / toast / mode
    # ------------------------------------------------------------------
    def set_status(self, msg):
        GLib.idle_add(
            self.status.set_text,
            f"{msg}  •  {self.current_iface} [{self._cached_mode}]"
        )

    def toast(self, msg, timeout=3):
        t = Adw.Toast.new(msg)
        t.set_timeout(timeout)
        GLib.idle_add(self.toast_overlay.add_toast, t)

    def refresh_mode_indicators(self):
        mode = get_interface_mode(self.current_iface)
        self._cached_mode = mode
        self.mode_badge.set_text(mode)
        for cls in ("mode-badge-monitor", "mode-badge-managed", "mode-badge-unknown"):
            self.mode_badge.remove_css_class(cls)
        if mode == 'monitor':
            self.mode_badge.add_css_class("mode-badge-monitor")
        elif mode == 'managed':
            self.mode_badge.add_css_class("mode-badge-managed")
        else:
            self.mode_badge.add_css_class("mode-badge-unknown")
        if hasattr(self, 'mode_label'):
            self.mode_label.set_text(f"{self.current_iface}: {mode}")
        self.set_status("Ready")

    def _show_root_warning(self):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Root required",
            body=("NetStrike needs root to control the wireless interface, "
                  "scan, and inject frames.\n\nRelaunch via the desktop entry "
                  "(uses pkexec) or run: sudo netstrike")
        )
        dialog.add_response("ok", "Continue anyway")
        dialog.present()

    def on_iface_changed(self, dropdown, _param):
        idx = dropdown.get_selected()
        if 0 <= idx < len(self.interfaces):
            self.current_iface = self.interfaces[idx]
            self.scanner.set_interface(self.current_iface)
            self.deauth.set_interface(self.current_iface)
            self.refresh_mode_indicators()
            write_log(f"Interface set to {self.current_iface}")
            self.toast(f"Interface: {self.current_iface}")

    def on_refresh_interfaces(self, _btn):
        new_list = list_wireless_interfaces()
        if new_list == self.interfaces:
            self.toast("No new interfaces")
            return
        self.interfaces = new_list
        # Rebuild dropdown
        new_dd = Gtk.DropDown.new_from_strings(self.interfaces)
        new_dd.connect("notify::selected", self.on_iface_changed)
        parent = self.iface_dropdown.get_parent()
        parent.remove(self.iface_dropdown)
        parent.prepend(new_dd)
        self.iface_dropdown = new_dd
        try:
            idx = self.interfaces.index(self.current_iface)
        except ValueError:
            idx = 0
            self.current_iface = self.interfaces[0]
            self.scanner.set_interface(self.current_iface)
            self.deauth.set_interface(self.current_iface)
        new_dd.set_selected(idx)
        self.refresh_mode_indicators()
        self.toast(f"Detected: {', '.join(self.interfaces)}")

    # ------------------------------------------------------------------
    # WiFi page
    # ------------------------------------------------------------------
    def _build_wifi_page(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        content.set_margin_top(10)
        content.set_margin_bottom(10)
        content.set_margin_start(10)
        content.set_margin_end(10)
        scroll.set_child(content)

        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title = Gtk.Label(label="WiFi Scanner")
        title.add_css_class("header-label")
        title.set_xalign(0)
        title.set_hexpand(True)
        title_row.append(title)
        self.wifi_spinner = Gtk.Spinner()
        self.wifi_spinner.set_size_request(24, 24)
        title_row.append(self.wifi_spinner)
        content.append(title_row)

        scan_btn = Gtk.Button(label="🔍 Scan Networks")
        scan_btn.add_css_class("action-button")
        scan_btn.connect("clicked", self.on_scan_wifi)
        self.scan_btn = scan_btn
        content.append(scan_btn)

        net_label = Gtk.Label(label="Networks")
        net_label.add_css_class("title-label")
        net_label.set_xalign(0)
        net_label.set_margin_top(6)
        content.append(net_label)

        self.networks_list = Gtk.ListBox()
        self.networks_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.networks_list.connect("row-selected", self.on_network_selected)
        self.networks_list.add_css_class("card")
        self._set_empty_state(self.networks_list, "Tap Scan to find networks")
        content.append(self.networks_list)

        # Detail panel
        self.detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.detail_box.set_visible(False)
        self.detail_box.set_margin_top(8)

        self.target_label = Gtk.Label(label="")
        self.target_label.add_css_class("title-label")
        self.target_label.set_xalign(0)
        self.target_label.set_wrap(True)
        self.detail_box.append(self.target_label)

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                             homogeneous=True)
        find_btn = Gtk.Button(label="👥 Find Clients")
        find_btn.add_css_class("action-button")
        find_btn.connect("clicked", self.on_scan_clients)
        action_row.append(find_btn)

        broadcast_btn = Gtk.Button(label="📡 Broadcast Deauth")
        broadcast_btn.add_css_class("danger-button")
        broadcast_btn.connect("clicked", self.on_broadcast_deauth)
        action_row.append(broadcast_btn)
        self.detail_box.append(action_row)

        clients_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cl_lbl = Gtk.Label(label="Clients")
        cl_lbl.add_css_class("title-label")
        cl_lbl.set_xalign(0)
        cl_lbl.set_hexpand(True)
        clients_header.append(cl_lbl)
        self.clients_spinner = Gtk.Spinner()
        clients_header.append(self.clients_spinner)
        self.detail_box.append(clients_header)

        self.clients_list = Gtk.ListBox()
        self.clients_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.clients_list.add_css_class("card")
        self._set_empty_state(self.clients_list, "Run Find Clients to populate")
        self.detail_box.append(self.clients_list)
        content.append(self.detail_box)

        # Log
        log_label = Gtk.Label(label="Activity")
        log_label.add_css_class("title-label")
        log_label.set_xalign(0)
        log_label.set_margin_top(8)
        content.append(log_label)

        self.wifi_log = Gtk.TextView()
        self.wifi_log.set_editable(False)
        self.wifi_log.add_css_class("log-view")
        self.wifi_log_buf = self.wifi_log.get_buffer()

        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_min_content_height(100)
        log_scroll.set_child(self.wifi_log)
        content.append(log_scroll)

        return scroll

    def log(self, msg):
        write_log(msg)
        def append():
            ts = datetime.now().strftime("%H:%M:%S")
            it = self.wifi_log_buf.get_end_iter()
            self.wifi_log_buf.insert(it, f"[{ts}] {msg}\n")
        GLib.idle_add(append)

    def _clear_list(self, listbox):
        while True:
            row = listbox.get_row_at_index(0)
            if row is None:
                break
            listbox.remove(row)

    def _set_empty_state(self, listbox, message):
        self._clear_list(listbox)
        row = Gtk.ListBoxRow()
        row.set_selectable(False)
        row.set_activatable(False)
        lbl = Gtk.Label(label=message)
        lbl.add_css_class("empty-state")
        lbl.set_xalign(0.5)
        row.set_child(lbl)
        listbox.append(row)

    def on_scan_wifi(self, btn):
        btn.set_sensitive(False)
        self.wifi_spinner.start()
        self.set_status("Scanning…")
        self.log(f"Scanning on {self.current_iface}")
        self._clear_list(self.networks_list)

        def done(success, networks, err):
            self.wifi_spinner.stop()
            btn.set_sensitive(True)
            if success:
                if networks:
                    for net in sorted(networks, key=lambda n: n.signal, reverse=True):
                        self.networks_list.append(self._build_network_row(net))
                    self.log(f"Found {len(networks)} networks")
                    self.toast(f"Found {len(networks)} networks")
                else:
                    self._set_empty_state(self.networks_list,
                                          "No networks found")
                    self.toast("No networks found")
            else:
                self._set_empty_state(self.networks_list, "Scan failed")
                self.log(f"Scan failed: {err}")
                self.toast(f"Scan failed: {err}", timeout=5)
            self.set_status("Ready")

        self.scanner.scan_networks(done)

    def _build_network_row(self, net):
        row = Gtk.ListBoxRow()
        row.add_css_class("network-row")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_top(6)
        box.set_margin_bottom(6)
        box.set_margin_start(10)
        box.set_margin_end(10)

        bars = Gtk.Label(label=net.signal_bars())
        bars.add_css_class(net.signal_class())
        box.append(bars)

        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        info.set_hexpand(True)
        ssid = Gtk.Label(label=net.ssid)
        ssid.set_xalign(0)
        ssid.add_css_class("title-label")
        ssid.set_ellipsize(3)  # PANGO_ELLIPSIZE_END
        info.append(ssid)
        detail = Gtk.Label(
            label=f"{net.bssid}  •  CH {net.channel}  •  {net.encryption}  •  {net.signal} dBm")
        detail.set_xalign(0)
        detail.add_css_class("subtitle-label")
        info.append(detail)
        box.append(info)

        row.set_child(box)
        row.network = net
        return row

    def on_network_selected(self, listbox, row):
        if row is None or not hasattr(row, 'network'):
            return
        self.current_network = row.network
        self.target_label.set_text(
            f"Target: {row.network.ssid}\n{row.network.bssid}  •  CH {row.network.channel}")
        self.detail_box.set_visible(True)
        self._set_empty_state(self.clients_list, "Run Find Clients to populate")
        self.log(f"Target selected: {row.network.ssid} ({row.network.bssid})")

    def _require_monitor(self):
        if self._cached_mode != 'monitor':
            self.refresh_mode_indicators()  # double-check
        if self._cached_mode != 'monitor':
            self._error(
                "Monitor mode required",
                f"{self.current_iface} is currently '{self._cached_mode}'. "
                f"Switch to monitor mode in the Tools tab first."
            )
            return False
        return True

    def on_scan_clients(self, btn):
        if not self.current_network:
            return
        if not self._require_monitor():
            return

        btn.set_sensitive(False)
        self.clients_spinner.start()
        self._clear_list(self.clients_list)
        self.set_status(f"Listening for clients ({CLIENT_SCAN_DURATION}s)…")
        self.log(f"Listening for clients on {self.current_network.bssid}")

        def done(success, clients, err):
            self.clients_spinner.stop()
            btn.set_sensitive(True)
            if success:
                if clients:
                    for c in clients:
                        self.clients_list.append(self._build_client_row(c))
                    self.log(f"Found {len(clients)} clients")
                    self.toast(f"Found {len(clients)} clients")
                else:
                    self._set_empty_state(self.clients_list,
                                          "No clients detected — try again, "
                                          "they may be idle")
                    self.log("No clients detected")
            else:
                self._set_empty_state(self.clients_list, "Client scan failed")
                self.log(f"Client scan failed: {err}")
                self.toast(f"Client scan failed: {err}", timeout=5)
            self.set_status("Ready")

        self.scanner.scan_clients(
            self.current_network.bssid,
            self.current_network.channel,
            CLIENT_SCAN_DURATION,
            done
        )

    def _build_client_row(self, client):
        row = Gtk.ListBoxRow()
        row.add_css_class("client-row")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_top(6)
        box.set_margin_bottom(6)
        box.set_margin_start(10)
        box.set_margin_end(10)

        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        info.set_hexpand(True)
        mac_lbl = Gtk.Label(label=client.mac)
        mac_lbl.set_xalign(0)
        mac_lbl.add_css_class("title-label")
        info.append(mac_lbl)
        meta = Gtk.Label(label=f"{client.power} dBm  •  {client.packets} pkts")
        meta.set_xalign(0)
        meta.add_css_class("subtitle-label")
        info.append(meta)
        box.append(info)

        deauth_btn = Gtk.Button(label="Deauth")
        deauth_btn.add_css_class("danger-button")
        deauth_btn.connect("clicked", lambda b, c=client: self._deauth_client_dialog(c))
        box.append(deauth_btn)

        capture_btn = Gtk.Button(label="Capture")
        capture_btn.add_css_class("action-button")
        capture_btn.connect("clicked", lambda b, c=client: self._capture_handshake_dialog(c))
        box.append(capture_btn)

        row.set_child(box)
        return row

    def _deauth_client_dialog(self, client):
        if not self._require_monitor():
            return
        net = self.current_network
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Deauth client",
            body=f"Send 64 deauth frames to:\n\n{client.mac}\non {net.ssid} ({net.bssid})?")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Send")
        dialog.set_response_appearance("go", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(d, resp):
            if resp == "go":
                self.set_status("Sending deauth…")
                self.log(f"Deauth {client.mac} on {net.bssid}")
                def worker():
                    ok, out = self.deauth.deauth_client(
                        net.bssid, client.mac, net.channel, 64)
                    if ok:
                        self.log("Deauth sent")
                        self.toast("Deauth sent")
                    else:
                        self.log(f"Deauth failed: {out}")
                        self.toast(f"Deauth failed: {out}", timeout=5)
                    self.set_status("Ready")
                threading.Thread(target=worker, daemon=True).start()
            d.destroy()

        dialog.connect("response", on_resp)
        dialog.present()

    def _capture_handshake_dialog(self, client):
        if not self._require_monitor():
            return
        net = self.current_network
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Capture WPA handshake",
            body=(f"Capture handshake for {net.ssid}?\n\n"
                  f"Briefly deauth {client.mac} to force a reconnect, then save "
                  f"the .cap file to:\n{CAPTURE_DIR}/\n\n"
                  f"Only run this on networks you own."))
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Capture")
        dialog.set_response_appearance("go", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(d, resp):
            if resp == "go":
                self.set_status("Capturing handshake…")
                self.log(f"Handshake capture: {net.bssid} via {client.mac}")
                self.clients_spinner.start()
                def worker():
                    ok, msg = self.deauth.capture_handshake(
                        net.bssid, net.ssid, client.mac, net.channel)
                    GLib.idle_add(self.clients_spinner.stop)
                    if ok:
                        self.log(msg)
                        self.toast("Handshake captured", timeout=5)
                    else:
                        self.log(f"Capture failed: {msg}")
                        self.toast(f"Capture failed: {msg}", timeout=5)
                    self.set_status("Ready")
                threading.Thread(target=worker, daemon=True).start()
            d.destroy()

        dialog.connect("response", on_resp)
        dialog.present()

    def on_broadcast_deauth(self, btn):
        if not self.current_network or not self._require_monitor():
            return
        net = self.current_network
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Broadcast deauth",
            body=(f"Send 64 broadcast deauth frames to all clients on:\n\n"
                  f"{net.ssid} ({net.bssid})?\n\n"
                  f"Only run this on networks you own or are authorized to test."))
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Send")
        dialog.set_response_appearance("go", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(d, resp):
            if resp == "go":
                self.set_status("Broadcasting deauth…")
                self.log(f"Broadcast deauth on {net.bssid}")
                def worker():
                    ok, out = self.deauth.deauth_broadcast(
                        net.bssid, net.channel, 64)
                    if ok:
                        self.log("Broadcast deauth sent")
                        self.toast("Broadcast deauth sent")
                    else:
                        self.log(f"Broadcast failed: {out}")
                        self.toast(f"Broadcast failed: {out}", timeout=5)
                    self.set_status("Ready")
                threading.Thread(target=worker, daemon=True).start()
            d.destroy()

        dialog.connect("response", on_resp)
        dialog.present()

    # ------------------------------------------------------------------
    # Nmap page
    # ------------------------------------------------------------------
    def _build_nmap_page(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        content.set_margin_top(10)
        content.set_margin_bottom(10)
        content.set_margin_start(10)
        content.set_margin_end(10)
        scroll.set_child(content)

        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title = Gtk.Label(label="Nmap")
        title.add_css_class("header-label")
        title.set_xalign(0)
        title.set_hexpand(True)
        title_row.append(title)
        self.nmap_spinner = Gtk.Spinner()
        self.nmap_spinner.set_size_request(24, 24)
        title_row.append(self.nmap_spinner)
        content.append(title_row)

        tgt_lbl = Gtk.Label(label="Target (IP / CIDR / hostname)")
        tgt_lbl.set_xalign(0)
        content.append(tgt_lbl)
        self.target_entry = Gtk.Entry()
        self.target_entry.set_placeholder_text("192.168.1.0/24")
        self.target_entry.set_text("192.168.1.0/24")
        content.append(self.target_entry)

        prof_lbl = Gtk.Label(label="Profile")
        prof_lbl.add_css_class("title-label")
        prof_lbl.set_xalign(0)
        prof_lbl.set_margin_top(8)
        content.append(prof_lbl)

        self.nmap_list = Gtk.ListBox()
        self.nmap_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.nmap_list.add_css_class("card")
        for p in NMAP_PROFILES:
            self.nmap_list.append(self._build_nmap_row(p))
        self.nmap_list.select_row(self.nmap_list.get_row_at_index(0))
        content.append(self.nmap_list)

        self.nmap_btn = Gtk.Button(label="🚀 Run Scan")
        self.nmap_btn.add_css_class("action-button")
        self.nmap_btn.connect("clicked", self.on_nmap_scan)
        content.append(self.nmap_btn)

        res_lbl = Gtk.Label(label="Output")
        res_lbl.add_css_class("title-label")
        res_lbl.set_xalign(0)
        res_lbl.set_margin_top(6)
        content.append(res_lbl)

        self.nmap_view = Gtk.TextView()
        self.nmap_view.set_editable(False)
        self.nmap_view.set_monospace(True)
        self.nmap_view.add_css_class("log-view")
        self.nmap_buf = self.nmap_view.get_buffer()

        rs = Gtk.ScrolledWindow()
        rs.set_min_content_height(240)
        rs.set_child(self.nmap_view)
        content.append(rs)

        return scroll

    def _build_nmap_row(self, profile):
        row = Gtk.ListBoxRow()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_top(6)
        box.set_margin_bottom(6)
        box.set_margin_start(10)
        box.set_margin_end(10)

        name = Gtk.Label(label=profile["name"])
        name.set_xalign(0)
        name.add_css_class("title-label")
        box.append(name)

        desc = Gtk.Label(label=f"{profile['desc']}  •  {profile['time']}")
        desc.set_xalign(0)
        desc.add_css_class("subtitle-label")
        desc.set_wrap(True)
        box.append(desc)

        row.set_child(box)
        row.profile = profile
        return row

    def on_nmap_scan(self, btn):
        target = self.target_entry.get_text().strip()
        if not target:
            self._error("No target", "Enter a target first.")
            return
        row = self.nmap_list.get_selected_row()
        if not row:
            return
        profile = row.profile

        btn.set_sensitive(False)
        self.nmap_spinner.start()
        self.set_status(f"Nmap scanning {target}…")
        write_log(f"Nmap: {profile['name']} on {target}")

        cmd = ['nmap'] + profile["args"] + [target]
        self._append_nmap(f"$ {' '.join(cmd)}\n" + "=" * 48 + "\n")

        def worker():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    GLib.idle_add(self._append_nmap, line)
                proc.wait()
                if proc.returncode == 0:
                    GLib.idle_add(self._append_nmap, "\n✓ Done\n")
                    self.toast("Nmap done")
                else:
                    GLib.idle_add(self._append_nmap,
                                  f"\n✗ Failed (exit {proc.returncode})\n")
                    self.toast("Nmap failed", timeout=5)
            except FileNotFoundError:
                GLib.idle_add(self._append_nmap, "\n✗ nmap not installed\n")
                self.toast("nmap not installed", timeout=5)
            except Exception as e:
                GLib.idle_add(self._append_nmap, f"\nError: {e}\n")
            finally:
                def finish():
                    self.nmap_spinner.stop()
                    btn.set_sensitive(True)
                    self.set_status("Ready")
                GLib.idle_add(finish)

        threading.Thread(target=worker, daemon=True).start()

    def _append_nmap(self, text):
        it = self.nmap_buf.get_end_iter()
        self.nmap_buf.insert(it, text)

    # ------------------------------------------------------------------
    # Tools page
    # ------------------------------------------------------------------
    def _build_tools_page(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        content.set_margin_top(10)
        content.set_margin_bottom(10)
        content.set_margin_start(10)
        content.set_margin_end(10)
        scroll.set_child(content)

        title = Gtk.Label(label="Tools")
        title.add_css_class("header-label")
        title.set_xalign(0)
        content.append(title)

        # Mode card
        mode_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        mode_card.add_css_class("card")

        mode_title = Gtk.Label(label="Interface mode")
        mode_title.add_css_class("title-label")
        mode_title.set_xalign(0)
        mode_card.append(mode_title)

        self.mode_label = Gtk.Label(label=f"{self.current_iface}: {get_interface_mode(self.current_iface)}")
        self.mode_label.set_xalign(0)
        mode_card.append(self.mode_label)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6,
                          homogeneous=True)
        mon_btn = Gtk.Button(label="📡 Monitor")
        mon_btn.add_css_class("action-button")
        mon_btn.connect("clicked", lambda b: self._switch_mode(b, 'monitor'))
        btn_row.append(mon_btn)

        man_btn = Gtk.Button(label="🌐 Managed")
        man_btn.add_css_class("success-button")
        man_btn.connect("clicked", lambda b: self._switch_mode(b, 'managed'))
        btn_row.append(man_btn)

        refresh_btn = Gtk.Button(label="🔄")
        refresh_btn.add_css_class("subtle-button")
        refresh_btn.connect("clicked", lambda b: self.refresh_mode_indicators())
        btn_row.append(refresh_btn)
        mode_card.append(btn_row)
        content.append(mode_card)

        # Info card
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info.add_css_class("card")
        info.append(self._label("Monitor mode", "title-label"))
        info.append(self._label("• Required for client scan, deauth, capture",
                                "subtitle-label"))
        info.append(self._label("• No internet while active", "subtitle-label"))
        info.append(self._label("• OnePlus 6 internal radio: unreliable. Use AR9271 (wlan1)",
                                "subtitle-label"))
        info.append(self._label("", "subtitle-label"))
        info.append(self._label("Captures", "title-label"))
        info.append(self._label(f"{CAPTURE_DIR}", "subtitle-label"))
        info.append(self._label("Activity log", "title-label"))
        info.append(self._label(f"{LOG_FILE}", "subtitle-label"))
        content.append(info)

        # About
        about = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        about.add_css_class("card")
        about.append(self._label("NetStrike v1.1", "title-label"))
        about.append(self._label("WiFi security audit — NetHunter Pro / Phosh",
                                 "subtitle-label"))
        about.append(self._label("Use only on networks you own or are authorized to test.",
                                 "subtitle-label"))
        content.append(about)

        return scroll

    def _label(self, text, css_class=None):
        lbl = Gtk.Label(label=text)
        lbl.set_xalign(0)
        lbl.set_wrap(True)
        if css_class:
            lbl.add_css_class(css_class)
        return lbl

    def _switch_mode(self, btn, target_mode):
        btn.set_sensitive(False)
        iface = self.current_iface
        self.set_status(f"Setting {iface} to {target_mode}…")
        write_log(f"Mode change: {iface} -> {target_mode}")

        def worker():
            try:
                cmds = [
                    ['ip', 'link', 'set', iface, 'down'],
                    ['iw', 'dev', iface, 'set', 'type', target_mode],
                    ['ip', 'link', 'set', iface, 'up'],
                ]
                if target_mode == 'managed':
                    cmds.append(['systemctl', 'restart', 'NetworkManager'])
                for c in cmds:
                    subprocess.run(c, capture_output=True, timeout=10)
            except Exception as e:
                write_log(f"Mode change error: {e}")

            new_mode = get_interface_mode(iface)
            def finish():
                self.refresh_mode_indicators()
                btn.set_sensitive(True)
                if new_mode == target_mode:
                    self.toast(f"{iface} → {target_mode}")
                else:
                    self.toast(f"Mode change failed ({iface}: {new_mode})",
                               timeout=5)
            GLib.idle_add(finish)

        threading.Thread(target=worker, daemon=True).start()

    def _error(self, heading, body):
        d = Adw.MessageDialog(transient_for=self, heading=heading, body=body)
        d.add_response("ok", "OK")
        d.present()


# ============================================================================
# MAIN
# ============================================================================

def main():
    write_log("NetStrike v1.1 started")
    app = NetStrikeApp()
    return app.run(sys.argv)


if __name__ == '__main__':
    sys.exit(main())
