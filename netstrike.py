#!/usr/bin/env python3
"""
NetStrike - WiFi Security Audit Tool
For NetHunter Pro / Phosh / Mobile Linux

Use only on networks you own or have explicit authorization to test.
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
from pathlib import Path
from datetime import datetime

# ============================================================================
# CONSTANTS
# ============================================================================

APP_ID = 'org.thepriest.netstrike'
APP_NAME = 'NetStrike'
CONFIG_DIR = Path.home() / '.config' / 'netstrike'
LOG_FILE = CONFIG_DIR / 'activity.log'
SCAN_PREFIX = '/tmp/netstrike_scan'

CSS_STYLES = b"""
window { background-color: #1e1e2e; }
.card {
    background-color: #313244;
    border-radius: 12px;
    padding: 16px;
}
.network-row, .client-row {
    background-color: #313244;
    border-radius: 10px;
    padding: 6px;
    margin: 4px 0;
}
.action-button {
    background-color: #89b4fa;
    color: #1e1e2e;
    font-weight: bold;
    min-height: 48px;
    border-radius: 10px;
    padding: 8px 16px;
}
.action-button:hover { background-color: #74c7ec; }
.danger-button {
    background-color: #f38ba8;
    color: #1e1e2e;
    font-weight: bold;
    min-height: 48px;
    border-radius: 10px;
    padding: 8px 16px;
}
.danger-button:hover { background-color: #eba0ac; }
.success-button {
    background-color: #a6e3a1;
    color: #1e1e2e;
    font-weight: bold;
    min-height: 48px;
    border-radius: 10px;
    padding: 8px 16px;
}
.success-button:hover { background-color: #94e2d5; }
.title-label {
    font-size: 16px;
    font-weight: bold;
    color: #cdd6f4;
}
.header-label {
    font-size: 22px;
    font-weight: 900;
    color: #cdd6f4;
    margin: 8px 0 12px 0;
}
.subtitle-label {
    font-size: 12px;
    color: #a6adc8;
}
.signal-strong { color: #a6e3a1; }
.signal-medium { color: #f9e2af; }
.signal-weak { color: #f38ba8; }
.status-bar {
    background-color: #181825;
    padding: 8px 12px;
    font-size: 12px;
    color: #a6adc8;
}
.log-view {
    font-family: monospace;
    font-size: 11px;
    color: #cdd6f4;
    background-color: #11111b;
    padding: 8px;
    border-radius: 8px;
}
.mode-monitor { color: #f9e2af; font-weight: bold; }
.mode-managed { color: #a6e3a1; font-weight: bold; }
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
    """Get current mode of interface (managed/monitor/etc)."""
    try:
        result = subprocess.run(['iw', 'dev', iface, 'info'],
                                capture_output=True, text=True, timeout=5)
        m = re.search(r'type\s+(\w+)', result.stdout)
        return m.group(1).lower() if m else 'unknown'
    except Exception:
        return 'unknown'

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
        """Trigger a scan and parse results."""
        def worker():
            try:
                # Trigger scan (non-blocking)
                subprocess.run(['iw', 'dev', self.interface, 'scan', 'trigger'],
                               capture_output=True, timeout=10)
                # Give it time to gather
                import time
                time.sleep(3)
                # Dump cached results
                result = subprocess.run(['iw', 'dev', self.interface, 'scan', 'dump'],
                                        capture_output=True, text=True, timeout=15)
                if result.returncode != 0:
                    # Fallback to full scan
                    result = subprocess.run(['iw', 'dev', self.interface, 'scan'],
                                            capture_output=True, text=True, timeout=30)
                networks = self._parse_iw_scan(result.stdout) if result.returncode == 0 else []
                GLib.idle_add(callback, True, networks, "")
            except subprocess.TimeoutExpired:
                GLib.idle_add(callback, False, [], "Scan timed out")
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
                # BSS aa:bb:cc:dd:ee:ff(on wlan0)
                bssid_match = re.match(r'BSS\s+([0-9a-fA-F:]+)', line)
                current_bss = bssid_match.group(1) if bssid_match else None
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
            elif 'DS Parameter set: channel' in stripped:
                m = re.search(r'channel\s+(\d+)', stripped)
                if m and 'channel' not in current:
                    current['channel'] = m.group(1)
            elif stripped.startswith('RSN:'):
                current['encryption'] = 'WPA2'
            elif stripped.startswith('WPA:') and 'encryption' not in current:
                current['encryption'] = 'WPA'
            elif 'Privacy' in stripped and 'capability' in stripped.lower():
                if 'encryption' not in current:
                    current['encryption'] = 'WEP?'

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
        """Run airodump-ng for `duration` seconds, parse CSV output."""
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
                # airodump writes to terminal — pipe everything away
                subprocess.run(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               timeout=duration + 5)

                clients = self._parse_airodump_csv(target_bssid)
                GLib.idle_add(callback, True, clients, "")
            except Exception as e:
                GLib.idle_add(callback, False, [], str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _parse_airodump_csv(self, target_bssid):
        """Parse airodump CSV — the station section is what we want."""
        csv_files = sorted(glob.glob(f"{SCAN_PREFIX}-*.csv"))
        if not csv_files:
            return []

        try:
            with open(csv_files[-1], 'r', errors='replace') as f:
                content = f.read()
        except Exception:
            return []

        # CSV has two sections: APs then Stations.
        # Split on the Station MAC header.
        if 'Station MAC' not in content:
            return []
        _, station_section = content.split('Station MAC', 1)

        clients = []
        for line in station_section.split('\n')[1:]:  # skip header line
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
            # Only clients on the target
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
        self.process = None

    def set_interface(self, iface):
        self.interface = iface

    def deauth_client(self, ap_bssid, client_mac, channel, count=64):
        """Send `count` deauth frames to a specific client. count=0 is not allowed here."""
        if count <= 0 or count > 10000:
            return False, "Packet count must be between 1 and 10000"
        try:
            subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                           capture_output=True, timeout=5)

            cmd = ['aireplay-ng', '--deauth', str(count), '-a', ap_bssid,
                   '-c', client_mac, self.interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)

    def deauth_broadcast(self, ap_bssid, channel, count=64):
        """Broadcast deauth to all clients on AP."""
        if count <= 0 or count > 10000:
            return False, "Packet count must be between 1 and 10000"
        try:
            subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                           capture_output=True, timeout=5)
            cmd = ['aireplay-ng', '--deauth', str(count), '-a', ap_bssid, self.interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)

    def capture_handshake(self, ap_bssid, client_mac, channel, capture_path):
        """Start airodump capturing on a target, then deauth a client briefly
        to force a reconnect and capture the WPA handshake."""
        try:
            subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                           capture_output=True, timeout=5)

            cmd_capture = [
                'airodump-ng', '--bssid', ap_bssid, '-c', str(channel),
                '-w', capture_path, '--output-format', 'pcap',
                self.interface
            ]
            cap_proc = subprocess.Popen(cmd_capture, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
            import time
            time.sleep(2)

            cmd_deauth = ['aireplay-ng', '--deauth', '4', '-a', ap_bssid,
                          '-c', client_mac, self.interface]
            subprocess.run(cmd_deauth, capture_output=True, timeout=30)

            time.sleep(10)
            cap_proc.terminate()
            try:
                cap_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cap_proc.kill()

            return True, f"Capture written near {capture_path}*.cap"
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
                         flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        # Load CSS on activate (proper place in GTK4)
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

        # Detect interfaces
        self.interfaces = list_wireless_interfaces()
        self.current_iface = self.interfaces[0]
        self.scanner.set_interface(self.current_iface)
        self.deauth.set_interface(self.current_iface)

        # Layout
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(box)

        # Header bar with interface selector
        header = Adw.HeaderBar()
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        title_box.append(Gtk.Label(label=APP_NAME))
        header.set_title_widget(title_box)

        self.iface_dropdown = Gtk.DropDown.new_from_strings(self.interfaces)
        self.iface_dropdown.set_selected(0)
        self.iface_dropdown.connect("notify::selected", self.on_iface_changed)
        header.pack_end(self.iface_dropdown)
        box.append(header)

        # Pages
        self.stack = Adw.ViewStack()
        self.stack.add_titled_with_icon(self._build_wifi_page(), "wifi",
                                        "WiFi", "network-wireless-symbolic")
        self.stack.add_titled_with_icon(self._build_nmap_page(), "nmap",
                                        "Nmap", "network-workgroup-symbolic")
        self.stack.add_titled_with_icon(self._build_tools_page(), "tools",
                                        "Tools", "applications-system-symbolic")
        box.append(self.stack)

        switcher = Adw.ViewSwitcherBar()
        switcher.set_stack(self.stack)
        switcher.set_reveal(True)
        box.append(switcher)

        # Status bar
        self.status = Gtk.Label(label=self._status_text("Ready"))
        self.status.add_css_class("status-bar")
        self.status.set_xalign(0)
        box.append(self.status)

        # Root check
        if not check_root():
            GLib.idle_add(self._show_root_warning)

    def _status_text(self, msg):
        mode = get_interface_mode(self.current_iface)
        return f"{msg}  •  {self.current_iface} [{mode}]"

    def set_status(self, msg):
        GLib.idle_add(self.status.set_text, self._status_text(msg))

    def _show_root_warning(self):
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Root required",
            body="NetStrike needs root to control the wireless interface, "
                 "scan, and inject frames.\n\n"
                 "Relaunch with: sudo netstrike  (or via pkexec)"
        )
        dialog.add_response("ok", "Continue anyway")
        dialog.present()

    def on_iface_changed(self, dropdown, _param):
        idx = dropdown.get_selected()
        if 0 <= idx < len(self.interfaces):
            self.current_iface = self.interfaces[idx]
            self.scanner.set_interface(self.current_iface)
            self.deauth.set_interface(self.current_iface)
            self.set_status("Interface changed")
            write_log(f"Interface set to {self.current_iface}")

    # ------------------------------------------------------------------
    # WiFi page
    # ------------------------------------------------------------------
    def _build_wifi_page(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        scroll.set_child(content)

        title = Gtk.Label(label="WiFi Scanner")
        title.add_css_class("header-label")
        title.set_xalign(0)
        content.append(title)

        scan_btn = Gtk.Button(label="🔍 Scan Networks")
        scan_btn.add_css_class("action-button")
        scan_btn.connect("clicked", self.on_scan_wifi)
        content.append(scan_btn)

        self.wifi_progress = Gtk.ProgressBar()
        self.wifi_progress.set_visible(False)
        content.append(self.wifi_progress)

        net_label = Gtk.Label(label="Networks")
        net_label.add_css_class("title-label")
        net_label.set_xalign(0)
        net_label.set_margin_top(8)
        content.append(net_label)

        self.networks_list = Gtk.ListBox()
        self.networks_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.networks_list.connect("row-selected", self.on_network_selected)
        self.networks_list.add_css_class("card")
        content.append(self.networks_list)

        # Target detail (hidden until network picked)
        self.detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.detail_box.set_visible(False)
        self.detail_box.set_margin_top(12)

        self.target_label = Gtk.Label(label="")
        self.target_label.add_css_class("title-label")
        self.target_label.set_xalign(0)
        self.detail_box.append(self.target_label)

        find_clients_btn = Gtk.Button(label="👥 Find Connected Clients (10s)")
        find_clients_btn.add_css_class("action-button")
        find_clients_btn.connect("clicked", self.on_scan_clients)
        self.detail_box.append(find_clients_btn)

        broadcast_btn = Gtk.Button(label="📡 Broadcast Deauth (64 frames)")
        broadcast_btn.add_css_class("danger-button")
        broadcast_btn.connect("clicked", self.on_broadcast_deauth)
        self.detail_box.append(broadcast_btn)

        clients_label = Gtk.Label(label="Clients")
        clients_label.add_css_class("title-label")
        clients_label.set_xalign(0)
        clients_label.set_margin_top(8)
        self.detail_box.append(clients_label)

        self.clients_list = Gtk.ListBox()
        self.clients_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.clients_list.add_css_class("card")
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
        log_scroll.set_min_content_height(120)
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

    def on_scan_wifi(self, btn):
        btn.set_sensitive(False)
        self.wifi_progress.set_visible(True)
        self.wifi_progress.pulse()
        self.set_status("Scanning…")
        self.log(f"Scanning on {self.current_iface}")

        # Pulse progress while scanning
        pulse_id = GLib.timeout_add(150, lambda: (self.wifi_progress.pulse(), True)[1])

        def done(success, networks, err):
            GLib.source_remove(pulse_id)
            self.wifi_progress.set_visible(False)
            btn.set_sensitive(True)
            self._clear_list(self.networks_list)
            if success:
                self.log(f"Found {len(networks)} networks")
                for net in sorted(networks, key=lambda n: n.signal, reverse=True):
                    self.networks_list.append(self._build_network_row(net))
            else:
                self.log(f"Scan failed: {err}")
            self.set_status("Ready")

        self.scanner.scan_networks(done)

    def _build_network_row(self, net):
        row = Gtk.ListBoxRow()
        row.add_css_class("network-row")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
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
        if row is None:
            return
        self.current_network = row.network
        self.target_label.set_text(
            f"Target: {row.network.ssid}\n{row.network.bssid}  •  CH {row.network.channel}")
        self.detail_box.set_visible(True)
        self._clear_list(self.clients_list)
        self.log(f"Target selected: {row.network.ssid} ({row.network.bssid})")

    def on_scan_clients(self, btn):
        if not self.current_network:
            return
        mode = get_interface_mode(self.current_iface)
        if mode != 'monitor':
            self._error("Monitor mode required",
                        "Switch the interface to monitor mode in the Tools tab "
                        "before scanning for clients.")
            return

        btn.set_sensitive(False)
        self.set_status("Listening for clients (10s)…")
        self.log(f"Listening for clients on {self.current_network.bssid}")

        def done(success, clients, err):
            btn.set_sensitive(True)
            self._clear_list(self.clients_list)
            if success:
                self.log(f"Found {len(clients)} clients")
                for c in clients:
                    self.clients_list.append(self._build_client_row(c))
                if not clients:
                    self.log("No clients detected — try a longer scan or wait for activity")
            else:
                self.log(f"Client scan failed: {err}")
            self.set_status("Ready")

        self.scanner.scan_clients(
            self.current_network.bssid,
            self.current_network.channel,
            10,
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
                    self.log("Deauth sent" if ok else f"Deauth failed: {out[:120]}")
                    self.set_status("Ready")
                threading.Thread(target=worker, daemon=True).start()
            d.destroy()

        dialog.connect("response", on_resp)
        dialog.present()

    def _capture_handshake_dialog(self, client):
        net = self.current_network
        path = f"/tmp/netstrike_hs_{net.bssid.replace(':', '')}"
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Capture WPA handshake",
            body=(f"Capture WPA handshake for {net.ssid}?\n\n"
                  f"This will briefly deauth {client.mac} to force a reconnect, "
                  f"then save the .cap file to:\n{path}-01.cap\n\n"
                  f"Use this only on networks you own."))
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Capture")
        dialog.set_response_appearance("go", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(d, resp):
            if resp == "go":
                self.set_status("Capturing handshake…")
                self.log(f"Handshake capture: {net.bssid} via {client.mac}")
                def worker():
                    ok, out = self.deauth.capture_handshake(
                        net.bssid, client.mac, net.channel, path)
                    self.log(out if ok else f"Capture failed: {out[:120]}")
                    self.set_status("Ready")
                threading.Thread(target=worker, daemon=True).start()
            d.destroy()

        dialog.connect("response", on_resp)
        dialog.present()

    def on_broadcast_deauth(self, btn):
        if not self.current_network:
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
                    ok, out = self.deauth.deauth_broadcast(net.bssid, net.channel, 64)
                    self.log("Broadcast deauth sent" if ok
                             else f"Broadcast failed: {out[:120]}")
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

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        scroll.set_child(content)

        title = Gtk.Label(label="Nmap")
        title.add_css_class("header-label")
        title.set_xalign(0)
        content.append(title)

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
        prof_lbl.set_margin_top(12)
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

        self.nmap_progress = Gtk.ProgressBar()
        self.nmap_progress.set_visible(False)
        content.append(self.nmap_progress)

        res_lbl = Gtk.Label(label="Output")
        res_lbl.add_css_class("title-label")
        res_lbl.set_xalign(0)
        res_lbl.set_margin_top(8)
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
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
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
        self.nmap_progress.set_visible(True)
        pulse_id = GLib.timeout_add(150, lambda: (self.nmap_progress.pulse(), True)[1])
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
                GLib.idle_add(self._append_nmap, "\n✓ Done\n"
                              if proc.returncode == 0 else "\n✗ Failed\n")
            except Exception as e:
                GLib.idle_add(self._append_nmap, f"\nError: {e}\n")
            finally:
                def finish():
                    GLib.source_remove(pulse_id)
                    self.nmap_progress.set_visible(False)
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

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
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

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                          homogeneous=True)
        mon_btn = Gtk.Button(label="📡 Monitor")
        mon_btn.add_css_class("action-button")
        mon_btn.connect("clicked", self.on_set_monitor)
        btn_row.append(mon_btn)

        man_btn = Gtk.Button(label="🌐 Managed")
        man_btn.add_css_class("success-button")
        man_btn.connect("clicked", self.on_set_managed)
        btn_row.append(man_btn)

        refresh_btn = Gtk.Button(label="🔄 Refresh")
        refresh_btn.connect("clicked", self.on_refresh_mode)
        btn_row.append(refresh_btn)
        mode_card.append(btn_row)
        content.append(mode_card)

        # Info
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info.add_css_class("card")
        info.append(self._label("Monitor mode", "title-label"))
        info.append(self._label("• Required for client scanning, deauth, capture", "subtitle-label"))
        info.append(self._label("• No internet while active", "subtitle-label"))
        info.append(self._label("• OnePlus 6 internal radio may not support it — use AR9271", "subtitle-label"))
        info.append(self._label("", "subtitle-label"))
        info.append(self._label("Activity log", "title-label"))
        info.append(self._label(f"{LOG_FILE}", "subtitle-label"))
        content.append(info)

        # About
        about = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        about.add_css_class("card")
        about.append(self._label("NetStrike", "title-label"))
        about.append(self._label("WiFi security audit tool — NetHunter Pro / Phosh",
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

    def on_set_monitor(self, btn):
        self._switch_mode(btn, 'monitor')

    def on_set_managed(self, btn):
        self._switch_mode(btn, 'managed')

    def _switch_mode(self, btn, target_mode):
        btn.set_sensitive(False)
        iface = self.current_iface
        self.set_status(f"Setting {iface} to {target_mode}…")
        write_log(f"Mode change requested: {iface} -> {target_mode}")

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
            GLib.idle_add(self.on_refresh_mode, None)
            GLib.idle_add(btn.set_sensitive, True)
            self.set_status("Ready")

        threading.Thread(target=worker, daemon=True).start()

    def on_refresh_mode(self, btn):
        mode = get_interface_mode(self.current_iface)
        self.mode_label.set_text(f"{self.current_iface}: {mode}")
        css = "mode-monitor" if mode == "monitor" else "mode-managed"
        for c in ("mode-monitor", "mode-managed"):
            self.mode_label.remove_css_class(c)
        self.mode_label.add_css_class(css)
        self.set_status("Ready")

    def _error(self, heading, body):
        d = Adw.MessageDialog(transient_for=self, heading=heading, body=body)
        d.add_response("ok", "OK")
        d.present()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    write_log("NetStrike started")
    app = NetStrikeApp()
    sys.exit(app.run(sys.argv))
