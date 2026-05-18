# NetStrike

WiFi security audit tool for NetHunter Pro / Phosh / mobile Linux.
GTK4 + libadwaita, touch-friendly UI, single-file Python.

> **Scope.** Use only on networks you own or have explicit written
> authorization to test. Unauthorized deauthentication, capture, or
> scanning of third-party networks is illegal in most jurisdictions —
> in Ireland it falls under the Criminal Justice (Offences Relating to
> Information Systems) Act 2017. You are responsible for how you use this.

## Features

- WiFi scan (passive) — sorted by signal, shows BSSID / channel / encryption
- Per-network client discovery via `airodump-ng` (parses CSV, not stdout)
- Targeted deauth (specific client MAC) — 64 frames default
- Broadcast deauth (all clients on selected AP) — 64 frames default
- WPA handshake capture (short deauth → reconnect → `.cap`)
- Nmap front-end with 5 profiles (quick / standard / full / stealth / vuln)
- Monitor ⇄ Managed mode toggle on any detected interface
- Interface selector (auto-detects wireless devices via `iw dev`)
- Activity log: `~/.config/netstrike/activity.log`

## Requirements

- Linux (tested target: Kali NetHunter Pro on OnePlus 6, Phosh)
- Root (uses `pkexec` from the desktop entry, or run with `sudo`)
- A wireless adapter that supports monitor mode + injection (e.g. AR9271)
- Packages:
  ```
  apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 \
              aircrack-ng nmap iw policykit-1
  ```

> The OnePlus 6 internal radio (wcn3990) does **not** reliably support
> monitor mode on NetHunter Pro. Use an external adapter (AR9271 etc.) —
> it'll show up as `wlan1` in the interface dropdown.

## Install

**One-liner (recommended):**

```
curl -fsSL https://raw.githubusercontent.com/the-priest/netstrike/main/get.sh | sudo bash
```

Pulls the repo, installs all apt deps (gtk4, libadwaita, aircrack-ng, nmap, iw,
policykit), drops the binary into `/usr/local/bin`, registers the icon and
desktop entry.

**Manual (from a local clone):**

```
chmod +x install.sh
sudo ./install.sh
```

Launch *NetStrike* from the app drawer, or:

```
pkexec /usr/local/bin/netstrike
```

## Workflow

1. **Tools tab** → pick interface (e.g. `wlan1`) → set Monitor mode
2. **WiFi tab** → Scan Networks → tap the target you own
3. → Find Connected Clients (10s passive listen via airodump)
4. → Tap *Deauth* on a specific client, or *Capture* for a WPA handshake
5. **Tools tab** → set Managed mode when done (restores networking)

For nmap, use the **Nmap tab** — pick a profile, set target, run.

## Uninstall

```
sudo rm /usr/local/bin/netstrike
sudo rm /usr/share/applications/netstrike.desktop
sudo rm /usr/share/icons/hicolor/scalable/apps/netstrike.svg
sudo update-desktop-database /usr/share/applications
```

## License

MIT — see LICENSE.
