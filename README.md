# Local Network IP Scanner

A cross-platform (Windows / Linux / macOS) command-line network scanner written
in Python. Give it a subnet in CIDR notation (e.g. `192.168.1.0/24`) and it
discovers every live host on the network and reports — similar to
**Advanced IP Scanner** — the:

- **IP address** and whether the host is **up**
- **MAC address**
- **Hostname** (when it can be resolved)
- **Vendor** (looked up from the MAC address / OUI database)
- **Device type** — a best-effort guess such as *Phone*, *Raspberry Pi*,
  *PC / Server*, *Router / Network gear*, *Printer*, *Smart TV / Media*,
  *IP Camera*, *NAS / Storage* or *IoT / Smart device*

## How it works

The scanner combines two techniques for the most complete results:

1. **ARP scan** (via [`scapy`](https://scapy.net/)) — the most reliable way to
   obtain MAC addresses on the local link. Requires administrator / root
   privileges.
2. **ICMP ping sweep** — a fast, concurrent ping of every address in the
   subnet, combined with a read of the operating-system ARP cache. This works
   without any extra privileges and is used as an automatic fallback.

Device type is inferred from the hardware **vendor** (resolved from the MAC
address using an offline OUI database) and the **hostname**.

## ⚠️ Important — for full functionality

For the scanner to work at its best (reliable MAC-address and device-type
detection via the ARP scan) you should:

- **Run the script with root / administrator privileges.** The ARP scan sends
  raw packets, which requires elevation:
  - **Windows:** open PowerShell / Command Prompt **as Administrator**.
  - **Linux / macOS:** run with `sudo`.
- **Install [Npcap](https://npcap.com/#download) (Windows only, strongly
  recommended).** Scapy's ARP scan needs a packet-capture driver. Without
  Npcap you'll see a warning and the tool falls back to the slower ping sweep.
  During installation, tick **"Install Npcap in WinPcap API-compatible Mode"**.

If you don't run elevated (or Npcap isn't installed on Windows), the scanner
still works — it automatically falls back to the ICMP ping sweep and reads MAC
addresses from the operating-system ARP cache — but MAC coverage will be
reduced and the scan will be slower.

## Requirements

- Python 3.7+
- The Python packages listed in [`requirements.txt`](requirements.txt)
- **Root / administrator privileges** (recommended — see the note above)
- **[Npcap](https://npcap.com/#download)** on Windows (recommended — see above)

Install the dependencies:

```bash
pip install -r requirements.txt
```

> Both dependencies are optional. If they are not installed the tool still runs
> using the ping sweep and the system ARP cache, but vendor/device detection
> and MAC coverage will be reduced. Installing them is recommended.

## Usage

```bash
python ip_scanner.py <subnet>
```

### Examples

```bash
# Basic scan of a /24 network
python ip_scanner.py 192.168.1.0/24

# Increase the per-host timeout and use more concurrent workers
python ip_scanner.py 192.168.1.0/24 --timeout 1.5 --workers 200

# Skip the ARP scan (no admin rights) and use the ping sweep only
python ip_scanner.py 10.0.0.0/24 --no-arp

# Save the results to a JSON file as well as printing them
python ip_scanner.py 192.168.1.0/24 --json results.json
```

### Running with privileges (for the ARP scan)

The ARP scan needs raw-socket access:

- **Windows:** run your terminal (PowerShell / Command Prompt) **as
  Administrator**. Scapy on Windows also needs
  [Npcap](https://npcap.com/) installed.
- **Linux / macOS:** run with `sudo`, e.g. `sudo python ip_scanner.py 192.168.1.0/24`.

If you don't run elevated, the scanner automatically falls back to the ping
sweep and reads MAC addresses from the system ARP cache.

### Options

| Option        | Description                                             | Default |
|---------------|---------------------------------------------------------|---------|
| `subnet`      | Subnet to scan in CIDR notation (positional, required)  | —       |
| `--timeout`   | Per-host timeout in seconds                              | `1.0`   |
| `--workers`   | Number of concurrent ping workers                       | `100`   |
| `--no-arp`    | Disable the scapy ARP scan; use the ping sweep only     | off     |
| `--json FILE` | Also write the results to `FILE` as JSON                | —       |

## Example output

```
Scanning 192.168.1.0/24 (254 addresses)...

IP Address     MAC Address        Hostname         Vendor                Device Type
------------   -----------------  ---------------  --------------------  ----------------------
192.168.1.1    A4:2B:B0:11:22:33  router.lan       TP-Link Technologies  Router / Network gear
192.168.1.10   DC:A6:32:44:55:66  raspberrypi      Raspberry Pi Trading  Raspberry Pi
192.168.1.23   3C:22:FB:77:88:99  Johns-iPhone     Apple, Inc.           Phone / Apple device
192.168.1.42   B8:27:EB:AA:BB:CC  nas.lan          Synology              NAS / Storage
192.168.1.50   00:11:22:DD:EE:FF  workstation      Intel Corporate       PC / Server

5 host(s) up.
```

## Notes & legal

- Only scan networks you **own or are explicitly authorised to test**.
  Unauthorised scanning may be against the law or against network policies.
- Results are best-effort. Device-type detection relies on vendor/hostname
  heuristics and may misclassify or leave devices as *Unknown* (for example
  when a device randomises its MAC address, as many modern phones do).
- ICMP replies can be blocked by host firewalls, so some live hosts may not
  respond to the ping sweep; the ARP scan usually still finds them on the
  local link.

## License

Released under the [MIT License](LICENSE) — free to use, modify and
redistribute, provided the copyright notice is retained. The software comes
with no warranty; see [`LICENSE`](LICENSE) for the full text.

Intended for educational use and authorised network administration (see
**Notes & legal** above).
