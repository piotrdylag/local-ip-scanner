#!/usr/bin/env python3
"""
Local Network IP Scanner
========================

Scans a local subnet (e.g. 192.168.1.0/24) and reports for every host:
  * whether it is UP
  * its IP address
  * its MAC address
  * its hostname (if resolvable)
  * its vendor (from the MAC OUI database)
  * a best-effort guess of the device *type* (Phone, Raspberry Pi, PC,
    Router, Server, Printer, TV, IoT, ...) similar to "Advanced IP Scanner".

Two scanning strategies are used:
  1. An ARP scan (via scapy) when available and permitted -- this is the most
     reliable way to obtain MAC addresses on the local link.
  2. A concurrent ICMP ping sweep combined with a read of the system ARP
     cache -- used as a fallback that works without extra privileges/modules.

Usage:
    python ip_scanner.py 192.168.1.0/24
    python ip_scanner.py 192.168.1.0/24 --timeout 1.5 --workers 200
    python ip_scanner.py 10.0.0.0/24 --no-arp          # force ping sweep
    python ip_scanner.py 192.168.1.0/24 --json out.json
"""

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Optional dependencies (the tool degrades gracefully if they are missing)
# ---------------------------------------------------------------------------
try:
    from scapy.all import ARP, Ether, srp  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:  # ImportError or runtime import errors
    SCAPY_AVAILABLE = False

try:
    from mac_vendor_lookup import MacLookup  # type: ignore

    MAC_LOOKUP_AVAILABLE = True
except Exception:
    MAC_LOOKUP_AVAILABLE = False


IS_WINDOWS = platform.system().lower().startswith("win")


# ---------------------------------------------------------------------------
# Terminal colours (disabled automatically when output is not a TTY)
# ---------------------------------------------------------------------------
class C:
    if sys.stdout.isatty():
        GREEN = "\033[92m"
        RED = "\033[91m"
        CYAN = "\033[96m"
        YELLOW = "\033[93m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"
    else:
        GREEN = RED = CYAN = YELLOW = BOLD = DIM = RESET = ""


# ---------------------------------------------------------------------------
# MAC vendor lookup
# ---------------------------------------------------------------------------
_mac_lookup = None


def get_mac_lookup():
    """Lazily build a MacLookup instance (loads the offline OUI database)."""
    global _mac_lookup
    if _mac_lookup is None and MAC_LOOKUP_AVAILABLE:
        try:
            _mac_lookup = MacLookup()
        except Exception:
            _mac_lookup = None
    return _mac_lookup


def lookup_vendor(mac):
    """Return the vendor name for a MAC address, or '' if unknown."""
    if not mac:
        return ""
    ml = get_mac_lookup()
    if ml is None:
        return ""
    try:
        return ml.lookup(mac)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Device-type inference
# ---------------------------------------------------------------------------
# Ordered list of (keywords, device-type) rules. The first rule whose keyword
# appears in the vendor string or hostname wins.
DEVICE_RULES = [
    (["raspberry"], "Raspberry Pi"),
    (["apple", "iphone", "ipad"], "Phone / Apple device"),
    (["samsung", "xiaomi", "huawei", "oneplus", "oppo", "vivo", "realme",
      "motorola", "nokia", "google pixel", "pixel"], "Phone / Mobile"),
    (["espressif", "tuya", "sonoff", "shelly", "tasmota", "esp32", "esp8266",
      "nest", "ring", "wyze", "tp-link smart", "smartthings"], "IoT / Smart device"),
    (["hikvision", "dahua", "reolink", "axis comm", "ubiquiti camera"], "IP Camera"),
    (["hewlett", "hp inc", "canon", "epson", "brother", "lexmark",
      "kyocera", "xerox", "printer"], "Printer"),
    (["cisco", "netgear", "tp-link", "d-link", "ubiquiti", "mikrotik",
      "asus", "zyxel", "aruba", "juniper", "fortinet", "router", "gateway"],
     "Router / Network gear"),
    (["synology", "qnap", "western digital", "seagate", "nas"], "NAS / Storage"),
    (["sony", "lg electronics", "vizio", "roku", "chromecast", "firetv",
      "amazon technologies", "philips", "tcl", "tv"], "Smart TV / Media"),
    (["intel", "dell", "lenovo", "micro-star", "msi", "gigabyte", "asrock",
      "supermicro", "vmware", "virtualbox", "qemu", "parallels"],
     "PC / Server"),
    (["server", "srv"], "Server"),
]


def guess_device_type(vendor, hostname):
    """Guess a human-friendly device type from vendor + hostname strings."""
    haystack = f"{vendor} {hostname}".lower()
    for keywords, dtype in DEVICE_RULES:
        for kw in keywords:
            if kw in haystack:
                return dtype
    if vendor:
        return "Unknown device"
    return "Unknown"


# ---------------------------------------------------------------------------
# Hostname resolution
# ---------------------------------------------------------------------------
def resolve_hostname(ip, timeout=2.0):
    """Reverse-DNS lookup bounded by `timeout` seconds (returns '' on failure).

    ``socket.gethostbyaddr`` can block for a long time on addresses with no PTR
    record, so it is run in a worker thread and abandoned if it overruns.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(socket.gethostbyaddr, ip)
        try:
            return future.result(timeout=timeout)[0]
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# ICMP ping
# ---------------------------------------------------------------------------
def ping(ip, timeout=1.0):
    """Return True if `ip` replies to a single ICMP echo request."""
    if IS_WINDOWS:
        # -n 1 : one echo, -w ms : timeout in milliseconds
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
    else:
        # -c 1 : one echo, -W s : timeout in seconds (integer, min 1)
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), str(ip)]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# System ARP cache parsing (fallback MAC source)
# ---------------------------------------------------------------------------
MAC_RE = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


def normalize_mac(mac):
    if not mac:
        return ""
    mac = mac.replace("-", ":").lower()
    return mac


def read_arp_table():
    """Return a dict {ip: mac} parsed from the OS ARP cache."""
    table = {}
    try:
        if IS_WINDOWS:
            output = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=10
            ).stdout
        else:
            # Prefer `ip neigh` on modern Linux; fall back to `arp -a`.
            try:
                output = subprocess.run(
                    ["ip", "neigh"], capture_output=True, text=True, timeout=10
                ).stdout
            except FileNotFoundError:
                output = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10
                ).stdout
    except Exception:
        return table

    for line in output.splitlines():
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        mac_match = MAC_RE.search(line)
        if ip_match and mac_match:
            table[ip_match.group(1)] = normalize_mac(mac_match.group(0))
    return table


# ---------------------------------------------------------------------------
# Scanning strategies
# ---------------------------------------------------------------------------
def arp_scan(network, timeout=2.0):
    """Fast ARP scan using scapy. Returns dict {ip: mac}. Needs privileges."""
    results = {}
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        for _, received in answered:
            results[received.psrc] = normalize_mac(received.hwsrc)
    except PermissionError:
        print(
            f"{C.YELLOW}[!] ARP scan needs elevated privileges; "
            f"falling back to ping sweep.{C.RESET}"
        )
    except Exception as exc:
        msg = str(exc).lower()
        if "winpcap" in msg or "npcap" in msg or "layer 2" in msg:
            print(
                f"{C.YELLOW}[!] ARP scan unavailable: Npcap is not installed. "
                f"Install it from https://npcap.com to enable the ARP scan "
                f"(or run with --no-arp to hide this). Falling back to ping "
                f"sweep + system ARP cache for MAC addresses.{C.RESET}"
            )
        else:
            print(
                f"{C.YELLOW}[!] ARP scan failed ({exc}); using ping sweep.{C.RESET}"
            )
    return results


def progress_bar(done, total, suffix="", width=32, prefix="Progress"):
    """Render a single-line, in-place progress bar to stderr."""
    if total <= 0:
        return
    frac = done / total
    filled = int(width * frac)
    bar = "#" * filled + "-" * (width - filled)
    end = "\n" if done >= total else ""
    tail = f" {suffix}" if suffix else ""
    sys.stderr.write(
        f"\r{C.DIM}{prefix:<11}{C.RESET} [{C.GREEN}{bar}{C.RESET}] "
        f"{done:>4}/{total} ({frac * 100:5.1f}%){tail}{end}"
    )
    sys.stderr.flush()


def ping_sweep(hosts, timeout=1.0, workers=100, show_progress=True):
    """Ping many hosts concurrently. Returns a set of IPs that are UP."""
    alive = set()
    total = len(hosts)
    done = 0
    # Only draw the live bar on an interactive terminal.
    show_progress = show_progress and sys.stderr.isatty()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_ip = {pool.submit(ping, ip, timeout): ip for ip in hosts}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    alive.add(ip)
            except Exception:
                pass
            done += 1
            if show_progress:
                progress_bar(
                    done, total,
                    suffix=f"{C.GREEN}{len(alive)} up{C.RESET}",
                    prefix="Ping sweep",
                )
    return alive


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def scan_network(cidr, timeout=1.0, workers=100, use_arp=True):
    """Run the full scan and return a sorted list of host dictionaries."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    print(
        f"{C.BOLD}Scanning {C.CYAN}{network}{C.RESET}{C.BOLD} "
        f"({len(hosts)} addresses)...{C.RESET}\n"
    )

    mac_map = {}
    alive = set()

    # Strategy 1: ARP scan (best MAC coverage) --------------------------------
    if use_arp and SCAPY_AVAILABLE:
        print(f"{C.DIM}Performing ARP scan...{C.RESET}")
        mac_map = arp_scan(network, timeout=max(timeout, 2.0))
        alive.update(mac_map.keys())

    # Strategy 2: ICMP ping sweep (finds hosts ARP may have missed) ----------
    print(f"{C.DIM}Performing ping sweep...{C.RESET}")
    alive.update(ping_sweep(hosts, timeout=timeout, workers=workers))

    # Fill in any missing MACs from the OS ARP cache -------------------------
    arp_cache = read_arp_table()
    for ip in alive:
        if ip not in mac_map and ip in arp_cache:
            mac_map[ip] = arp_cache[ip]

    # Build result records ----------------------------------------------------
    # Reverse-DNS is the slow (network) part, so resolve hostnames concurrently
    # with a progress bar. The MAC->vendor lookup is fast and offline, but the
    # underlying library uses asyncio and only works on the main thread, so it
    # is done here rather than inside the worker threads.
    alive_sorted = sorted(alive, key=lambda a: ipaddress.ip_address(a))

    print(f"{C.DIM}Resolving hostnames & vendors...{C.RESET}")
    hostnames = {}
    total = len(alive_sorted)
    show_progress = sys.stderr.isatty()
    if total:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(50, total)
        ) as pool:
            futures = {pool.submit(resolve_hostname, ip): ip for ip in alive_sorted}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                hostnames[ip] = future.result()
                done += 1
                if show_progress:
                    progress_bar(done, total, prefix="Resolving")

    results = []
    for ip in alive_sorted:
        mac = mac_map.get(ip, "")
        vendor = lookup_vendor(mac)  # main thread: asyncio works here
        hostname = hostnames.get(ip, "")
        results.append(
            {
                "ip": ip,
                "status": "up",
                "mac": mac.upper() if mac else "",
                "hostname": hostname,
                "vendor": vendor,
                "device_type": guess_device_type(vendor, hostname),
            }
        )
    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_table(results):
    if not results:
        print(f"{C.YELLOW}No live hosts found.{C.RESET}")
        return

    headers = ["IP Address", "MAC Address", "Hostname", "Vendor", "Device Type"]
    rows = [
        [
            r["ip"],
            r["mac"] or "-",
            (r["hostname"] or "-")[:28],
            (r["vendor"] or "-")[:26],
            r["device_type"],
        ]
        for r in results
    ]

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt(cells, colour=""):
        line = "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))
        return f"{colour}{line}{C.RESET}" if colour else line

    print(fmt(headers, C.BOLD + C.CYAN))
    print(C.DIM + "  ".join("-" * w for w in widths) + C.RESET)
    for row in rows:
        print(fmt(row, C.GREEN))

    print(f"\n{C.BOLD}{len(results)} host(s) up.{C.RESET}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan a local network for live hosts, MAC addresses and "
        "device types.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "subnet",
        help="Subnet in CIDR notation, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-host timeout in seconds.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent ping workers.",
    )
    parser.add_argument(
        "--no-arp",
        action="store_true",
        help="Disable the scapy ARP scan and use the ping sweep only.",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Also write the results to FILE as JSON.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    try:
        ipaddress.ip_network(args.subnet, strict=False)
    except ValueError as exc:
        print(f"{C.RED}Invalid subnet '{args.subnet}': {exc}{C.RESET}")
        return 2

    if not MAC_LOOKUP_AVAILABLE:
        print(
            f"{C.YELLOW}[!] 'mac-vendor-lookup' not installed; vendor and "
            f"device-type detection will be limited.{C.RESET}"
        )
    if not SCAPY_AVAILABLE and not args.no_arp:
        print(
            f"{C.YELLOW}[!] 'scapy' not installed; using ping sweep + system "
            f"ARP cache for MAC addresses.{C.RESET}"
        )

    start = time.time()
    results = scan_network(
        args.subnet,
        timeout=args.timeout,
        workers=args.workers,
        use_arp=not args.no_arp,
    )
    elapsed = time.time() - start

    print()
    print_table(results)
    print(f"{C.DIM}Scan completed in {elapsed:.1f}s.{C.RESET}")

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
            print(f"{C.DIM}Results written to {args.json}.{C.RESET}")
        except OSError as exc:
            print(f"{C.RED}Could not write JSON file: {exc}{C.RESET}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Scan interrupted by user.{C.RESET}")
        sys.exit(130)
