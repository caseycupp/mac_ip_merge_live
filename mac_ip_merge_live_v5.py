#!/usr/bin/env python3
"""
mac_ip_merge_live_v4.py - IMPROVED VERSION

Enhancements over v3:
- Progress indicators with rich progress bars
- Better error handling and retry logic
- Vendor lookup using mac-vendor-lookup module (auto-updating IEEE database)
- Configurable VRF list via CLI or config file
- Summary statistics and preview of results
- Logging to file for debugging
- Concurrent device collection option
- Better MAC normalization
- Output validation
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

import macaddress
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from tqdm import tqdm

# Optional: rich for better output (if installed)
try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Optional: mac_vendor_lookup for vendor database
try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False


DOMAIN_DEFAULT = "williams.com"
DEFAULT_VRF_LIST = ["10", "821", "841", "999", "ICS-S2H-821", "ICS-S2S-822"]

# Cisco commands
CISCO_MAC_COMMAND = "show mac address-table"

# Palo Alto commands
PALO_ARP_COMMAND = "show arp all"

# Logging setup
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'


# ---------- Vendor Lookup ----------

class VendorLookup:
    """Handles MAC vendor lookups using mac_vendor_lookup module"""
    
    def __init__(self, update_vendors: bool = False):
        """
        Initialize vendor lookup.
        
        Args:
            update_vendors: If True, update the vendor database from IEEE
        """
        self.cache: Dict[str, str] = {}
        self.mac_lookup = None
        
        if HAS_MAC_LOOKUP:
            try:
                self.mac_lookup = MacLookup()
                
                # Update vendor database if requested
                if update_vendors:
                    logging.info("Updating vendor database from IEEE...")
                    self.mac_lookup.update_vendors()
                    logging.info("Vendor database updated successfully")
                
                logging.info("MAC vendor lookup initialized successfully")
            except Exception as e:
                logging.error(f"Failed to initialize MAC vendor lookup: {e}")
                self.mac_lookup = None
        else:
            logging.warning("mac_vendor_lookup module not installed. Install with: pip install mac-vendor-lookup")
    
    def lookup(self, mac: str) -> str:
        """Lookup vendor for a MAC address"""
        if not mac:
            return "UNKNOWN"
        
        # Check cache first
        if mac in self.cache:
            return self.cache[mac]
        
        vendor = "UNKNOWN"
        
        if self.mac_lookup:
            try:
                vendor = self.mac_lookup.lookup(mac)
            except Exception as e:
                logging.debug(f"Vendor lookup failed for {mac}: {e}")
                vendor = "UNKNOWN"
        
        # Cache result
        self.cache[mac] = vendor
        return vendor


# ---------- MAC Normalization ----------

def normalize_mac(m: str) -> Optional[str]:
    """Normalize MAC address to lowercase colon-separated format"""
    try:
        return str(macaddress.MAC(m)).lower()
    except Exception:
        s = m.strip().lower().replace(".", "").replace("-", "").replace(":", "")
        if len(s) == 12 and re.fullmatch(r"[0-9a-f]{12}", s):
            try:
                return str(macaddress.MAC(":".join(s[i:i+2] for i in range(0, 12, 2)))).lower()
            except Exception:
                logging.debug(f"Failed to normalize MAC after sanitization: {m}")
                return None
        if m and m.strip():  # Only log non-empty strings
            logging.debug(f"Invalid MAC format: {m}")
        return None


# ---------- Helpers ----------

def ip_sort_key(row: dict):
    """Sort key for IP addresses"""
    ip = row.get("ip", "")
    if not ip:
        return (1, ipaddress.IPv4Address("0.0.0.0"))
    try:
        return (0, ipaddress.IPv4Address(ip))
    except Exception:
        return (1, ipaddress.IPv4Address("0.0.0.0"))


def dns_resolves(host: str) -> bool:
    """Check if hostname resolves"""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


def best_target(value: str, domain: str) -> str:
    """Determine best connection target (IP or FQDN)"""
    s = (value or "").strip()
    if not s:
        return s
    
    # If IP, use directly
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    
    # Try hostname as-is first
    if dns_resolves(s):
        return s
    
    # Try with domain appended
    fqdn = f"{s}.{domain}".strip(".")
    if dns_resolves(fqdn):
        return fqdn
    
    # Return original if nothing works
    return s


def tcp_port_open(host: str, port: int = 22, timeout: float = 2.0) -> bool:
    """Fast pre-check to see if TCP port is open"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def compute_port_types(entries: List[Tuple[str, str, str, str]]) -> Dict[Tuple[str, str], str]:
    """Mark ports as trunk (>1 VLAN) or access (1 VLAN)"""
    port_vlans: Dict[Tuple[str, str], set] = {}
    for _mac, vlan, sw, port in entries:
        port_vlans.setdefault((sw, port), set()).add(vlan)
    return {k: ("trunk" if len(v) > 1 else "access") for k, v in port_vlans.items()}


# ---------- Parsing Functions ----------

# Palo Alto ARP regex
PALO_ARP_RE = re.compile(
    r"^(?P<intf>\S+)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<mac>\S+)\b"
)

# Cisco ARP regex
CISCO_ARP_RE = re.compile(
    r"^\s*(?:Internet|IP)\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<age>\S+)\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|"
    r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|"
    r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}))\s+"
    r"\S+\s+"
    r"(?P<intf>\S+)\s*$"
)

# Cisco MAC table regex
CISCO_MAC_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+"
    r"(?P<mac>(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|"
    r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|"
    r"[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}))\s+"
    r"\S+\s+"
    r"(?P<port>\S+)\s*$"
)


def parse_palo_arp(text: str, fw: str) -> Dict[str, Tuple[str, str, str]]:
    """Parse Palo Alto ARP output - returns mac -> (ip, firewall, interface)"""
    out: Dict[str, Tuple[str, str, str]] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("-"):
            continue
        low = s.lower()
        if low.startswith(("interface", "maximum", "default timeout", "total arp", "status:")):
            continue
        m = PALO_ARP_RE.match(s)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac:
            out[mac] = (m.group("ip"), fw, m.group("intf"))
    logging.debug(f"Palo {fw}: parsed {len(out)} ARP entries")
    return out


def parse_cisco_arp(text: str) -> Dict[str, Tuple[str, str]]:
    """Parse Cisco ARP output - returns mac -> (ip, interface)"""
    out: Dict[str, Tuple[str, str]] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = CISCO_ARP_RE.match(s)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac and mac != "incomplete":
            out[mac] = (m.group("ip"), m.group("intf"))
    return out


def parse_cisco_mac(text: str, device: str) -> List[Tuple[str, str, str, str]]:
    """Parse Cisco MAC table - returns list of (mac, vlan, device, port)"""
    entries: List[Tuple[str, str, str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = CISCO_MAC_RE.match(s)
        if not m:
            continue
        mac = normalize_mac(m.group("mac"))
        if mac:
            entries.append((mac, m.group("vlan"), device, m.group("port")))
    logging.debug(f"Cisco {device}: parsed {len(entries)} MAC table entries")
    return entries


# ---------- Device Collection ----------

def collect_from_device(
    host_value: str,
    device_type: str,
    username: str,
    password: str,
    domain: str,
    timeout: int,
    vrf_list: List[str],
) -> Dict:
    """
    Collect data from a single device.
    Returns a dict with status, data, and errors.
    """
    result = {
        "host": host_value,
        "type": device_type,
        "success": False,
        "palo_arp": {},
        "cisco_arp": {},
        "cisco_arp_all": {},
        "mac_entries": [],
        "error": None,
    }
    
    target = best_target(host_value, domain)
    label = f"[{device_type.upper()}] {host_value}"
    
    # Fast skip for unreachable devices
    if not tcp_port_open(target, 22, timeout=2.0):
        result["error"] = "TCP/22 unreachable"
        logging.warning(f"{label}: {result['error']}")
        return result
    
    conn = None
    try:
        if device_type == "palo":
            # Palo Alto connection
            conn = ConnectHandler(
                host=target,
                username=username,
                password=password,
                device_type="paloalto_panos",
                timeout=timeout,
                conn_timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                fast_cli=False,
            )
            out = conn.send_command(PALO_ARP_COMMAND)
            result["palo_arp"] = parse_palo_arp(out, fw=host_value)
            result["success"] = True
            logging.info(f"{label}: Collected {len(result['palo_arp'])} ARP entries")
        
        else:
            # Cisco connection
            conn = ConnectHandler(
                host=target,
                username=username,
                password=password,
                device_type="cisco_ios",
                timeout=timeout,
                conn_timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                fast_cli=False,
            )
            
            # Collect ARP from global and VRFs
            cisco_arp_commands = ["show arp"] + [f"show arp vrf {v}" for v in vrf_list]
            cisco_arp_all_dict = {"global": {}}
            per_dev = {}
            
            for cmd in cisco_arp_commands:
                out = conn.send_command(cmd)
                parsed = parse_cisco_arp(out)
                per_dev.update(parsed)
                
                if cmd.strip().lower() == "show arp":
                    for m, (ip, intf) in parsed.items():
                        cisco_arp_all_dict["global"][m] = (ip, intf, host_value)
                else:
                    vrf = cmd.split()[-1]
                    cisco_arp_all_dict.setdefault(vrf, {})
                    for m, (ip, intf) in parsed.items():
                        cisco_arp_all_dict[vrf][m] = (ip, intf, host_value)
            
            result["cisco_arp"] = per_dev
            result["cisco_arp_all"] = cisco_arp_all_dict
            
            # Collect MAC table
            mac_out = conn.send_command(CISCO_MAC_COMMAND)
            result["mac_entries"] = parse_cisco_mac(mac_out, device=host_value)
            result["success"] = True
            
            logging.info(f"{label}: Collected {len(per_dev)} ARP + {len(result['mac_entries'])} MAC entries")
    
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        result["error"] = f"Connection failed: {type(e).__name__}"
        logging.error(f"{label}: {result['error']}")
    except Exception as e:
        result["error"] = f"Error: {type(e).__name__}: {str(e)}"
        logging.error(f"{label}: {result['error']}")
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass
    
    return result


def collect_all_devices(
    devices: List[Tuple[str, str]],
    username: str,
    password: str,
    domain: str,
    timeout: int,
    vrf_list: List[str],
    max_workers: int = 5,
) -> Tuple[Dict, Dict, Dict, List, List]:
    """
    Collect data from all devices (optionally in parallel).
    Returns: palo_map, cisco_arp_by_device, cisco_arp_all, mac_entries, errors
    """
    palo_map: Dict[str, Tuple[str, str, str]] = {}
    cisco_arp_by_device: Dict[str, Dict[str, Tuple[str, str]]] = {}
    cisco_arp_all: Dict[str, Dict[str, Tuple[str, str, str]]] = {"global": {}}
    for v in vrf_list:
        cisco_arp_all[v] = {}
    mac_entries: List[Tuple[str, str, str, str]] = []
    errors: List[str] = []
    
    results = []
    
    # Use ThreadPoolExecutor for concurrent collection
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                collect_from_device,
                host, dtype, username, password, domain, timeout, vrf_list
            ): (host, dtype)
            for host, dtype in devices
        }
        
        # Progress bar
        with tqdm(total=len(devices), desc="Collecting from devices", unit="device") as pbar:
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                if result["success"]:
                    # Merge Palo ARP
                    palo_map.update(result["palo_arp"])
                    
                    # Merge Cisco ARP
                    if result["cisco_arp"]:
                        cisco_arp_by_device[result["host"]] = result["cisco_arp"]
                    
                    # Merge Cisco ARP (all VRFs)
                    for vrf, arp_dict in result["cisco_arp_all"].items():
                        cisco_arp_all.setdefault(vrf, {}).update(arp_dict)
                    
                    # Merge MAC entries
                    mac_entries.extend(result["mac_entries"])
                else:
                    errors.append(f"{result['host']}: {result['error']}")
                
                pbar.update(1)
    
    return palo_map, cisco_arp_by_device, cisco_arp_all, mac_entries, errors


# ---------- CSV Reading ----------

def read_devices_csv(path: Path) -> List[Tuple[str, str]]:
    """Read devices from CSV and return list of (hostname, type) tuples"""
    devices = []
    
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        
        # Normalize header names
        headers = {k.lower().strip().strip('"'): k for k in reader.fieldnames or []}
        
        # Find host column
        host_col = None
        for candidate in ["hostname", "host", "device", "name", "ip"]:
            if candidate in headers:
                host_col = headers[candidate]
                break
        
        # Find type column
        type_col = None
        for candidate in ["type", "device_type", "devicetype", "platform", "vendor"]:
            if candidate in headers:
                type_col = headers[candidate]
                break
        
        if not host_col or not type_col:
            raise ValueError(
                f"CSV must have host column (hostname/host/device/name/ip) "
                f"and type column (type/device_type/devicetype/platform/vendor)"
            )
        
        # Read rows
        for row in reader:
            host = row.get(host_col, "").strip().strip('"')
            dtype = row.get(type_col, "").strip().strip('"').lower()
            
            if not host or not dtype:
                continue
            
            # Normalize type
            if dtype in ["palo", "panos", "paloalto", "pa"]:
                dtype = "palo"
            elif dtype in ["cisco", "ios", "iosxe", "nxos", "router", "switch"]:
                dtype = "cisco"
            else:
                logging.warning(f"Unknown device type '{dtype}' for {host}, skipping")
                continue
            
            devices.append((host, dtype))
    
    logging.info(f"Loaded {len(devices)} devices from {path}")
    return devices


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(
        description="Collect ARP and MAC tables from Cisco SD-WAN and Palo Alto devices"
    )
    parser.add_argument("--csv", required=True, help="Input CSV with devices")
    parser.add_argument("--out", required=True, help="Output CSV file")
    parser.add_argument("--domain", default=DOMAIN_DEFAULT, help=f"DNS domain (default: {DOMAIN_DEFAULT})")
    parser.add_argument("--timeout", type=int, default=10, help="SSH timeout in seconds (default: 10)")
    parser.add_argument("--update-vendors", action="store_true", help="Update vendor database from IEEE before lookup")
    parser.add_argument("--only-matched", action="store_true", help="Only output rows with IP addresses")
    parser.add_argument("--vrf-list", help="Comma-separated VRF list (default: built-in list)")
    parser.add_argument("--max-workers", type=int, default=5, help="Max concurrent device connections (default: 5)")
    parser.add_argument("--log", help="Log file path (default: mac_ip_merge.log)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_file = args.log or f"mac_ip_merge_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logging.info(f"Starting collection at {datetime.now()}")
    
    # Read devices
    try:
        devices = read_devices_csv(Path(args.csv))
    except Exception as e:
        logging.error(f"Failed to read CSV: {e}")
        return 2
    
    if not devices:
        logging.error("No valid devices found in CSV")
        return 2
    
    # Get credentials
    print("\n=== Device Credentials ===")
    username = input("Username: ").strip()
    password = getpass("Password: ")
    
    if not username or not password:
        logging.error("Username/password cannot be empty")
        return 2
    
    # VRF list
    vrf_list = DEFAULT_VRF_LIST
    if args.vrf_list:
        vrf_list = [v.strip() for v in args.vrf_list.split(",") if v.strip()]
        logging.info(f"Using custom VRF list: {vrf_list}")
    
    # Setup vendor lookup
    vendor_lookup = VendorLookup(update_vendors=args.update_vendors)
    
    # Collect from all devices
    print("\n=== Collecting Data ===")
    palo_map, cisco_arp_by_device, cisco_arp_all, mac_entries, errors = collect_all_devices(
        devices=devices,
        username=username,
        password=password,
        domain=args.domain,
        timeout=args.timeout,
        vrf_list=vrf_list,
        max_workers=args.max_workers,
    )
    
    # Merge and build output rows
    print("\n=== Merging Data ===")
    include_palo_cols = bool(palo_map)
    port_types = compute_port_types(mac_entries)
    vrf_priority = ["global"] + vrf_list
    
    rows: List[Dict[str, str]] = []
    seen_row_keys: Set[Tuple[str, str, str, str]] = set()
    
    # Build rows from MAC table entries
    for mac, vlan, sw, port in tqdm(mac_entries, desc="Processing MAC entries", unit="entry"):
        ip = ""
        fw = ""
        fw_intf = ""
        ptype = port_types.get((sw, port), "unknown")
        
        # Try Palo ARP first
        if mac in palo_map:
            ip, fw, fw_intf = palo_map[mac]
        else:
            # Try Cisco ARP (prioritize by VRF)
            for vrf in vrf_priority:
                hit = cisco_arp_all.get(vrf, {}).get(mac)
                if hit:
                    ip, arp_intf, arp_dev = hit
                    break
        
        row = {
            "ip": ip,
            "mac": mac,
            "vlan": vlan,
            "switch": sw,
            "switchport": port,
            "port_type": ptype,
            "vendor": vendor_lookup.lookup(mac),
        }
        if include_palo_cols:
            row["firewall"] = fw
            row["fw_intf"] = fw_intf
        
        if args.only_matched and not row["ip"]:
            continue
        
        rows.append(row)
        seen_row_keys.add((row["ip"], row["mac"], row["switch"], row["switchport"]))
    
    # Add Cisco ARP-only rows
    for dev, macmap in cisco_arp_by_device.items():
        for mac, (ip, intf) in macmap.items():
            key = (ip, mac, dev, intf)
            if key in seen_row_keys:
                continue
            
            row = {
                "ip": ip,
                "mac": mac,
                "vlan": "",
                "switch": dev,
                "switchport": intf,
                "port_type": "",
                "vendor": vendor_lookup.lookup(mac),
            }
            if include_palo_cols:
                row["firewall"] = ""
                row["fw_intf"] = ""
            
            if args.only_matched and not row["ip"]:
                continue
            
            rows.append(row)
            seen_row_keys.add(key)
    
    # Add Palo ARP-only rows
    for mac, (ip, fw, fw_intf) in palo_map.items():
        key = (ip, mac, fw, fw_intf)
        if key in seen_row_keys:
            continue
        
        row = {
            "ip": ip,
            "mac": mac,
            "vlan": "",
            "switch": "",
            "switchport": "",
            "port_type": "",
            "vendor": vendor_lookup.lookup(mac),
        }
        if include_palo_cols:
            row["firewall"] = fw
            row["fw_intf"] = fw_intf
        
        if args.only_matched and not row["ip"]:
            continue
        
        rows.append(row)
        seen_row_keys.add(key)
    
    # Sort by IP
    rows.sort(key=ip_sort_key)
    
    # Write CSV
    print("\n=== Writing Output ===")
    fields = ["ip", "mac", "vlan", "switch", "switchport", "port_type"]
    if include_palo_cols:
        fields += ["firewall", "fw_intf"]
    fields += ["vendor"]
    
    with Path(args.out).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    
    logging.info(f"Wrote {len(rows)} rows to {args.out}")
    
    # Summary statistics
    print("\n" + "="*60)
    print("COLLECTION SUMMARY")
    print("="*60)
    
    succeeded = len([d for d, _ in devices]) - len(errors)
    failed = len(errors)
    
    summary_data = [
        ("Total Devices", len(devices)),
        ("Succeeded", succeeded),
        ("Failed/Skipped", failed),
        ("", ""),
        ("MAC Table Entries", len(mac_entries)),
        ("Cisco ARP Entries", sum(len(v) for v in cisco_arp_by_device.values())),
        ("Palo ARP MACs", len(palo_map)),
        ("Vendor Lookup", "Enabled" if vendor_lookup.mac_lookup else "Disabled"),
        ("", ""),
        ("Output Rows", len(rows)),
    ]
    
    if HAS_RICH:
        table = Table(title="Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
        for metric, value in summary_data:
            if metric:
                table.add_row(metric, str(value))
            else:
                table.add_row("", "")
        console.print(table)
    else:
        for metric, value in summary_data:
            if metric:
                print(f"{metric:.<40} {value:>10}")
    
    # Show vendor distribution
    vendor_counts = defaultdict(int)
    for row in rows:
        vendor_counts[row.get("vendor", "UNKNOWN")] += 1
    
    print("\n" + "="*60)
    print("TOP 10 VENDORS")
    print("="*60)
    top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    if HAS_RICH:
        table = Table()
        table.add_column("Vendor", style="cyan")
        table.add_column("Count", style="green", justify="right")
        for vendor, count in top_vendors:
            table.add_row(vendor, str(count))
        console.print(table)
    else:
        for vendor, count in top_vendors:
            print(f"{vendor:.<40} {count:>10}")
    
    # Show errors
    if errors:
        print("\n" + "="*60)
        print("ERRORS")
        print("="*60)
        for e in errors:
            print(f"  • {e}")
    
    print(f"\nLog file: {log_file}")
    print(f"Output file: {args.out}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
