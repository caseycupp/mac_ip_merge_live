#!/usr/bin/env python3
"""MAC/IP Merge - Collect ARP and MAC tables, output to CSV"""

import csv
import sys
import logging
import getpass
import argparse
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from cisco_driver import CiscoIOSDriver
from paloalto_driver import PaloAltoDriver
from mac_path_tracer import MACPathTracer

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress verbose netmiko/paramiko logging even in debug mode
logging.getLogger('netmiko').setLevel(logging.WARNING)
logging.getLogger('paramiko').setLevel(logging.WARNING)

DRIVERS = {
    # Support both short and long forms for better UX
    'cisco': CiscoIOSDriver,
    'cisco_ios': CiscoIOSDriver,
    'cisco_iosxe': CiscoIOSDriver,
    'paloalto': PaloAltoDriver,
    'paloalto_panos': PaloAltoDriver,
}


class MACIPMerge:
    def __init__(self):
        self.devices = []
        self.arp_data = {}  # {ip: [{mac, vrf, interface, device_ip, hostname, device_type}]}
        self.mac_data = {}  # {mac: [{vlan, device_ip, hostname, interface, port_type}]}
        self.failed_devices = []
        self.devices_scanned = 0
        self.start_time = None
        self.end_time = None
        self.path_tracer = MACPathTracer()  # For MAC path tracing

    def load_devices(self, csv_file: str) -> bool:
        """Load devices from CSV with validation"""
        try:
            csv_path = Path(csv_file)
            if not csv_path.exists():
                logger.error(f"Device file not found: {csv_file}")
                return False
            
            with open(csv_file) as f:
                reader = csv.DictReader(f)
                
                # Validate required columns
                required_cols = {'hostname', 'type'}
                if not required_cols.issubset(reader.fieldnames):
                    missing = required_cols - set(reader.fieldnames)
                    logger.error(f"Missing required columns in CSV: {missing}")
                    logger.error(f"Required columns: {required_cols}")
                    return False
                
                self.devices = list(reader)
                
                # Validate device types
                invalid_types = []
                for device in self.devices:
                    dtype = device['type'].lower()
                    if dtype not in DRIVERS:
                        invalid_types.append((device['hostname'], dtype))
                
                if invalid_types:
                    logger.error("Invalid device types found:")
                    for host, dtype in invalid_types:
                        logger.error(f"  {host}: {dtype}")
                    logger.error(f"Valid types: {list(DRIVERS.keys())}")
                    return False
            
            logger.info(f"Loaded {len(self.devices)} devices from {csv_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load devices: {e}")
            return False

    def preflight_check(self, username: str, password: str) -> bool:
        """Pre-flight connectivity check"""
        logger.info("=" * 50)
        logger.info("PRE-FLIGHT CONNECTIVITY CHECK")
        logger.info("=" * 50)
        
        reachable = 0
        unreachable = 0
        
        for device_row in self.devices:
            device_ip = device_row['hostname']
            device_type = device_row['type'].lower()
            
            driver_class = DRIVERS[device_type]
            driver = driver_class(device_ip, username, password, device_type)
            
            if driver.connect():
                logger.info(f"✓ {device_ip} ({device_type}) - OK")
                driver.disconnect()
                reachable += 1
            else:
                logger.error(f"✗ {device_ip} ({device_type}) - FAILED")
                unreachable += 1
        
        logger.info("=" * 50)
        logger.info(f"Pre-flight results: {reachable} reachable, {unreachable} unreachable")
        logger.info("=" * 50)
        return unreachable == 0

    def collect_data(self, username: str, password: str):
        """Collect ARP and MAC data from all devices"""
        logger.info("=" * 50)
        logger.info("COLLECTING DATA")
        logger.info("=" * 50)
        
        self.start_time = datetime.now()
        
        for device_row in self.devices:
            device_ip = device_row['hostname']
            device_type = device_row['type'].lower()
            
            driver_class = DRIVERS[device_type]
            driver = driver_class(device_ip, username, password, device_type)
            
            if not driver.connect():
                self.failed_devices.append({
                    'device_ip': device_ip,
                    'device_type': device_type,
                    'reason': 'Connection failed'
                })
                continue
            
            self.devices_scanned += 1
            
            # Collect ARP
            try:
                if device_type.startswith('cisco'):
                    # For Cisco: collect from global routing table AND all VRFs
                    vrfs_to_check = [None]  # None = global routing table
                    discovered_vrfs = driver.discover_vrfs()
                    if discovered_vrfs:
                        vrfs_to_check.extend(discovered_vrfs)
                    else:
                        logger.info(f"  No VRFs on {driver.hostname}, checking global routing table only")
                else:
                    # For non-Cisco (Palo Alto, etc.)
                    vrfs_to_check = [None]
                
                for vrf in vrfs_to_check:
                    arp_entries = driver.get_arp_table(vrf)
                    # Only log if we found entries, or if verbose mode
                    if len(arp_entries) > 0:
                        logger.info(f"  Collected {len(arp_entries)} ARP entries from {driver.hostname} (VRF: {vrf or 'global'})")
                    
                    for entry in arp_entries:
                        ip = entry['ip']
                        mac = entry['mac'].lower()  # Drivers already normalize to colon format
                        
                        if ip not in self.arp_data:
                            self.arp_data[ip] = []
                        
                        self.arp_data[ip].append({
                            'mac': mac,
                            'device_ip': device_ip,
                            'hostname': driver.hostname,
                            'interface': entry['interface'],
                            'vrf': entry.get('vrf', 'global'),
                            'device_type': device_type,
                            'is_local': entry.get('is_local', False),
                            'interface_type': entry.get('interface_type', 'data'),
                        })
                        
                        # Add to path tracer
                        self.path_tracer.add_arp_entry(
                            mac=mac,
                            ip=ip,
                            device=driver.hostname,
                            interface=entry['interface'],
                            device_type=device_type
                        )
            except Exception as e:
                logger.error(f"Error collecting ARP from {driver.hostname}: {e}")
                self.failed_devices.append({
                    'device_ip': device_ip,
                    'device_type': device_type,
                    'reason': f'ARP collection failed: {e}'
                })
            
            # Collect MAC table
            try:
                mac_entries = driver.get_mac_table()
                if len(mac_entries) > 0:
                    logger.info(f"  Collected {len(mac_entries)} MAC entries from {driver.hostname}")
                else:
                    logger.debug(f"  No MAC table entries from {driver.hostname} (normal for routers/firewalls)")
                
                for entry in mac_entries:
                    mac = entry['mac'].lower()
                    if mac not in self.mac_data:
                        self.mac_data[mac] = []
                    self.mac_data[mac].append({
                        'vlan': entry['vlan'],
                        'device_ip': device_ip,
                        'hostname': driver.hostname,
                        'interface': entry['interface'],
                        'port_type': entry['port_type'],
                        'device_type': device_type,  # Store device type
                    })
                    
                    # Add to path tracer
                    self.path_tracer.add_mac_entry(
                        mac=mac,
                        device=driver.hostname,
                        interface=entry['interface'],
                        vlan=entry['vlan'],
                        port_type=entry['port_type']
                    )
            except Exception as e:
                logger.warning(f"Error collecting MAC table from {driver.hostname}: {e}")
            
            driver.disconnect()
        
        self.end_time = datetime.now()

    def detect_duplicates(self) -> dict:
        """Detect MACs appearing on multiple trunk ports (potential issues)"""
        duplicates = {}
        
        for mac, entries in self.mac_data.items():
            # Get unique trunk port locations (device + interface combo)
            trunk_locations = {}
            for e in entries:
                if e['port_type'] == 'trunk':
                    key = f"{e['hostname']}:{e['interface']}"
                    trunk_locations[key] = e
            
            # Only flag if MAC appears on multiple different trunk ports
            if len(trunk_locations) > 1:
                duplicates[mac] = list(trunk_locations.values())
        
        if duplicates:
            logger.warning("=" * 50)
            logger.warning("DUPLICATE MAC DETECTION")
            logger.warning("=" * 50)
            for mac, entries in duplicates.items():
                logger.warning(f"DUPLICATE MAC {mac} found on {len(entries)} locations:")
                for e in entries:
                    logger.warning(f"  - {e['hostname']} ({e['port_type']}): {e['interface']} VLAN {e['vlan']}")
            logger.warning("=" * 50)
        
        return duplicates

    def generate_summary_report(self):
        """Generate summary report"""
        total_arp = sum(len(v) for v in self.arp_data.values())
        unique_ips = len(self.arp_data)
        unique_macs = len(self.mac_data)
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
        
        logger.info("=" * 50)
        logger.info("MAC/IP MERGE SUMMARY")
        logger.info("=" * 50)
        logger.info(f"Devices Scanned:     {self.devices_scanned}")
        logger.info(f"Devices Failed:      {len(self.failed_devices)}")
        logger.info(f"Total ARP Entries:   {total_arp}")
        logger.info(f"Unique IPs:          {unique_ips}")
        logger.info(f"Unique MACs:         {unique_macs}")
        logger.info(f"Collection Time:     {duration:.2f} seconds")
        
        if self.failed_devices:
            logger.warning("\nFailed Devices:")
            for device in self.failed_devices:
                logger.warning(f"  - {device['device_ip']} ({device['device_type']}): {device['reason']}")
        
        logger.info("=" * 50)

    def merge_and_export(self, output_file: str = None):
        """Merge ARP and MAC data with complete path tracking, export to CSV"""
        if not output_file:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"merged_{ts}.csv"
        # else: use the provided output_file as-is (don't add another timestamp)
        
        # Ensure output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        rows = []
        timestamp = datetime.now().isoformat()

        # Build a MAC -> local L3 ownership map from ARP data.
        # This powers "which IP is configured on which device/interface".
        l3_sources_by_mac = {}
        for ip, arp_entries in self.arp_data.items():
            for entry in arp_entries:
                if not entry.get('is_local'):
                    continue
                mac = entry['mac']
                if mac not in l3_sources_by_mac:
                    l3_sources_by_mac[mac] = []
                l3_sources_by_mac[mac].append({
                    'ip': ip,
                    'hostname': entry['hostname'],
                    'interface': entry['interface'],
                    'vrf': entry.get('vrf', 'global'),
                    'device_type': entry.get('device_type', ''),
                })

        def ip_sort_key(ip_addr: str):
            try:
                return (0, tuple(map(int, ip_addr.split('.'))))
            except Exception:
                return (1, ip_addr)
        
        # For each IP with ARP data
        for ip in sorted(self.arp_data.keys(), key=ip_sort_key):
            # Group ARP entries by MAC
            macs_for_ip = {}
            for arp_entry in self.arp_data[ip]:
                mac = arp_entry['mac']
                if mac not in macs_for_ip:
                    macs_for_ip[mac] = []
                macs_for_ip[mac].append(arp_entry)
            
            # For each MAC associated with this IP
            for mac, arp_sources in macs_for_ip.items():
                vrf_values = sorted(set(
                    s.get('vrf', 'global') for s in arp_sources if s.get('vrf')
                ))
                vrf_value = ','.join(vrf_values) if vrf_values else 'global'

                l3_sources = l3_sources_by_mac.get(mac, [])
                primary_l3 = l3_sources[0] if l3_sources else None
                l3_device = primary_l3['hostname'] if primary_l3 else ''
                l3_interface = primary_l3['interface'] if primary_l3 else ''
                l3_ip = primary_l3['ip'] if primary_l3 else ''
                l3_vrf = primary_l3['vrf'] if primary_l3 else ''
                
                # Get all switch ports that learned this MAC
                mac_entries = self.mac_data.get(mac, [])
                
                if mac_entries:
                    # We have switch MAC table entries - show the complete path
                    # Identify which ports are endpoints vs transit
                    mac_entries_with_role = self._identify_endpoint_ports(mac_entries)
                    
                    # Sort: Access ports first, then trunks, then routed
                    mac_entries_with_role.sort(key=lambda x: (
                        0 if x['port_type'] == 'access' else
                        1 if x['port_type'] == 'trunk' else
                        2 if x['port_type'] == 'routed' else 3
                    ))
                    
                    # Add row for each device/port where MAC was seen
                    for mac_entry in mac_entries_with_role:
                        vlan_value = mac_entry.get('vlan')
                        if not vlan_value:
                            vlan_value = 'unknown'

                        rows.append({
                            'ip': ip,
                            'mac': mac,
                            'vrf': vrf_value,
                            'vlan': vlan_value,
                            'device': mac_entry['hostname'],
                            'switchport': mac_entry['interface'],
                            'port_type': mac_entry['port_type'],
                            'path_role': mac_entry.get('role', ''),
                            'l3_device': l3_device,
                            'l3_interface': l3_interface,
                            'l3_ip': l3_ip,
                            'l3_vrf': l3_vrf,
                            'vendor': get_vendor(mac),
                            'device_type': mac_entry.get('device_type', 'switch'),
                            'is_endpoint': mac_entry.get('is_endpoint', False),
                            'timestamp': timestamp,
                        })
                
                # Add Layer 3 source (router/firewall where IP is configured)
                for arp_entry in arp_sources:
                    if arp_entry.get('is_local'):
                        # This device owns this IP - show as routed
                        rows.append({
                            'ip': ip,
                            'mac': mac,
                            'vrf': arp_entry.get('vrf', 'global'),
                            'vlan': 'N/A',
                            'device': arp_entry['hostname'],
                            'switchport': arp_entry['interface'],
                            'port_type': 'routed',
                            'path_role': 'l3_source',
                            'l3_device': arp_entry['hostname'],
                            'l3_interface': arp_entry['interface'],
                            'l3_ip': ip,
                            'l3_vrf': arp_entry.get('vrf', 'global'),
                            'vendor': get_vendor(mac),
                            'device_type': arp_entry['device_type'],
                            'is_endpoint': False,  # L3 source is not endpoint
                            'timestamp': timestamp,
                        })
                
                # If no MAC entries and no local source, still show ARP source
                # (MAC might be on firewall interface, not on switch)
                if not mac_entries:
                    non_local_sources = [s for s in arp_sources if not s.get('is_local')]
                    if non_local_sources:
                        # Show first non-local source
                        arp_entry = non_local_sources[0]
                        rows.append({
                            'ip': ip,
                            'mac': mac,
                            'vrf': arp_entry.get('vrf', 'global'),
                            'vlan': 'N/A',
                            'device': arp_entry['hostname'],
                            'switchport': arp_entry['interface'],
                            'port_type': 'routed',
                            'path_role': 'arp_only',
                            'l3_device': l3_device,
                            'l3_interface': l3_interface,
                            'l3_ip': l3_ip,
                            'l3_vrf': l3_vrf,
                            'vendor': get_vendor(mac),
                            'device_type': arp_entry['device_type'],
                            'is_endpoint': False,
                            'timestamp': timestamp,
                        })
        
        # Write CSV with new is_endpoint field
        try:
            with open(output_file, 'w', newline='') as f:
                fieldnames = [
                    'ip', 'mac', 'vrf', 'vlan', 'device', 'switchport', 'port_type',
                    'path_role', 'l3_device', 'l3_interface', 'l3_ip', 'l3_vrf',
                    'vendor', 'device_type', 'is_endpoint', 'timestamp'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"✓ Wrote {len(rows)} entries to {output_file}")
            
            # Log vendor lookup stats
            stats = _vendor_lookup.get_cache_stats()
            logger.info(f"  Vendor Lookup Stats: {stats['cache_size']} cached MACs, {stats['unique_vendors']} unique vendors")
            
            return output_file
        except Exception as e:
            logger.error(f"Failed to write CSV: {e}")
            return None
    
    def _identify_endpoint_ports(self, mac_entries: List[Dict]) -> List[Dict]:
        """
        Mark which ports are endpoints (access) vs transit (trunk)
        
        Args:
            mac_entries: List of MAC table entries for a single MAC
        
        Returns:
            Same list with 'is_endpoint' and 'role' fields added
        """
        # Group by device
        by_device = {}
        for entry in mac_entries:
            device = entry['hostname']
            if device not in by_device:
                by_device[device] = {'access': [], 'trunk': [], 'other': []}
            
            if entry['port_type'] == 'access':
                by_device[device]['access'].append(entry)
            elif entry['port_type'] == 'trunk':
                by_device[device]['trunk'].append(entry)
            else:
                by_device[device]['other'].append(entry)
        
        # Mark endpoints
        result = []
        for device, ports in by_device.items():
            # Access ports are endpoints
            for entry in ports['access']:
                entry['is_endpoint'] = True
                entry['role'] = 'endpoint'
                result.append(entry)
            
            # Trunk ports are transit
            for entry in ports['trunk']:
                entry['is_endpoint'] = False
                entry['role'] = 'transit'
                result.append(entry)
            
            # Other (routed, unknown)
            for entry in ports['other']:
                entry['is_endpoint'] = False
                entry['role'] = 'layer3' if entry['port_type'] == 'routed' else 'unknown'
                result.append(entry)
        
        return result


class VendorLookup:
    """Singleton vendor lookup with caching for performance"""
    _instance = None
    _mac_lookup = None
    _cache = {}
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize vendor lookup (only once)"""
        if VendorLookup._initialized:
            return
        
        VendorLookup._initialized = True
        
        try:
            from mac_vendor_lookup import MacLookup
            VendorLookup._mac_lookup = MacLookup()
            logger.info("✓ MAC vendor lookup initialized successfully")
            
            # Test with a known MAC
            test_mac = "00:50:56:00:00:01"  # VMware
            test_result = VendorLookup._mac_lookup.lookup(test_mac)
            logger.info(f"✓ Vendor lookup test: {test_mac} → {test_result}")
            
        except ImportError:
            logger.warning("⚠ mac-vendor-lookup module not installed")
            logger.warning("   Install with: pip install mac-vendor-lookup")
            VendorLookup._mac_lookup = None
        except Exception as e:
            logger.error(f"✗ Failed to initialize MAC vendor lookup: {e}")
            VendorLookup._mac_lookup = None
    
    def lookup(self, mac: str) -> str:
        """
        Lookup vendor with caching
        
        Args:
            mac: MAC address in any format (colon, dash, dot separated)
        
        Returns:
            Vendor name or 'UNKNOWN'
        """
        if not mac:
            return 'UNKNOWN'
        
        # Normalize MAC address format to colon-separated
        mac_clean = mac.lower().replace('-', ':').replace('.', '')
        if len(mac_clean) == 12:
            # No separators - add colons
            mac_normalized = ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
        else:
            mac_normalized = mac_clean
        
        # Check cache first
        if mac_normalized in VendorLookup._cache:
            return VendorLookup._cache[mac_normalized]
        
        # Lookup if module available
        if VendorLookup._mac_lookup:
            try:
                vendor = VendorLookup._mac_lookup.lookup(mac_normalized)
                VendorLookup._cache[mac_normalized] = vendor
                return vendor
            except Exception as e:
                # Log first few failures, then be quiet
                if len(VendorLookup._cache) < 5:
                    logger.debug(f"Vendor lookup failed for {mac_normalized}: {e}")
                VendorLookup._cache[mac_normalized] = 'UNKNOWN'
                return 'UNKNOWN'
        
        return 'UNKNOWN'
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics"""
        return {
            'cache_size': len(VendorLookup._cache),
            'unique_vendors': len(set(VendorLookup._cache.values())),
            'lookup_available': VendorLookup._mac_lookup is not None,
        }


# Global singleton instance
_vendor_lookup = VendorLookup()


def get_vendor(mac: str) -> str:
    """
    Lookup MAC vendor using cached singleton
    
    This is the function called throughout the codebase.
    """
    return _vendor_lookup.lookup(mac)


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    logger.info("\nInterrupted - cleaning up...")
    sys.exit(0)


def main():
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='MAC/IP Merge Tool - Collect ARP and MAC tables from network devices',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--input', '-i', 
                       default='devices.csv',
                       help='Input CSV file (default: devices.csv)')
    parser.add_argument('--output', '-o',
                       help='Output CSV file (default: merged_YYYYMMDD_HHMMSS.csv)')
    parser.add_argument('--check-only',
                       action='store_true',
                       help='Pre-flight connectivity check only, no data collection')
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Verbose output (debug logging)')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        # Enable DEBUG for our application modules only
        for logger_name in ['__main__', 'cisco_driver', 'paloalto_driver', 'mac_ip_merge']:
            logging.getLogger(logger_name).setLevel(logging.DEBUG)
    
    # Validate input file exists
    if not Path(args.input).exists():
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)
    
    # Get credentials
    import os
    username = os.environ.get("DEVICE_USER") or input("Username: ")
    password = os.environ.get("DEVICE_PASS") or getpass.getpass("Password: ")
    
    # Initialize tool
    merge = MACIPMerge()
    if not merge.load_devices(args.input):
        sys.exit(1)
    
    # Pre-flight check mode
    if args.check_only:
        success = merge.preflight_check(username, password)
        sys.exit(0 if success else 1)
    
    # Full data collection
    logger.info("Starting data collection...")
    merge.collect_data(username, password)
    
    # Detect duplicates
    merge.detect_duplicates()
    
    # Generate summary
    merge.generate_summary_report()
    
    # Merge and export
    logger.info("Merging and exporting...")
    output = merge.merge_and_export(args.output)
    
    if output:
        # Generate MAC path tracing reports with matching timestamp
        output_dir = Path(output).parent
        output_name = Path(output).stem  # e.g., "merged_20260215_193810"
        
        # Extract timestamp from filename if present
        import re
        ts_match = re.search(r'(\d{8}_\d{6})$', output_name)
        timestamp = ts_match.group(1) if ts_match else datetime.now().strftime("%Y%m%d_%H%M%S")
        
        logger.info("Generating MAC path reports...")
        path_report = merge.path_tracer.generate_path_report(
            str(output_dir / f"mac_paths_{timestamp}.txt"),
            timestamp=timestamp
        )
        path_csv = merge.path_tracer.generate_path_csv(
            str(output_dir / f"mac_paths_{timestamp}.csv"),
            timestamp=timestamp
        )
        topology = merge.path_tracer.generate_topology_diagram(
            str(output_dir / f"mac_topology_{timestamp}.txt"),
            timestamp=timestamp
        )
        
        logger.info(f"✓ Complete. Output files:")
        logger.info(f"  - Main CSV: {output}")
        logger.info(f"  - MAC Paths (readable): {path_report}")
        logger.info(f"  - MAC Paths (CSV): {path_csv}")
        logger.info(f"  - Topology Diagram: {topology}")
        sys.exit(0)
    else:
        logger.error("Failed to generate output file")
        sys.exit(1)


if __name__ == '__main__':
    main()
