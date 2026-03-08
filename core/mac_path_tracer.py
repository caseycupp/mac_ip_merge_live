#!/usr/bin/env python3
"""
MAC Path Tracer - Shows the complete L2 path for each MAC address
"""

import csv
from collections import defaultdict
from typing import Dict, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class MACPathTracer:
    """Trace MAC addresses through the network topology"""
    
    def __init__(self):
        self.mac_paths = defaultdict(lambda: {
            'arp_sources': [],  # Devices that have this MAC in ARP (L3)
            'switch_ports': []   # Switches that learned this MAC (L2)
        })
    
    def add_arp_entry(self, mac: str, ip: str, device: str, interface: str, device_type: str):
        """Add an ARP entry (L3 endpoint)"""
        self.mac_paths[mac]['arp_sources'].append({
            'ip': ip,
            'device': device,
            'interface': interface,
            'device_type': device_type
        })
    
    def add_mac_entry(self, mac: str, device: str, interface: str, vlan: str, port_type: str):
        """Add a MAC table entry (L2 forwarding)"""
        self.mac_paths[mac]['switch_ports'].append({
            'device': device,
            'interface': interface,
            'vlan': vlan,
            'port_type': port_type
        })
    
    def generate_path_report(self, output_file: str = None, timestamp: str = None):
        """Generate human-readable MAC path report"""
        
        if not output_file:
            ts = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mac_paths_{ts}.txt"
        
        lines = []
        lines.append("=" * 80)
        lines.append("MAC ADDRESS PATH TRACING REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Sort MACs for consistent output
        for mac in sorted(self.mac_paths.keys()):
            path_data = self.mac_paths[mac]
            
            lines.append(f"MAC: {mac}")
            lines.append("-" * 80)
            
            # Show L3 endpoints (where this MAC has an IP)
            if path_data['arp_sources']:
                lines.append("  L3 Endpoints (IP Addresses):")
                for arp in path_data['arp_sources']:
                    lines.append(f"    • {arp['ip']:15s} on {arp['device']:15s} ({arp['interface']})")
            
            # Show L2 path (devices that learned this MAC)
            if path_data['switch_ports']:
                lines.append("  L2 Path (Device Ports):")
                
                # Group by device for cleaner output
                by_device = defaultdict(list)
                for entry in path_data['switch_ports']:
                    by_device[entry['device']].append(entry)
                
                # Sort devices and show their ports
                for device in sorted(by_device.keys()):
                    for entry in by_device[device]:
                        port_info = f"{entry['interface']:20s} [{entry['port_type']:6s}]"
                        if entry['vlan']:
                            port_info += f" VLAN {entry['vlan']}"
                        lines.append(f"    • {device:15s} → {port_info}")
            
            lines.append("")
        
        # Write to file
        report_text = "\n".join(lines)
        with open(output_file, 'w') as f:
            f.write(report_text)
        
        logger.info(f"✓ MAC path report written to {output_file}")
        return output_file
    
    def generate_path_csv(self, output_file: str = None, timestamp: str = None):
        """Generate CSV with MAC path information"""
        
        if not output_file:
            ts = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mac_paths_{ts}.csv"
        
        rows = []
        
        for mac in sorted(self.mac_paths.keys()):
            path_data = self.mac_paths[mac]
            
            # Get all IPs for this MAC
            ips = ', '.join([arp['ip'] for arp in path_data['arp_sources']])
            
            # Get ARP source devices
            arp_devices = ', '.join(sorted(set([arp['device'] for arp in path_data['arp_sources']])))
            
            # Get all device ports (sorted by device name for consistency)
            device_paths = []
            for entry in sorted(path_data['switch_ports'], key=lambda x: x['device']):
                device_paths.append(f"{entry['device']}:{entry['interface']}({entry['port_type']})")
            
            rows.append({
                'mac': mac,
                'ip_addresses': ips,
                'arp_source_devices': arp_devices,
                'device_count': len(set([e['device'] for e in path_data['switch_ports']])),
                'l2_path': ' → '.join(device_paths),
            })
        
        # Write CSV
        with open(output_file, 'w', newline='') as f:
            fieldnames = ['mac', 'ip_addresses', 'arp_source_devices', 'device_count', 'l2_path']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        logger.info(f"✓ MAC path CSV written to {output_file}")
        return output_file
    
    def generate_topology_diagram(self, output_file: str = None, timestamp: str = None):
        """Generate ASCII topology diagram showing MAC paths"""
        
        if not output_file:
            ts = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"mac_topology_{ts}.txt"
        
        lines = []
        lines.append("=" * 80)
        lines.append("NETWORK TOPOLOGY - MAC FORWARDING PATHS")
        lines.append("=" * 80)
        lines.append("")
        
        # Build device hierarchy (access → distribution → core → router)
        device_roles = self._classify_devices()
        
        for mac in sorted(self.mac_paths.keys()):
            path_data = self.mac_paths[mac]
            
            if not path_data['switch_ports']:
                continue
            
            lines.append(f"MAC: {mac}")
            
            # Get IPs if available
            if path_data['arp_sources']:
                ips = ', '.join([arp['ip'] for arp in path_data['arp_sources']])
                lines.append(f"IPs: {ips}")
            
            # Build path diagram
            lines.append("")
            
            # Group by port type to show access → trunk flow
            access_ports = [e for e in path_data['switch_ports'] if e['port_type'] == 'access']
            trunk_ports = [e for e in path_data['switch_ports'] if e['port_type'] == 'trunk']
            
            if access_ports:
                lines.append("  [Access Port(s)]")
                for entry in access_ports:
                    lines.append(f"    ↓ {entry['device']} {entry['interface']}")
            
            if trunk_ports:
                lines.append("      ↓")
                lines.append("  [Trunk Path]")
                for entry in trunk_ports:
                    vlan_info = f"VLAN {entry['vlan']}" if entry['vlan'] else ""
                    lines.append(f"    ↓ {entry['device']} {entry['interface']} {vlan_info}")
            
            if path_data['arp_sources']:
                lines.append("      ↓")
                lines.append("  [L3 Gateway]")
                for arp in path_data['arp_sources']:
                    lines.append(f"    → {arp['device']} {arp['interface']} ({arp['ip']})")
            
            lines.append("")
            lines.append("-" * 80)
            lines.append("")
        
        # Write to file
        report_text = "\n".join(lines)
        with open(output_file, 'w') as f:
            f.write(report_text)
        
        logger.info(f"✓ Topology diagram written to {output_file}")
        return output_file
    
    def _classify_devices(self) -> Dict:
        """Classify devices by role (access, distribution, core, router)"""
        # This is a simplified classification - could be enhanced
        roles = defaultdict(str)
        
        for mac, data in self.mac_paths.items():
            for entry in data['switch_ports']:
                device = entry['device']
                if entry['port_type'] == 'access' and not roles[device]:
                    roles[device] = 'access'
                elif entry['port_type'] == 'trunk':
                    if roles[device] != 'access':
                        roles[device] = 'distribution'
            
            for arp in data['arp_sources']:
                device = arp['device']
                if arp['device_type'].startswith('cisco'):
                    roles[device] = 'router'
                elif 'palo' in arp['device_type']:
                    roles[device] = 'firewall'
        
        return roles
