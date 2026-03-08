"""Cisco IOS/IOS-XE driver with Genie parsers"""
from device_driver import DeviceDriver
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from typing import List, Dict
import logging
import re

logger = logging.getLogger(__name__)

# Control plane interfaces to filter out from MAC table
CONTROL_PLANE_INTERFACES = {'CPU', 'ROUTER', 'SWITCH', 'SYSTEM', 'SUPERVISOR', 'NULL0'}


class CiscoIOSDriver(DeviceDriver):
    def __init__(self, device_ip: str, username: str, password: str, device_type: str = "cisco_ios"):
        super().__init__(device_ip, username, password, device_type)
        self.conn = None
        self.use_genie = True  # Try Genie first, fallback to manual parsing
        self.local_ips = {}  # Store IPs assigned to this device's interfaces
    
    def _normalize_interface_name(self, interface: str) -> str:
        """Normalize interface name to short form for comparison"""
        # Convert long form to short form for consistent comparison
        # GigabitEthernet0/1/0 -> Gi0/1/0
        # TenGigabitEthernet1/0/1 -> Te1/0/1
        # etc.
        replacements = {
            'GigabitEthernet': 'Gi',
            'FastEthernet': 'Fa',
            'TenGigabitEthernet': 'Te',
            'TwentyFiveGigE': 'Tw',
            'TwentyFiveGigabitEthernet': 'Tw',
            'FortyGigabitEthernet': 'Fo',
            'HundredGigE': 'Hu',
            'HundredGigabitEthernet': 'Hu',
            'AppGigabitEthernet': 'Ap',
            'Ethernet': 'Eth',
            'Port-channel': 'Po',
            'Loopback': 'Lo',
            'Vlan': 'Vl',
            'Tunnel': 'Tu',
        }
        
        normalized = interface
        for long_form, short_form in replacements.items():
            if normalized.startswith(long_form):
                normalized = short_form + normalized[len(long_form):]
                break
        
        return normalized

    def connect(self) -> bool:
        try:
            self.conn = ConnectHandler(
                host=self.device_ip,
                username=self.username,
                password=self.password,
                device_type=self.device_type,
                timeout=15,
            )
            output = self.conn.send_command("show run | include ^hostname")
            match = re.search(r'hostname\s+(\S+)', output)
            self.hostname = match.group(1) if match else self.device_ip
            self.is_connected = True
            
            # Get local IP addresses for Layer 3 detection (non-critical)
            try:
                self.local_ips = self._get_local_ips()
            except Exception as e:
                logger.warning(f"[{self.hostname}] Could not get local IPs: {e}")
                self.local_ips = {}
            
            logger.info(f"✓ {self.hostname}")
            return True
        except NetmikoAuthenticationException as e:
            logger.error(f"✗ {self.device_ip}: Authentication failed - {e}")
            return False
        except NetmikoTimeoutException as e:
            logger.error(f"✗ {self.device_ip}: Timeout - {e}")
            return False
        except Exception as e:
            logger.error(f"✗ {self.device_ip}: {e}")
            return False

    def disconnect(self):
        if self.conn:
            try:
                self.conn.disconnect()
            except Exception as e:
                logger.warning(f"Error disconnecting from {self.device_ip}: {e}")

    def _get_local_ips(self) -> Dict[str, str]:
        """
        Get all IP addresses assigned to this device's interfaces
        Returns: {interface: ip_address}
        """
        local_ips = {}
        
        if not self.is_connected:
            return local_ips
        
        try:
            output = self.conn.send_command("show ip interface brief")
            
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                interface = parts[0]
                ip_address = parts[1]
                
                # Skip header lines and invalid IPs
                if interface.lower() in ['interface', 'vlan', 'port'] or \
                   ip_address.lower() in ['address', 'unassigned', 'yes', 'no', 'up', 'down']:
                    continue
                
                # Validate IP format
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
                    local_ips[interface] = ip_address
                    logger.debug(f"[{self.hostname}] Local IP: {interface} = {ip_address}")
            
            if local_ips:
                logger.info(f"  [{self.hostname}] Found {len(local_ips)} local IP addresses")
            return local_ips
            
        except Exception as e:
            logger.warning(f"[{self.hostname}] Failed to get local IPs: {e}")
            return {}

    def discover_vrfs(self) -> List[str]:
        """Discover VRFs using Genie parser if available, fallback to manual parsing"""
        if not self.is_connected:
            logger.warning(f"Not connected to {self.device_ip}, cannot discover VRFs")
            return []
        
        # Try Genie parser first
        if self.use_genie:
            try:
                parsed = self.conn.send_command("show vrf", use_genie=True)
                
                if parsed and 'vrf' in parsed:
                    vrfs = list(parsed['vrf'].keys())
                    logger.info(f"  Discovered {len(vrfs)} VRFs on {self.hostname}: {', '.join(vrfs)}")
                    return vrfs
                else:
                    logger.info(f"  No VRFs found on {self.hostname}, will query global ARP table only")
                    return []
            except ImportError:
                logger.debug(f"Genie not available, using manual VRF parsing")
                self.use_genie = False
            except Exception as e:
                logger.debug(f"Genie VRF parsing failed on {self.hostname}, trying manual: {e}")
        
        # Fallback to manual parsing
        try:
            output = self.conn.send_command("show vrf")
            vrfs = []
            
            # Parse output - skip header lines
            lines = output.split('\n')
            for line in lines:
                # Skip header and separator lines
                if 'Name' in line or 'Default RD' in line or '---' in line or not line.strip():
                    continue
                
                parts = line.split()
                if parts:
                    vrf_name = parts[0]
                    # Filter out anything that looks like a VLAN number (pure digits)
                    if not vrf_name.isdigit():
                        vrfs.append(vrf_name)
            
            if vrfs:
                logger.info(f"  Discovered {len(vrfs)} VRFs on {self.hostname}: {', '.join(vrfs)}")
            else:
                logger.info(f"  No VRFs found on {self.hostname}, will query global ARP table only")
            
            return vrfs
        except Exception as e:
            logger.warning(f"VRF discovery failed on {self.hostname}: {e}")
            return []

    def get_arp_table(self, vrf: str = None) -> List[Dict]:
        """Get ARP table using Genie parser if available, fallback to manual parsing"""
        if not self.is_connected:
            return []
        
        cmd = f"show ip arp vrf {vrf}" if vrf else "show ip arp"
        
        # Try Genie parser first
        if self.use_genie:
            try:
                parsed = self.conn.send_command(cmd, use_genie=True)
                entries = []
                
                if parsed and 'interfaces' in parsed:
                    for interface, intf_data in parsed['interfaces'].items():
                        if 'ipv4' in intf_data and 'neighbors' in intf_data['ipv4']:
                            for ip, neighbor_data in intf_data['ipv4']['neighbors'].items():
                                mac = neighbor_data.get('link_layer_address', '').lower()
                                if mac:
                                    # Normalize MAC to colon notation if in dot notation
                                    if '.' in mac and ':' not in mac:
                                        mac_no_dots = mac.replace('.', '')
                                        mac = ':'.join([mac_no_dots[i:i+2] for i in range(0, len(mac_no_dots), 2)])
                                    
                                    # Check if this IP is local to this device
                                    is_local = interface in self.local_ips and self.local_ips[interface] == ip
                                    
                                    entries.append({
                                        "ip": ip,
                                        "mac": mac,
                                        "interface": interface,
                                        "vrf": vrf or "global",
                                        "is_local": is_local,
                                    })
                
                logger.debug(f"Genie parsed {len(entries)} ARP entries from {self.hostname} (VRF: {vrf or 'global'})")
                return entries
            except ImportError:
                logger.debug(f"Genie not available, using manual ARP parsing")
                self.use_genie = False
            except Exception as e:
                logger.debug(f"Genie ARP parsing failed on {self.hostname}, trying manual: {e}")
        
        # Fallback to manual parsing
        try:
            output = self.conn.send_command(cmd)
            entries = []
            
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) < 5 or parts[0] != 'Internet':
                    continue
                # Validate IP (X.X.X.X) - must have exactly 3 dots
                if parts[1].count('.') != 3:
                    continue
                # MAC must be in Cisco dot notation or colon notation
                if '.' not in parts[3] and ':' not in parts[3]:
                    continue
                
                # Convert MAC from dot notation (906c.acbb.3580) to colon (90:6c:ac:bb:35:80)
                mac = parts[3]
                if '.' in mac and ':' not in mac:
                    # Remove dots first, then convert
                    mac_no_dots = mac.replace('.', '')
                    mac = ':'.join([mac_no_dots[i:i+2] for i in range(0, len(mac_no_dots), 2)])
                
                ip = parts[1]
                interface = parts[5] if len(parts) > 5 else ""
                
                # Check if this IP is local to this device
                is_local = interface in self.local_ips and self.local_ips[interface] == ip
                
                entries.append({
                    "ip": ip,
                    "mac": mac.lower(),
                    "interface": interface,
                    "vrf": vrf or "global",
                    "is_local": is_local,
                })
            
            logger.debug(f"Manual parsed {len(entries)} ARP entries from {self.hostname} (VRF: {vrf or 'global'})")
            return entries
        except (ValueError, IndexError, KeyError) as e:
            logger.error(f"ARP parsing error on {self.hostname}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting ARP table from {self.hostname}: {e}")
            return []

    def get_mac_table(self) -> List[Dict]:
        """Get MAC address table using Genie parser if available, fallback to manual parsing"""
        if not self.is_connected:
            return []
        
        # Get trunk and routed interfaces for port_type detection
        trunk_interfaces = self._get_trunk_interfaces()
        routed_interfaces = self._get_routed_interfaces()
        
        # Try Genie parser first
        if self.use_genie:
            try:
                parsed = self.conn.send_command("show mac address-table", use_genie=True)
                entries = []
                
                if parsed and 'mac_table' in parsed:
                    for vlan, vlan_data in parsed['mac_table'].get('vlans', {}).items():
                        for mac, mac_data in vlan_data.get('mac_addresses', {}).items():
                            # Normalize MAC to colon notation
                            mac_normalized = mac.lower().replace('.', '')
                            mac_colon = ':'.join([mac_normalized[i:i+2] for i in range(0, len(mac_normalized), 2)])
                            
                            interfaces = mac_data.get('interfaces', {})
                            for interface, intf_data in interfaces.items():
                                # Filter out control plane interfaces
                                if interface.upper() in CONTROL_PLANE_INTERFACES:
                                    logger.debug(f"[{self.hostname}] Skipping control plane: {interface}")
                                    continue
                                
                                # Normalize interface name for comparison
                                normalized_intf = self._normalize_interface_name(interface)
                                
                                # Determine port type
                                if normalized_intf in routed_interfaces:
                                    port_type = "routed"
                                elif normalized_intf in trunk_interfaces:
                                    port_type = "trunk"
                                else:
                                    port_type = "access"
                                
                                entries.append({
                                    "mac": mac_colon,
                                    "vlan": str(vlan),
                                    "interface": interface,
                                    "port_type": port_type,
                                })
                
                logger.debug(f"Genie parsed {len(entries)} MAC entries from {self.hostname}")
                return entries
            except ImportError:
                logger.debug(f"Genie not available, using manual MAC parsing")
                self.use_genie = False
            except Exception as e:
                logger.debug(f"Genie MAC parsing failed on {self.hostname}, trying manual: {e}")
        
        # Fallback to manual parsing
        try:
            output = self.conn.send_command("show mac address-table")
            entries = []
            
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) < 4 or 'Vlan' in line or '---' in line:
                    continue
                if '.' not in parts[1]:
                    continue
                
                # Convert MAC to colon notation
                mac_no_dots = parts[1].replace('.', '')
                mac = ':'.join([mac_no_dots[i:i+2] for i in range(0, len(mac_no_dots), 2)])
                
                # Get interface
                interface = parts[3]
                
                # Filter out control plane interfaces
                if interface.upper() in CONTROL_PLANE_INTERFACES:
                    logger.debug(f"[{self.hostname}] Skipping control plane: {interface}")
                    continue
                
                # Normalize interface name for comparison
                normalized_intf = self._normalize_interface_name(interface)
                
                # Determine port type
                if normalized_intf in routed_interfaces:
                    port_type = "routed"
                elif normalized_intf in trunk_interfaces:
                    port_type = "trunk"
                else:
                    port_type = "access"
                
                entries.append({
                    "mac": mac.lower(),
                    "vlan": parts[0],
                    "interface": interface,
                    "port_type": port_type,
                })
            
            logger.debug(f"Manual parsed {len(entries)} MAC entries from {self.hostname}")
            return entries
        except (ValueError, IndexError, KeyError) as e:
            logger.error(f"MAC table parsing error on {self.hostname}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting MAC table from {self.hostname}: {e}")
            return []
    
    def _get_trunk_interfaces(self) -> set:
        """Get list of trunk interfaces on the device"""
        trunk_intfs = set()
        try:
            output = self.conn.send_command("show interfaces trunk")
            logger.debug(f"[{self.hostname}] show interfaces trunk output length: {len(output)} chars")
            
            # Parse trunk interface list
            in_section = False
            for line in output.split('\n'):
                # Look for the Port line that starts the trunk list
                if 'Port' in line and ('Mode' in line or 'Status' in line or 'Encapsulation' in line):
                    in_section = True
                    logger.debug(f"[{self.hostname}] Found trunk section header: {line.strip()}")
                    continue
                
                if in_section and line.strip():
                    # Stop if we hit the next section
                    if 'Vlans allowed' in line or 'Vlans in spanning' in line:
                        break
                    
                    parts = line.split()
                    if parts and not parts[0].startswith('-') and parts[0] not in ['Port', 'Vlans']:
                        # Filter to only actual interface names (start with Gi, Fa, Te, Eth, Po, Ap)
                        if any(parts[0].startswith(prefix) for prefix in ['Gi', 'Fa', 'Te', 'Eth', 'Po', 'Tw', 'Fo', 'Hu', 'Ap']):
                            trunk_intfs.add(parts[0])
                            logger.debug(f"[{self.hostname}] Added trunk interface: {parts[0]}")
            
            if trunk_intfs:
                logger.info(f"  Found {len(trunk_intfs)} trunk interfaces on {self.hostname}: {', '.join(sorted(trunk_intfs))}")
            else:
                logger.debug(f"[{self.hostname}] No trunk interfaces found")
            return trunk_intfs
        except Exception as e:
            logger.warning(f"Could not determine trunk interfaces on {self.hostname}: {e}")
            return set()
    
    def _get_routed_interfaces(self) -> set:
        """Get list of routed (L3) interfaces - those with 'Switchport: Disabled'"""
        routed_intfs = set()
        try:
            # Get all interfaces
            output = self.conn.send_command("show ip interface brief")
            potential_intfs = []
            
            for line in output.split('\n'):
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                # Skip header
                if 'Interface' in line:
                    continue
                
                interface = parts[0]
                # Check physical/logical interfaces (not Vlan interfaces - those are SVIs)
                if any(interface.startswith(prefix) for prefix in ['Gi', 'Fa', 'Te', 'Eth', 'Po', 'Tw', 'Fo', 'Hu', 'Ap']):
                    # Only check main interface (Gi0/2), not subinterfaces (Gi0/2.100)
                    if '.' not in interface:
                        potential_intfs.append(interface)
            
            # Now check each interface to see if switchport is disabled
            for intf in potential_intfs[:15]:  # Limit to first 15 to avoid slowdown
                try:
                    sw_output = self.conn.send_command(f"show interfaces {intf} switchport", expect_string=r'#')
                    if 'Switchport: Disabled' in sw_output:
                        routed_intfs.add(intf)
                        logger.debug(f"[{self.hostname}] Found routed interface: {intf}")
                except:
                    pass
            
            if routed_intfs:
                logger.info(f"  Found {len(routed_intfs)} routed (L3) interfaces on {self.hostname}: {', '.join(sorted(routed_intfs))}")
            return routed_intfs
        except Exception as e:
            logger.debug(f"Could not determine routed interfaces on {self.hostname}: {e}")
            return set()
