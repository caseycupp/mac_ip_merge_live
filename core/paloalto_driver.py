"""Palo Alto driver"""
from device_driver import DeviceDriver
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from typing import List, Dict
import logging
import re

logger = logging.getLogger(__name__)


class PaloAltoDriver(DeviceDriver):
    def __init__(self, device_ip: str, username: str, password: str, device_type: str = "paloalto_panos"):
        super().__init__(device_ip, username, password, device_type)
        self.conn = None
        self.local_ips = {}  # Store IPs assigned to this firewall's interfaces
        logger.debug(f"[PaloAltoDriver] Initialized for {device_ip}")

    def connect(self) -> bool:
        try:
            logger.debug(f"[PaloAltoDriver.connect] Connecting to {self.device_ip}")
            self.conn = ConnectHandler(
                host=self.device_ip,
                username=self.username,
                password=self.password,
                device_type=self.device_type,
                timeout=15,
            )
            
            # Try to get hostname
            try:
                output = self.conn.send_command("show system info | match hostname")
                match = re.search(r'hostname:\s+(\S+)', output)
                self.hostname = match.group(1) if match else self.device_ip
            except:
                self.hostname = self.device_ip
            
            self.is_connected = True
            
            # Get local IP addresses for Layer 3 detection (non-critical)
            try:
                self.local_ips = self._get_local_ips()
            except Exception as e:
                logger.warning(f"[{self.hostname}] Could not get local IPs: {e}")
                self.local_ips = {}
            
            logger.info(f"✓ {self.hostname} (Palo Alto)")
            return True
        except NetmikoAuthenticationException as e:
            logger.error(f"[PaloAltoDriver.connect] Auth failed {self.device_ip}: {e}")
            return False
        except NetmikoTimeoutException as e:
            logger.error(f"[PaloAltoDriver.connect] Timeout {self.device_ip}: {e}")
            return False
        except Exception as e:
            logger.error(f"[PaloAltoDriver.connect] Unexpected error {self.device_ip}: {type(e).__name__}: {e}")
            return False

    def disconnect(self):
        try:
            if self.conn:
                self.conn.disconnect()
                logger.debug(f"[PaloAltoDriver.disconnect] Closed connection to {self.device_ip}")
        except Exception as e:
            logger.warning(f"[PaloAltoDriver.disconnect] Error disconnecting {self.device_ip}: {e}")

    def discover_vrfs(self) -> List[str]:
        logger.debug(f"[PaloAltoDriver.discover_vrfs] Palo Alto has no VRFs, returning empty")
        return []

    def _get_local_ips(self) -> Dict[str, str]:
        """
        Get all IP addresses assigned to this firewall's interfaces
        Uses both 'show interface all' and 'show interface management'
        Returns: {interface: ip_address}
        """
        local_ips = {}
        
        if not self.is_connected:
            return local_ips
        
        try:
            # Get data interfaces
            output = self.conn.send_command("show interface all")
            local_ips.update(self._parse_interface_all_ips(output))
            
            # Get management interface
            output = self.conn.send_command("show interface management")
            mgmt_ip = self._parse_management_ip(output)
            if mgmt_ip:
                local_ips['management'] = mgmt_ip
            
            if local_ips:
                logger.info(f"  [{self.hostname}] Found {len(local_ips)} local IP addresses")
            return local_ips
            
        except Exception as e:
            logger.warning(f"[{self.hostname}] Failed to get local IPs: {e}")
            return {}
    
    def _parse_interface_all_ips(self, output: str) -> Dict[str, str]:
        """Parse IPs from 'show interface all' output"""
        ips = {}
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('Interface:'):
                current_interface = line.split('Interface:')[1].strip()
            
            elif current_interface and 'IP address:' in line:
                ip_part = line.split('IP address:')[1].strip()
                # Check if it's a valid IP (not "unknown" or "(layer2)")
                if ip_part and ip_part != 'unknown' and '(layer2)' not in ip_part and 'N/A' not in ip_part:
                    # Remove subnet if present (e.g., "10.1.1.1/24" -> "10.1.1.1")
                    ip = ip_part.split('/')[0]
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        ips[current_interface] = ip
                        logger.debug(f"[{self.hostname}] Local IP: {current_interface} = {ip}")
        
        return ips
    
    def _parse_management_ip(self, output: str) -> str:
        """Parse IP from 'show interface management' output"""
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('IP'):
                # IP      : 10.100.1.50
                ip = line.split(':', 1)[1].strip()
                if ip and ip != 'unknown' and ip != '0.0.0.0':
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        logger.debug(f"[{self.hostname}] Management IP: {ip}")
                        return ip
        return None

    def get_arp_table(self, vrf: str = None) -> List[Dict]:
        """
        Get complete interface information from Palo Alto
        Uses 'show interface all' and 'show interface management'
        Returns ARP-compatible entries for all interfaces
        """
        if not self.is_connected:
            logger.warning(f"[PaloAltoDriver.get_arp_table] Not connected to {self.device_ip}")
            return []
        
        entries = []
        
        try:
            # 1. Parse data interfaces (show interface all)
            logger.debug(f"[{self.hostname}] Running show interface all")
            output = self.conn.send_command("show interface all")
            data_entries = self._parse_show_interface_all(output)
            entries.extend(data_entries)
            logger.info(f"  [{self.hostname}] Found {len(data_entries)} data interfaces")
            
            # 2. Parse management interface (show interface management)
            logger.debug(f"[{self.hostname}] Running show interface management")
            output = self.conn.send_command("show interface management")
            mgmt_entry = self._parse_show_interface_management(output)
            if mgmt_entry:
                entries.append(mgmt_entry)
                logger.info(f"  [{self.hostname}] Found management interface: {mgmt_entry.get('ip')}")
            
            logger.info(f"  [{self.hostname}] Total interfaces: {len(entries)}")
            return entries
            
        except Exception as e:
            logger.error(f"[{self.hostname}] ERROR getting interfaces: {type(e).__name__}: {e}", exc_info=True)
            return []
    
    def _parse_show_interface_all(self, output: str) -> List[Dict]:
        """Parse 'show interface all' output"""
        entries = []
        current_interface = None
        current_data = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            # New interface section
            if line.startswith('Interface:'):
                # Save previous interface
                if current_interface and current_data:
                    entry = self._process_interface_data(current_data)
                    if entry:
                        entries.append(entry)
                
                # Start new interface
                current_interface = line.split('Interface:')[1].strip()
                current_data = {'interface': current_interface}
            
            # Parse interface properties
            elif current_interface:
                if 'MAC address:' in line:
                    mac = line.split('MAC address:')[1].strip()
                    # Normalize MAC to colon notation
                    if mac and mac != 'N/A' and mac != 'unknown':
                        current_data['mac'] = self._normalize_mac(mac)
                
                elif 'IP address:' in line:
                    ip_part = line.split('IP address:')[1].strip()
                    if ip_part and ip_part != 'unknown' and '(layer2)' not in ip_part and 'N/A' not in ip_part:
                        # Parse IP/subnet (e.g., "10.1.1.1/24")
                        ip = ip_part.split('/')[0]
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            current_data['ip'] = ip
                
                elif 'State:' in line or 'Link status:' in line:
                    status = line.split(':')[1].strip()
                    current_data['state'] = status
        
        # Don't forget last interface
        if current_interface and current_data:
            entry = self._process_interface_data(current_data)
            if entry:
                entries.append(entry)
        
        return entries
    
    def _parse_show_interface_management(self, output: str) -> Dict:
        """Parse 'show interface management' output"""
        data = {'interface': 'management'}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('IP'):
                ip = line.split(':', 1)[1].strip()
                if ip and ip != 'unknown' and ip != '0.0.0.0':
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        data['ip'] = ip
            
            elif line.startswith('MAC Address'):
                mac = line.split(':', 1)[1].strip()
                if mac and mac != 'N/A' and mac != 'unknown':
                    data['mac'] = self._normalize_mac(mac)
            
            elif line.startswith('Link status'):
                status = line.split(':', 1)[1].strip()
                data['state'] = status
        
        return self._process_interface_data(data)
    
    def _process_interface_data(self, data: Dict) -> Dict:
        """Process parsed interface data into ARP entry format"""
        interface = data.get('interface')
        ip = data.get('ip')
        mac = data.get('mac')
        
        # Only return if we have IP and MAC (Layer 3 interface)
        if not ip or not mac:
            return None
        
        # Check if this IP is local to this firewall
        is_local = interface in self.local_ips and self.local_ips[interface] == ip
        
        return {
            'ip': ip,
            'mac': mac,
            'interface': interface,
            'vrf': 'global',
            'is_local': is_local,
            'interface_type': 'management' if interface == 'management' else 'data',
        }
    
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address to colon notation"""
        # Remove common separators
        mac_clean = mac.lower().replace(':', '').replace('-', '').replace('.', '')
        # Add colons every 2 characters
        if len(mac_clean) == 12:
            return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
        return mac

    def get_mac_table(self) -> List[Dict]:
        logger.debug(f"[PaloAltoDriver.get_mac_table] Palo Alto has no MAC table, returning empty")
        return []
