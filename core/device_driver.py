"""Base device driver"""
from abc import ABC, abstractmethod
from typing import List, Dict


class DeviceDriver(ABC):
    def __init__(self, device_ip: str, username: str, password: str, device_type: str):
        self.device_ip = device_ip
        self.username = username
        self.password = password
        self.device_type = device_type
        self.hostname = device_ip
        self.is_connected = False

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self):
        pass

    @abstractmethod
    def get_arp_table(self, vrf: str = None) -> List[Dict]:
        pass

    @abstractmethod
    def get_mac_table(self) -> List[Dict]:
        pass

    @abstractmethod
    def discover_vrfs(self) -> List[str]:
        pass
