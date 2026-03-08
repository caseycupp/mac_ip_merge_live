"""
Multi-VRF discovery and orchestration.
Handles dynamic VRF detection and ARP collection across VRFs.
"""

from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class VRFDiscovery:
    """Manage VRF discovery and ARP collection."""

    def __init__(self, device_driver):
        self.driver = device_driver
        self.discovered_vrfs = []

    def discover(self) -> List[str]:
        """Discover VRFs on device."""
        if not self.driver.is_connected:
            logger.warning(f"Device {self.driver.hostname} not connected, skipping VRF discovery")
            return []

        try:
            self.discovered_vrfs = self.driver.discover_vrfs()
            logger.info(f"Discovered {len(self.discovered_vrfs)} VRFs on {self.driver.hostname}: {self.discovered_vrfs}")
            return self.discovered_vrfs
        except Exception as e:
            logger.error(f"VRF discovery failed on {self.driver.hostname}: {e}")
            return []

    def get_all_arp_entries(self) -> List[Dict[str, str]]:
        """Collect ARP entries from all VRFs (or global if no VRFs)."""
        if not self.driver.is_connected:
            return []

        all_entries = []

        # If no VRFs discovered, query global ARP
        if not self.discovered_vrfs:
            logger.info(f"No VRFs discovered on {self.driver.hostname}, querying global ARP")
            entries = self.driver.get_arp_table(vrf=None)
            all_entries.extend(entries)
        else:
            # Query each VRF
            for vrf in self.discovered_vrfs:
                logger.info(f"Querying ARP on {self.driver.hostname} VRF: {vrf}")
                entries = self.driver.get_arp_table(vrf=vrf)
                all_entries.extend(entries)

        logger.info(f"Total ARP entries collected from {self.driver.hostname}: {len(all_entries)}")
        return all_entries
