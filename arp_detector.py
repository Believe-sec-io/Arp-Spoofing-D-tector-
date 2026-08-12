"""
ARP Spoofing Detector
Detection engine for suspicious ARP table changes.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ARPAlert:
    ip: str
    old_mac: str
    new_mac: str
    risk_score: int
    severity: str
    reason: str


class ARPDetector:
    """Detect suspicious changes in IP-to-MAC mappings."""

    def __init__(self):
        self.baseline: Dict[str, str] = {}

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalize a MAC address for reliable comparison."""
        return mac.strip().lower().replace("-", ":")

    def set_baseline(self, arp_table: Dict[str, str]) -> None:
        """Store the current ARP table as the trusted baseline."""
        self.baseline = {
            ip: self.normalize_mac(mac)
            for ip, mac in arp_table.items()
        }

    def analyze(self, arp_table: Dict[str, str]) -> List[ARPAlert]:
        """
        Compare the current ARP table against the trusted baseline.
        Returns alerts for suspicious IP-to-MAC changes.
        """
        alerts: List[ARPAlert] = []

        for ip, mac in arp_table.items():
            mac = self.normalize_mac(mac)

            if ip not in self.baseline:
                continue

            old_mac = self.baseline[ip]

            if old_mac == mac:
                continue

            alert = self._create_alert(
                ip=ip,
                old_mac=old_mac,
                new_mac=mac,
            )

            alerts.append(alert)

        return alerts

    @staticmethod
    def _create_alert(ip: str, old_mac: str, new_mac: str) -> ARPAlert:
        """
        Create an alert for an IP-to-MAC mapping change.

        A MAC change alone is not proof of ARP poisoning,
        so the alert is classified as suspicious rather than
        automatically declaring an attack.
        """
        return ARPAlert(
            ip=ip,
            old_mac=old_mac,
            new_mac=new_mac,
            risk_score=80,
            severity="HIGH",
            reason=(
                f"ARP mapping changed for {ip}: "
                f"{old_mac} -> {new_mac}"
            ),
        )

    def update_baseline(self, arp_table: Dict[str, str]) -> None:
        """Update the trusted ARP baseline."""
        self.set_baseline(arp_table)
