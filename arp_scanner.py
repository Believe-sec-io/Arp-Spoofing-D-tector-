"""
ARP Spoofing Detector
Cross-platform ARP table scanner.
"""

import platform
import re
import subprocess
from typing import Dict


class ARPScanner:
    """Retrieve the local ARP table."""

    def scan(self) -> Dict[str, str]:
        """Return the current ARP table as IP -> MAC mappings."""
        system = platform.system().lower()

        if system == "windows":
            return self._scan_windows()

        if system == "linux":
            return self._scan_linux()

        raise RuntimeError(
            f"Unsupported operating system: {platform.system()}"
        )

    def _run_command(self, command: list[str]) -> str:
        """Execute a system command and return its output."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                f"Failed to execute {' '.join(command)}: {exc}"
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(command)}\n"
                f"{result.stderr.strip()}"
            )

        return result.stdout

    def _scan_windows(self) -> Dict[str, str]:
        """Read ARP entries from Windows."""
        output = self._run_command(["arp", "-a"])
        arp_table: Dict[str, str] = {}

        pattern = re.compile(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3})"
            r"\s+([0-9a-fA-F-]{17})"
            r"\s+(\w+)"
        )

        for line in output.splitlines():
            match = pattern.match(line)

            if not match:
                continue

            ip = match.group(1)
            mac = match.group(2)

            arp_table[ip] = mac

        return arp_table

    def _scan_linux(self) -> Dict[str, str]:
        """Read ARP entries from Linux."""
        output = self._run_command(["ip", "neigh"])
        arp_table: Dict[str, str] = {}

        pattern = re.compile(
            r"^(\d{1,3}(?:\.\d{1,3}){3})"
            r".*?lladdr\s+([0-9a-fA-F:]{17})"
        )

        for line in output.splitlines():
            match = pattern.search(line)

            if not match:
                continue

            ip = match.group(1)
            mac = match.group(2)

            arp_table[ip] = mac

        return arp_table
