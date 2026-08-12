"""
ARP Spoofing Detector
Main application.
"""

import argparse
import sys
import time
from datetime import datetime

from arp_detector import ARPDetector
from arp_scanner import ARPScanner


def print_banner() -> None:
    print("=" * 60)
    print("             ARP SPOOFING DETECTOR")
    print("=" * 60)
    print("Defensive ARP monitoring tool")
    print()


def print_arp_table(arp_table: dict[str, str]) -> None:
    """Display the current ARP table."""
    print("\nCurrent ARP table:")
    print("-" * 60)

    if not arp_table:
        print("No ARP entries found.")
        return

    for ip, mac in sorted(arp_table.items()):
        print(f"{ip:<18} -> {mac}")


def print_alert(alert) -> None:
    """Display a detected ARP anomaly."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print()
    print("!" * 60)
    print("🚨 ARP SPOOFING SUSPICION DETECTED")
    print("!" * 60)
    print(f"Time      : {timestamp}")
    print(f"IP        : {alert.ip}")
    print(f"Old MAC   : {alert.old_mac}")
    print(f"New MAC   : {alert.new_mac}")
    print(f"Risk      : {alert.risk_score}/100")
    print(f"Severity  : {alert.severity}")
    print(f"Reason    : {alert.reason}")
    print("!" * 60)


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Detect suspicious ARP table changes."
    )

    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=5,
        help="Scan interval in seconds (default: 5)",
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Perform one scan and exit",
    )

    parser.add_argument(
        "--show-table",
        action="store_true",
        help="Display the ARP table during each scan",
    )

    return parser


def run_once(scanner: ARPScanner, detector: ARPDetector) -> None:
    """Perform a single ARP scan."""
    try:
        arp_table = scanner.scan()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        return

    print_arp_table(arp_table)

    detector.set_baseline(arp_table)
    print("\n[+] Baseline created successfully.")


def monitor(
    scanner: ARPScanner,
    detector: ARPDetector,
    interval: int,
    show_table: bool,
) -> None:
    """Continuously monitor the ARP table."""

    print(f"[*] Monitoring every {interval} second(s)...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        while True:
            try:
                arp_table = scanner.scan()
            except RuntimeError as exc:
                print(f"[ERROR] {exc}")
                time.sleep(interval)
                continue

            if show_table:
                print_arp_table(arp_table)

            alerts = detector.analyze(arp_table)

            if alerts:
                for alert in alerts:
                    print_alert(alert)

            else:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] ✓ No suspicious ARP changes")

            # Update the baseline after processing the current state.
            detector.update_baseline(arp_table)

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[*] Monitoring stopped.")
        print("[+] Exiting safely.")


def main() -> None:
    """Application entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("Interval must be greater than 0.")

    print_banner()

    scanner = ARPScanner()
    detector = ARPDetector()

    print("[*] Performing initial ARP scan...")

    try:
        arp_table = scanner.scan()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)

    if not arp_table:
        print("[WARNING] No ARP entries were found.")

    detector.set_baseline(arp_table)

    print(f"[+] {len(arp_table)} ARP entr{'y' if len(arp_table) == 1 else 'ies'} loaded.")
    print("[+] Trusted baseline established.")

    if args.once:
        print_arp_table(arp_table)
        return

    monitor(
        scanner=scanner,
        detector=detector,
        interval=args.interval,
        show_table=args.show_table,
    )


if __name__ == "__main__":
    main()
