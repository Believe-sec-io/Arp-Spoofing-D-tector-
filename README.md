## Featurestures Spoofing Detector

A lightweight, cross-platform defensive security tool that monitors the local ARP table and detects suspicious IP-to-MAC address changes that may indicate ARP spoofing / ARP poisoning.

# Features

- 🔍 Continuous ARP table monitoring
- 🛡️ Baseline-based detection
- 🚨 Detection of suspicious IP-to-MAC changes
- 📊 Risk scoring
- ⚠️ Severity classification
- 🖥️ Windows and Linux support
- ⏱️ Configurable monitoring interval
- 📋 Optional ARP table display
- 🔧 Simple command-line interface
- 🐍 Python-based with minimal dependencies

How It Works

The detector first creates a trusted baseline from the current ARP table.

             Local ARP Table
                    │
                    ▼
             Create Baseline
                    │
                    ▼
            Continuous Scan
                    │
                    ▼
          Compare IP → MAC
                    │
             ┌──────┴──────┐
             │             │
          No change     Change detected
             │             │
             ▼             ▼
           Normal       Risk analysis
                           │
                           ▼
                    🚨 Suspicious ARP

For example:

Baseline:

192.168.1.1 → AA:BB:CC:DD:EE:FF

Later:

192.168.1.1 → 11:22:33:44:55:66

The detector reports the change as suspicious.

«A MAC address change alone does not prove ARP poisoning. Legitimate network changes can produce the same behavior. Future versions can correlate multiple indicators to improve confidence and reduce false positives.»

Requirements

- Python 3.9+
- Windows or Linux

No external Python dependency is currently required.

Installation

Clone the repository:

git clone https://github.com/yourusername/arp-spoofing-detector.git
cd arp-spoofing-detector

Run the application:

python main.py

Usage

Continuous monitoring

python main.py

The default monitoring interval is 5 seconds.

Custom interval

python main.py --interval 10

This scans the ARP table every 10 seconds.

Display the ARP table

python main.py --show-table

Perform a single scan

python main.py --once

Example Output

============================================================
             ARP SPOOFING DETECTOR
============================================================
Defensive ARP monitoring tool

[*] Performing initial ARP scan...
[+] 5 ARP entries loaded.
[+] Trusted baseline established.
[*] Monitoring every 5 second(s)...
[*] Press Ctrl+C to stop.

[22:10:05] ✓ No suspicious ARP changes
[22:10:10] ✓ No suspicious ARP changes

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
🚨 ARP SPOOFING SUSPICION DETECTED
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Time      : 2026-08-12 22:10:15
IP        : 192.168.1.1
Old MAC   : aa:bb:cc:dd:ee:ff
New MAC   : 11:22:33:44:55:66
Risk      : 80/100
Severity  : HIGH
Reason    : ARP mapping changed for 192.168.1.1
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Project Structure

arp-spoofing-detector/
│
├── main.py
├── arp_detector.py
├── arp_scanner.py
├── logger.py
├── config.py
├── requirements.txt
├── README.md
│
└── logs/
    └── alerts.log

«"logger.py", "config.py", and persistent alert logging are planned components for the next development stage.»

Detection Logic

The current detection engine focuses on:

IP → MAC changes

Known:
192.168.1.1 → AA:BB:CC:DD:EE:FF

Observed:
192.168.1.1 → 11:22:33:44:55:66

This generates a high-risk alert.

Why this matters

During ARP poisoning, an attacker may attempt to associate their MAC address with the IP address of another host, commonly the network gateway.

This can enable traffic interception or man-in-the-middle activity.

Security Notice

This project is intended for:

- Defensive security research
- SOC analyst training
- Network monitoring
- Security laboratories
- Authorized environments

Only monitor networks and systems that you own or have explicit permission to analyze.

Roadmap

- [x] ARP table scanner
- [x] Windows support
- [x] Linux support
- [x] ARP baseline
- [x] IP-to-MAC change detection
- [x] Risk scoring
- [x] Continuous monitoring
- [ ] Gateway detection
- [ ] Duplicate MAC detection
- [ ] Duplicate IP detection
- [ ] Historical ARP tracking
- [ ] Persistent alert logging
- [ ] Configuration file
- [ ] Improved false-positive handling
- [ ] Rich terminal interface
- [ ] JSON/CSV reports
- [ ] Network interface selection
- [ ] Alert notifications
- [ ] Unit tests
- [ ] Production hardening

Disclaimer

This software is provided for educational and defensive security purposes. Detection results are indicators of suspicious behavior and should be investigated before concluding that an ARP poisoning attack has occurred.

License

MIT License
