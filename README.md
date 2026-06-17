# 🔌 Network Port Scanner

A multi-threaded Python port scanner that performs TCP connect scans,
banner grabbing, and automated risk assessment on target hosts.

---

## ⚡ Features

- **TCP Connect Scan** — Tests ports using socket connections
- **Multi-threaded** — Scans 100 ports simultaneously (10x faster)
- **Banner Grabbing** — Extracts service version info from open ports
- **DNS Resolution** — Accepts both hostnames and IP addresses
- **Risk Assessment** — Flags dangerous open ports (Telnet, RDP, SMB, etc.)
- **Report Generation** — Saves full results to `port_scan_report.txt`

---

## 🛠️ Setup & Installation

**Requirements:** Python 3.x (no external libraries needed)

```bash
# Clone the repository
git clone https://github.com/s0xandrew/network-port-scanner.git
cd network-port-scanner

# Run the scanner
python port_scanner.py
```

---

## 📸 Sample Output

NETWORK PORT SCANNER

By Sourabh (s0xandrew) | Ethical Use Only

Target: scanme.nmap.org
[DNS] Resolving scanme.nmap.org...

[DNS] Resolved to: 45.33.32.156
[SCAN] Scanning ports 1-1024 on 45.33.32.156

[SCAN] Using 100 threads for speed
PORT     SERVICE              BANNER

22       SSH                  No banner

80       HTTP                 HTTP/1.1 200 OK
[RESULTS] Total open ports found: 2

[RISK] No commonly dangerous ports found open.

---

## 🧠 How It Works

### TCP Connect Scan
Each port is tested by attempting a full TCP handshake using
Python's `socket` module. If the connection succeeds (returns 0),
the port is open. This mirrors what tools like nmap do at a basic level.

### Multi-threading
Without threading, scanning 1024 ports with a 1-second timeout
would take 17+ minutes. Using `ThreadPoolExecutor` with 100 workers
reduces this to under 60 seconds — a 17x speedup.

### Banner Grabbing
Once an open port is found, the scanner sends an HTTP HEAD request
and reads the first response. Services often reveal their software
name and version here — critical data for vulnerability assessment.

### Risk Assessment
Open ports are checked against a dictionary of commonly exploited
services (Telnet, RDP, SMB, MongoDB, Redis). Matches trigger
high-risk warnings with explanations.

---

## 🎯 Legal Practice Targets

| Target | Notes |
|--------|-------|
| `scanme.nmap.org` | Maintained by nmap.org — explicitly for scanning practice |
| `localhost` | Your own machine |
| Your home router IP | You own it |

**Never scan targets without permission.**

---

## ⚖️ Ethical Use Disclaimer

This tool is for:
- Educational purposes only
- Systems you own or have written permission to test
- Legal practice environments like `scanme.nmap.org`

Unauthorized port scanning may be illegal under the IT Act, 2000 (India)
and Computer Fraud and Abuse Act (USA). The author takes no 
responsibility for misuse.

---

## 🔗 B.Cyber Relevance

| Concept | Mapped To |
|---------|-----------|
| TCP/IP & OSI Model | Socket programming, connect scan |
| Network Reconnaissance | Port scanning methodology |
| Banner Grabbing | Service fingerprinting |
| Threat Intelligence | Risk assessment engine |
| Defense in Depth | Identifying dangerous exposed services |

---

## 📁 Project Structure
network-port-scanner/

│

├── port_scanner.py          # Main scanner

├── port_scan_report.txt     # Auto-generated report

└── README.md                # This file
---

## 👨‍💻 Author

**Sourabh (s0xandrew)**  
Self-taught cybersecurity enthusiast |

---

## 📚 What I Learned

- TCP/IP handshake mechanics at the socket level
- How port scanners like nmap work under the hood
- Multi-threading for network I/O performance
- Banner grabbing and service fingerprinting
- Risk-based thinking about exposed network services
- Python: socket, threading, concurrent.futures
