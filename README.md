# autoWebPeNT — Automated Web Penetration Testing Framework

**autoWebPeNT** is an automated web penetration testing orchestration framework designed for Kali Linux. It integrates 15+ industry-standard security tools into a single, cohesive, four-phase pipeline: Reconnaissance, Port Scanning, Web Enumeration, and Vulnerability Exploitation, producing a client-ready executive PDF report.

---

## 📋 Table of Contents

1. [Prerequisites & Tool Installation](#1-prerequisites--tool-installation)
2. [Installation from GitHub](#2-installation-from-github)
3. [Quick Start](#3-quick-start)
4. [Command-Line Options](#4-command-line-options)
5. [Usage Examples](#5-usage-examples)
6. [Building & Installing Debian Package (`.deb`)](#6-building--installing-debian-package-deb)
7. [Executive PDF Report](#7-executive-pdf-report)
8. [Exit Codes](#8-exit-codes)

---

## 1. Prerequisites & Tool Installation

`autoWebPeNT` requires Python 3.8+ and is optimized for Kali Linux. `autoWebPeNT` automatically detects missing dependencies during pre-flight check and attempts to install them via `apt`.

---

## 2. Installation from GitHub

To clone and set up `autoWebPeNT` directly from GitHub:

```bash
# Clone the repository
git clone https://github.com/stebyvarghese1/autoWebPeNT.git

# Navigate into the project directory
cd autoWebPeNT

# Make the script executable
chmod +x autoWebPeNT.py
```

---

## 3. Quick Start

Run a complete 4-phase security assessment against a target domain with a single command:

```bash
python3 autoWebPeNT.py -d example.com
```

## 4. Command-Line Options

```
Usage: autowebpnt -d <domain> [OPTIONS]

Required Arguments:
  -d, --domain DOMAIN       Target domain to assess (e.g., example.com)

Optional Arguments:
  --skip-recon              Skip Phase 1: Reconnaissance (Amass, Sublist3r, theHarvester, etc.)
  --skip-scan               Skip Phase 2: Port Scanning (RustScan, Nmap)
  --skip-web                Skip Phase 3: Web Enumeration (Gobuster, FFUF, Nikto, WPScan, Nuclei)
  --skip-exploit            Skip Phase 4: Vulnerability Exploitation (Sqlmap, XSStrike, Commix, Hydra)
  --threads THREADS         Max parallel threads for concurrent tool runs (default: 3)
  --company COMPANY         Client or company name for report header (default: "Authorized Security Audit")
  --show-creds              Show unredacted credentials in report (default: True)
  --no-creds                Mask discovered credentials in report
  -h, --help                Show help message and exit
```

---

## 5. Usage Examples

### Example 1: Standard Full Scan
```bash
python3 autoWebPeNT.py -d target.com
```

### Example 2: High-Speed Custom Audit with Client Branding
Run with 5 parallel threads, setting custom client header and credential masking:
```bash
python3 autoWebPeNT.py -d target.com --threads 5 --company "Acme Security Labs" --no-creds
```

### Example 3: Non-Intrusive Scan (Skip Exploitation)
Run Reconnaissance, Port Scanning, and Web Enumeration while skipping Phase 4:
```bash
python3 autoWebPeNT.py -d target.com --skip-exploit
```

### Example 4: Reconnaissance Only
Run only Phase 1 to quickly harvest subdomains and OSINT:
```bash
python3 autoWebPeNT.py -d target.com --skip-scan --skip-web --skip-exploit
```

---

## 6. Building & Installing Debian Package (`.deb`)

To build and install `autoWebPeNT` natively on Kali Linux using the provided `debian/` packaging infrastructure:

### Step 1: Build the `.deb` package
```bash
dpkg-buildpackage -b -uc -us
```

### Step 2: Install the built package
```bash
sudo dpkg -i ../autowebpnt_1.0.0-1_all.deb
sudo apt-get install -f   # Fix any missing tool dependencies automatically
```

### Step 3: View the System Man Page
```bash
man autowebpnt
```

---

## 7. Executive PDF Report

Upon completing an assessment, `autoWebPeNT` automatically generates a client-ready executive PDF report in the current working directory named:

```
autowebpnt_report_<target>_<timestamp>.pdf
```

### Report Contents:
1. **Executive Summary & Security Posture**: Security Score (0-100), Risk Rating, and finding breakdown (Critical, High, Medium, Low).
2. **Confirmed Security Vulnerabilities & PoC Evidence**: Detailed vulnerability writeups, impact analysis, remediations, and raw PoC evidence.
3. **Discovered Technology Stack & Fingerprinting**: Web server, framework, and CMS fingerprints from WhatWeb and header analysis.
4. **Target Intelligence & Subdomains**: Discovered subdomains mapped across OSINT sources.
5. **Open Ports & Network Services**: Service banners and OS detection from Nmap and RustScan.
6. **Actionable Prioritized Remediation Roadmap**: Prioritized mitigation steps (P0, P1, P2).
7. **Regulatory & Framework Compliance Matrix**: Alignment against OWASP Top 10 (2021), NIST SP 800-53, and PCI-DSS 4.0.
8. **Raw Execution Vault & Audit Logs**: Embedded logs for verification and auditing.

*Note: Intermediate tool workspace files are automatically isolated in a temporary directory and cleaned up upon assessment completion.*

---

## 8. Exit Codes

| Code | Meaning | Action Needed |
|------|---------|---------------|
| `0` | **Success** | All requested phases completed cleanly. |
| `1` | **Invalid Arguments** | Check CLI flag syntax with `-h`. |
| `2` | **Missing Tool Dependency** | Install missing tools with `sudo apt install <tool>`. |
| `3` | **Directory Error** | Check write permissions for workspace directory. |

