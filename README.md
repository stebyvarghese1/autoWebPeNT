<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=240&section=header&text=autoWebPeNT&fontSize=70&fontColor=ffffff&fontAlignY=42&desc=Automated%20Web%20Penetration%20Testing%20Orchestration%20Framework&descAlignY=63&descSize=16&descColor=94a3b8&animation=fadeIn" width="100%"/>

</div>

<br>

<div align="center">

```
   Automated Recon  ·  Port Scanning  ·  Web Enumeration  ·  Exploitation  ·  PDF Reports
```

</div>

<br>

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-2024+-557C93?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Nmap](https://img.shields.io/badge/Nmap-Port_Scanning-4682B4?style=for-the-badge&logo=networkation&logoColor=white)](https://nmap.org)
[![OWASP](https://img.shields.io/badge/OWASP-Compliance-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org)
[![ReportLab](https://img.shields.io/badge/ReportLab-PDF_Reports-FF6F00?style=for-the-badge)](https://www.reportlab.com/)
[![License](https://img.shields.io/badge/License-MIT-fbbf24?style=for-the-badge)](LICENSE)

<br>

[![Stars](https://img.shields.io/github/stars/stebyvarghese1/autoWebPeNT?style=flat-square&color=fbbf24&label=⭐%20Stars)](https://github.com/stebyvarghese1/autoWebPeNT/stargazers)
&nbsp;
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Debian%20%7C%20Linux-38bdf8?style=flat-square)](#)
&nbsp;
[![Built by](https://img.shields.io/badge/by-Steby%20Varghese-a78bfa?style=flat-square)](https://github.com/stebyvarghese1)

</div>

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 01 `&nbsp;&nbsp; THE OVERVIEW
</div>

<br>

> ### *"Single-command web penetration testing: From target reconnaissance to executive PDF reporting."*

<br>

**autoWebPeNT** is an automated web penetration testing orchestration framework tailored for Kali Linux. It integrates 15+ industry-standard security tools into a unified, high-performance, four-phase testing pipeline: **Reconnaissance**, **Port Scanning**, **Web Enumeration**, and **Vulnerability Exploitation**, culminating in a client-ready executive PDF report.

```
  ┌─────────────────────────────────────────────────────────┐
  │  15+ Industry-Standard Security Tools Integrated       │
  │  Automated Pre-Flight Dependency Detection via APT      │
  │  Concurrent Multi-Threaded Execution Pipeline            │
  │  Client-Ready PDF Report with Compliance Alignment      │
  └─────────────────────────────────────────────────────────┘
```

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 02 `&nbsp;&nbsp; FEATURES
</div>

<br>

<div align="center">

| &nbsp; | Feature | Description |
|--------|---------|-------------|
| 🎯 | **Single-Command Auditing** | Run a full 4-phase audit against target domains with 1 command |
| ⚡ | **Multi-Threaded Execution** | Concurrent tool execution for maximum speed and throughput |
| 🛡️ | **15+ Tool Integration** | Seamlessly orchestrates Nmap, RustScan, Nuclei, Sqlmap, XSStrike, etc. |
| 📊 | **Executive PDF Generation** | Generates detailed reports complete with risk matrix & remediation steps |
| ⚖️ | **Compliance Mapping** | Maps findings to OWASP Top 10 (2021), NIST SP 800-53 & PCI-DSS 4.0 |
| 📦 | **Debian Native Packaging** | Native `.deb` packaging infrastructure & system man page included |

</div>

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 03 `&nbsp;&nbsp; THE 4-PHASE PIPELINE
</div>

<br>

<div align="center">

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                      PHASE 1: RECONNAISSANCE                            │
  │       Amass  ·  Sublist3r  ·  theHarvester  ·  OSINT Subdomains         │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                      PHASE 2: PORT SCANNING                             │
  │            RustScan (Fast Discovery)  ·  Nmap (Service & OS)            │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     PHASE 3: WEB ENUMERATION                            │
  │     Gobuster  ·  FFUF  ·  Nikto  ·  WPScan  ·  WhatWeb  ·  Nuclei        │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                   PHASE 4: VULNERABILITY EXPLOITATION                   │
  │          Sqlmap  ·  XSStrike  ·  Commix  ·  Hydra Bruteforce            │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     EXECUTIVE PDF REPORT GENERATION                     │
  │      Security Posture · Remediation Roadmap · Compliance Audit Logs     │
  └─────────────────────────────────────────────────────────────────────────┘
```

</div>

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 04 `&nbsp;&nbsp; TECH STACK
</div>

<br>

<div align="center">

| Layer | Component | Integrated Tools & Technologies |
|-------|-----------|----------------------------------|
| 🔍 **Phase 1: Recon** | OSINT & Subdomains | Amass · Sublist3r · theHarvester |
| 🌐 **Phase 2: Scanning** | Network & Port Audit | RustScan · Nmap |
| 🔎 **Phase 3: Web Enum** | Fingerprint & Vulnerability Scan | Gobuster · FFUF · Nikto · WPScan · WhatWeb · Nuclei |
| ⚡ **Phase 4: Exploitation** | Automated Exploitation | Sqlmap · XSStrike · Commix · Hydra |
| 📄 **Reporting** | PDF Engine | Python 3.8+ · ReportLab · PyPDF2 |
| 📦 **Deployment** | Packaging | Debian Packaging (`dpkg-buildpackage`) · Linux Man Pages |

</div>

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 05 `&nbsp;&nbsp; GETTING STARTED
</div>

<br>

### Prerequisites
`autoWebPeNT` requires **Python 3.8+** and is optimized for **Kali Linux**. Missing tool dependencies are automatically detected during pre-flight checks and installed via `apt`.

<br>

**Step 1 — Clone the Repository**
```bash
git clone https://github.com/stebyvarghese1/autoWebPeNT.git
cd autoWebPeNT
```

**Step 2 — Make Executable**
```bash
chmod +x autoWebPeNT.py
```

**Step 3 — Quick Start**
Run a complete 4-phase assessment against a target domain:
```bash
python3 autoWebPeNT.py -d example.com
```

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 06 `&nbsp;&nbsp; COMMAND-LINE OPTIONS & USAGE
</div>

<br>

### CLI Reference

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

<br>

### Usage Examples

**Example 1: Standard Full 4-Phase Scan**
```bash
python3 autoWebPeNT.py -d target.com
```

**Example 2: High-Speed Custom Audit with Client Branding**
```bash
python3 autoWebPeNT.py -d target.com --threads 5 --company "Acme Security Labs" --no-creds
```

**Example 3: Non-Intrusive Scan (Skip Phase 4 Exploitation)**
```bash
python3 autoWebPeNT.py -d target.com --skip-exploit
```

**Example 4: Reconnaissance Phase Only**
```bash
python3 autoWebPeNT.py -d target.com --skip-scan --skip-web --skip-exploit
```

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 07 `&nbsp;&nbsp; DEBIAN PACKAGING (.DEB)
</div>

<br>

To build and install `autoWebPeNT` natively on Kali Linux / Debian system using the included `debian/` packaging infrastructure:

**Step 1 — Build the `.deb` Package**
```bash
dpkg-buildpackage -b -uc -us
```

**Step 2 — Install Package & Dependencies**
```bash
sudo dpkg -i ../autowebpnt_1.0.0-1_all.deb
sudo apt-get install -f   # Automatically installs missing tool dependencies
```

**Step 3 — Access System Man Page**
```bash
man autowebpnt
```

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 08 `&nbsp;&nbsp; EXECUTIVE PDF REPORT
</div>

<br>

Upon assessment completion, `autoWebPeNT` automatically compiles a professional PDF report saved directly to your workspace:

```
autowebpnt_report_<target>_<timestamp>.pdf
```

### Report Contents
1. **Executive Summary & Security Posture**: Security Score (0–100), Risk Rating, and severity breakdown (Critical, High, Medium, Low).
2. **Confirmed Vulnerabilities & PoC Evidence**: Detailed writeups, impact analysis, mitigations, and raw proof-of-concept outputs.
3. **Discovered Tech Stack & Fingerprinting**: Server, framework, and CMS fingerprints via WhatWeb and header analysis.
4. **Target Intelligence & Subdomains**: Mapped subdomains gathered across OSINT sources.
5. **Open Ports & Network Services**: Service banners and OS detection from RustScan & Nmap.
6. **Prioritized Remediation Roadmap**: Clear, actionable mitigation steps prioritized by severity (P0, P1, P2).
7. **Compliance Matrix**: Direct mapping against OWASP Top 10 (2021), NIST SP 800-53, and PCI-DSS 4.0.
8. **Audit Logs & Execution Vault**: Embedded execution logs for full auditability.

> ℹ️ *Note: Workspace files and temporary tool outputs are isolated and automatically cleaned up upon completion.*

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 09 `&nbsp;&nbsp; EXIT CODES
</div>

<br>

<div align="center">

| Code | Meaning | Action Needed |
|:----:|---------|---------------|
| `0` | **Success** | All requested assessment phases completed cleanly. |
| `1` | **Invalid Arguments** | Check CLI flag syntax with `-h`. |
| `2` | **Missing Tool Dependency** | Install missing tools with `sudo apt install <tool>`. |
| `3` | **Directory Error** | Verify write permissions for the workspace directory. |

</div>

<br>
<br>

---

<div align="center">

## &nbsp;&nbsp;&nbsp;` 10 `&nbsp;&nbsp; PROJECT STRUCTURE
</div>

<br>

```
autoWebPeNT/
│
├── autoWebPeNT.py             ← Main framework CLI & orchestration engine
├── debian/                    ← Debian packaging configurations
│   ├── changelog
│   ├── control
│   ├── copyright
│   └── rules
├── man/                       ← Linux man page sources
│   └── autowebpnt.1
├── prd.md                     ← Product Requirements Document
└── README.md                  ← Project documentation
```

<br>
<br>

---

<br>

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=130&section=footer&animation=fadeIn" width="100%"/>

[![GitHub](https://img.shields.io/badge/GitHub-stebyvarghese1-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/stebyvarghese1)
&nbsp;
[![Portfolio](https://img.shields.io/badge/Portfolio-Visit-a78bfa?style=flat-square&logo=firefox&logoColor=white)](https://portfolio-v3ia.onrender.com/)
&nbsp;
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/steby-varghese)

<br>

**⭐ Star this repo if autoWebPeNT helped streamline your penetration tests!**

Licensed under [MIT](LICENSE)

</div>

