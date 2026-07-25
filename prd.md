# Product Requirements Document (PRD)

## autoWebPeNT — Automated Web Penetration Testing Framework

| Document | Details |
|----------|---------|
| **Project Name** | autoWebPeNT |
| **Version** | 1.0.0 (Draft) |
| **Status** | In Development |
| **Author** | [Authorized Security Team] |
| **Date** | July 20, 2026 |
| **Classification** | Internal — Authorized Security Tooling |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Project Goals & Objectives](#3-project-goals--objectives)
4. [Scope](#4-scope)
5. [User Personas](#5-user-personas)
6. [Functional Requirements](#6-functional-requirements)
7. [Non-Functional Requirements](#7-non-functional-requirements)
8. [System Architecture](#8-system-architecture)
9. [Tool Integration Matrix](#9-tool-integration-matrix)
10. [Data Flow & Pipeline Design](#10-data-flow--pipeline-design)
11. [User Interface & Experience](#11-user-interface--experience)
12. [Output & Reporting](#12-output--reporting)
13. [Installation & Deployment](#13-installation--deployment)
14. [Security & Compliance](#14-security--compliance)
15. [Error Handling & Resilience](#15-error-handling--resilience)
16. [Performance Requirements](#16-performance-requirements)
17. [Roadmap & Milestones](#17-roadmap--milestones)
18. [Testing Strategy](#18-testing-strategy)
19. [Limitations & Known Constraints](#19-limitations--known-constraints)
20. [Appendices](#20-appendices)

---

## 1. Executive Summary

autoWebPeNT is an **automated web penetration testing orchestration framework** that integrates 15+ industry-standard Kali Linux tools into a single, cohesive, four-phase pipeline. It enables authorized cybersecurity professionals to execute comprehensive web application assessments — from reconnaissance through exploitation — with a single command, while producing client-ready executive PDF reports.

The framework is designed to **reduce manual repetition**, **enforce methodological consistency**, and **accelerate the time-to-findings** for penetration testers, red teamers, and security auditors operating against authorized targets.

autoWebPeNT is distributed as a Debian package (`.deb`) via a Launchpad PPA, making it natively installable on Kali Linux with `sudo apt install autowebpnt`. It follows the Kali Linux tool packaging conventions and integrates seamlessly into existing workflows.

---

## 2. Problem Statement

### 2.1 Current Pain Points

| Issue | Description |
|-------|-------------|
| **Manual Tool Chaining** | Pentesters manually run Nmap, then manually parse output to feed into Gobuster, then manually run Nikto, etc. Time-consuming and error-prone. |
| **Inconsistent Methodology** | Different team members run different tools, skip phases, or use different flags — leading to inconsistent assessment depth across engagements. |
| **Lost Artifacts** | Output files from individual tools are scattered across directories, making post-engagement report compilation tedious. |
| **No Unified Reporting** | Findings from Sqlmap, Nuclei, Nikto, etc. live in separate formats (XML, JSON, plaintext). No single consolidated view. |
| **High Barrier for Juniors** | New pentesters must learn the CLI flags, syntax, and dependencies of 15+ tools before being productive. |

### 2.2 Impact

- **30-50%** of engagement time spent on manual orchestration rather than analysis
- **Inconsistent coverage** — critical vulnerabilities missed due to skipped phases
- **Report generation** takes 2-4 hours per engagement
- **Onboarding** new team members requires weeks of tool-specific training

---

## 3. Project Goals & Objectives

### 3.1 Primary Goals

1. **Single-command execution** — Run a complete web pentest with `autowebpnt -d <target>`
2. **Tool interoperability** — Seamlessly pipe output from one tool as input to the next
3. **Comprehensive coverage** — Execute all four phases: Recon, Scanning, Web Enumeration, Exploitation
4. **Executive PDF reporting** — Generate unified, client-ready PDF reports with vulnerability evidence and compliance matrices
5. **Kali-native packaging** — Distribute via Launchpad PPA with `apt` install

### 3.2 Success Metrics

| Metric | Target |
|--------|--------|
| **Phase completion rate** | 100% (all phases execute without fatal errors) |
| **False positive rate** | <15% (inline with individual tool accuracy) |
| **Report generation time** | <30 seconds after pipeline completion |
| **Installation success** | 100% on Kali Linux 2024.x+ |
| **Tool chain latency** | <5% overhead vs. running tools manually |

---

## 4. Scope

### 4.1 In Scope

- Web application penetration testing (external perspective)
- 15+ integrated Kali Linux tools across 4 phases
- Client-ready executive PDF report generation (`autowebpnt_report_<target>_<timestamp>.pdf`)
- Phase-level granularity (`--skip-*` flags)
- Multi-threaded execution for independent tool runs
- Target: single domain via `-d` flag
- Debian packaging (`.deb`) via Launchpad PPA
- Kali Linux 2024.x+ support
- Python 3.8+ runtime

### 4.2 Out of Scope (v1.0)

- Internal network penetration testing (AD, SMB, etc.)
- Wireless security assessment
- Mobile application testing
- Cloud infrastructure assessment (AWS, Azure, GCP)
- API-specific testing (beyond what Sqlmap/Commix cover)
- Real-time collaboration features
- GUI interface (CLI-only in v1.0)
- Windows/macOS support
- Multi-target batch processing from file
- Automatic credential validation (e.g., CrackMapExec integration)
- Screenshot capture (EyeWitness/Gowitness integration)
- Continuous monitoring / scheduled scanning

---

## 5. User Personas

### Persona 1: Senior Penetration Tester

| Attribute | Detail |
|-----------|--------|
| **Name** | Alex |
| **Role** | Lead Security Consultant |
| **Experience** | 8+ years in penetration testing |
| **Tools Known** | All 15+ tools manually |
| **Pain Point** | Repetitive chaining; wants automation without losing control |
| **Usage Pattern** | Runs full pipeline, then deep-dives into specific findings manually |
| **Key Need** | Phase-skip flags, raw output access, configurable threads |

### Persona 2: Junior Security Analyst

| Attribute | Detail |
|-----------|--------|
| **Name** | Jordan |
| **Role** | Associate Security Analyst |
| **Experience** | 1 year, familiar with 3-4 tools |
| **Pain Point** | Overwhelmed by tool count and flag combinations |
| **Usage Pattern** | Runs full pipeline, reads consolidated report |
| **Key Need** | One-command simplicity, clear reporting, educational output |

### Persona 3: Red Team Operator

| Attribute | Detail |
|-----------|--------|
| **Name** | Casey |
| **Role** | Red Team Lead |
| **Experience** | 6+ years |
| **Pain Point** | Needs fast initial recon to identify attack surface before going manual |
| **Usage Pattern** | Runs recon + scan phases, then pivots to custom tooling |
| **Key Need** | Speed, RustScan → Nmap chaining, raw data access |

### Persona 4: SOC Manager / Reporting Lead

| Attribute | Detail |
|-----------|--------|
| **Name** | Sam |
| **Role** | Security Operations Manager |
| **Experience** | 10+ years |
| **Pain Point** | Needs standardized, client-ready reports across all engagements |
| **Usage Pattern** | Reviews output HTML reports after analysts run assessments |
| **Key Need** | Clean formatting, severity-based findings, reproducible output |

---

## 6. Functional Requirements

### 6.1 Core Pipeline (F-001 to F-010)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-001** | The system shall accept a target domain via `-d` or `--domain` flag | P0 | Core |
| **F-002** | The system shall accept an output directory via `-o` or `--output` flag (default: `./autowebpnt_output`) | P0 | Core |
| **F-003** | The system shall execute four phases in order: Recon -> Scanning -> Web Enumeration -> Exploitation | P0 | Core |
| **F-004** | Each phase shall be independently skippable via `--skip-recon`, `--skip-scan`, `--skip-web`, `--skip-exploit` | P0 | Core |
| **F-005** | The system shall support configurable thread count via `--threads N` (default: 3) | P1 | Core |
| **F-006** | The system shall display a timestamped banner and phase progress during execution | P1 | Core |
| **F-007** | The system shall measure and report total execution duration | P1 | Core |
| **F-008** | The system shall create phase-specific subdirectories (`recon/`, `scanning/`, `web/`, `exploit/`) under the output directory | P0 | Core |
| **F-009** | The system shall save raw tool output to subdirectories as plaintext files | P0 | Core |
| **F-010** | The system shall display help/usage information with `--help` | P0 | Core |

### 6.2 Reconnaissance Phase (F-011 to F-015)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-011** | Amass shall enumerate subdomains and save to `recon/amass.txt` | P0 | Recon |
| **F-012** | Sublist3r shall perform fast subdomain discovery and save to `recon/sublist3r.txt` | P0 | Recon |
| **F-013** | theHarvester shall collect emails, subdomains, and IPs from search engines and save to `recon/theharvester.html` | P1 | Recon |
| **F-014** | DNSRecon shall enumerate DNS records (A, AAAA, MX, NS, TXT, SOA) and save to `recon/dnsrecon.txt` | P1 | Recon |
| **F-015** | WhatWeb shall fingerprint web technologies (CMS, frameworks, server headers) and save to `recon/whatweb.json` | P0 | Recon |

### 6.3 Scanning Phase (F-016 to F-017)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-016** | RustScan shall perform fast port discovery and save results to `scanning/rustscan.txt` | P0 | Scanning |
| **F-017** | Nmap shall perform service version detection (`-sV`), default script scanning (`-sC`), and OS detection on RustScan-discovered ports, saving to `scanning/nmap.txt` and `scanning/nmap.xml` | P0 | Scanning |
| **F-017a** | If RustScan discovers no open ports, Nmap shall run a full `-p-` scan instead | P1 | Scanning |

### 6.4 Web Enumeration Phase (F-018 to F-024)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-018** | Gobuster shall brute-force directories with `dirb/common.txt` and save to `web/gobuster.txt` | P0 | Web Enum |
| **F-019** | FFUF shall fuzz for parameters and save to `web/ffuf_params.txt` | P1 | Web Enum |
| **F-020** | FFUF shall perform virtual host discovery and save to `web/ffuf_vhost.txt` | P2 | Web Enum |
| **F-021** | Dirsearch shall perform extended directory enumeration with `directory-list-2.3-medium.txt` and save to `web/dirsearch.txt` | P1 | Web Enum |
| **F-022** | Nikto shall scan for known web server vulnerabilities and misconfigurations, saving to `web/nikto.txt` | P0 | Web Enum |
| **F-023** | If WhatWeb detects WordPress, WPScan shall enumerate vulnerable plugins, themes, and users, saving to `web/wpscan.txt` | P0 | Web Enum |
| **F-024** | Nuclei shall run template-based vulnerability scanning and save results to `web/nuclei.txt` and `web/nuclei.json` | P0 | Web Enum |

### 6.5 Exploitation Phase (F-025 to F-028)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-025** | Sqlmap shall crawl the target (depth 2) and test for SQL injection vulnerabilities, saving results to `exploit/sqlmap/` | P0 | Exploit |
| **F-026** | XSStrike shall crawl and test for cross-site scripting vulnerabilities, saving to `exploit/xsstrike.txt` | P0 | Exploit |
| **F-027** | Commix shall crawl (depth 1) and test for command injection vulnerabilities, saving to `exploit/commix/` | P1 | Exploit |
| **F-028** | Hydra shall perform form-based authentication brute-force using common username and password wordlists, saving to `exploit/hydra.txt` | P1 | Exploit |

### 6.6 Reporting (F-029 to F-033)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-029** | The system shall generate an HTML report (`report.html`) in the output directory | P0 | Reporting |
| **F-030** | The HTML report shall include: target domain, scan date, total duration, and findings per phase | P0 | Reporting |
| **F-031** | The HTML report shall use a dark terminal-themed CSS styling with color-coded severity indicators | P1 | Reporting |
| **F-032** | The system shall save a JSON summary of all phase outputs alongside the HTML report | P2 | Reporting |
| **F-033** | The report shall be timestamped and include the framework version number | P1 | Reporting |

### 6.7 Packaging & Distribution (F-034 to F-038)

| ID | Requirement | Priority | Phase |
|----|-------------|----------|-------|
| **F-034** | The system shall be packaged as a Debian binary package (`.deb`) | P0 | Packaging |
| **F-035** | The `.deb` shall declare all tool dependencies in `Depends` | P0 | Packaging |
| **F-036** | The package shall install the script to `/usr/bin/autowebpnt` | P0 | Packaging |
| **F-037** | A man page (`autowebpnt.1`) shall be installed to `/usr/share/man/man1/` | P1 | Packaging |
| **F-038** | The package shall be published via Launchpad PPA (`ppa:yourname/autowebpnt`) | P0 | Packaging |

---

## 7. Non-Functional Requirements

### 7.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| **NF-001** | Pipeline overhead (orchestration logic) shall not exceed 5% of total execution time | <5% |
| **NF-002** | HTML report generation shall complete within 30 seconds | <30s |
| **NF-003** | Tool timeout defaults shall prevent runaway processes (max 15 min per tool) | 900s |
| **NF-004** | The system shall support at least 3 concurrent tool executions via threading | 3 threads |

### 7.2 Reliability

| ID | Requirement | Target |
|----|-------------|--------|
| **NF-005** | A single tool failure shall not abort the entire pipeline | Continue on error |
| **NF-006** | All tool timeouts shall be caught and logged without crashing the framework | Graceful handling |
| **NF-007** | Missing tool binaries shall be detected at startup with a clear error message | Pre-flight check |

### 7.3 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| **NF-008** | The tool shall require no configuration file for basic usage | Zero config |
| **NF-009** | All command-line flags shall have both short and long forms | `-d` and `--domain` |
| **NF-010** | Error messages shall indicate the exact tool and reason for failure | Descriptive errors |

### 7.4 Maintainability

| ID | Requirement | Target |
|----|-------------|--------|
| **NF-011** | The codebase shall use modular functions (one per phase) | Modular |
| **NF-012** | Tool definitions and wordlist paths shall be centralized in configuration variables | Centralized config |
| **NF-013** | The package version shall be incremented following semantic versioning | SemVer |

### 7.5 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| **NF-014** | The framework shall run on Kali Linux 2024.x and later | Kali 2024+ |
| **NF-015** | Python 3.8 or later required | Python >= 3.8 |
| **NF-016** | All 15 integrated tools must be installable via `apt` on Kali | apt-installable |

---

## 8. System Architecture

### 8.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    autoWebPeNT Orchestrator                      │
│                       (Python 3 CLI)                             │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Argument Parser                             │
│                  (argparse: -d, -o, --skip-*)                    │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Pre-flight Check                             │
│              (Verify all tool binaries exist)                    │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Phase Execution Pipeline                       │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│   Phase 1    │   Phase 2    │   Phase 3    │   Phase 4          │
│ Reconnaissance│   Scanning   │Web Enumeration│ Exploitation      │
│              │              │              │                    │
│ ┌──────────┐ │ ┌──────────┐ │ ┌──────────┐ │ ┌──────────┐      │
│ │ Amass    │ │ │RustScan  │ │ │Gobuster  │ │ │ Sqlmap   │      │
│ │Sublist3r │→│ │    ↓     │ │ │ FFUF     │ │ │ XSStrike │      │
│ │theHarvest│ │ │  Nmap    │ │ │Dirsearch │ │ │ Commix   │      │
│ │ DNSRecon │ │ │          │ │ │ Nikto    │ │ │ Hydra    │      │
│ │ WhatWeb  │ │ │          │ │ │ WPScan*  │ │ │          │      │
│ └──────────┘ │ └──────────┘ │ │ Nuclei   │ │ └──────────┘      │
│              │              │ └──────────┘ │                    │
└──────────────┴──────────────┴──────────────┴────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Report Generator                             │
│              (HTML + JSON from collected outputs)                │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Component Diagram

```
┌──────────────────────────────────────────┐
│              autowebpnt                   │
│  ┌────────────────────────────────────┐   │
│  │        main()                      │   │
│  │  - Parse arguments                 │   │
│  │  - Run pre-flight checks           │   │
│  │  - Execute phases                  │   │
│  │  - Generate report                 │   │
│  └────────────────────────────────────┘   │
│                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │phase_    │ │phase_    │ │phase_    │ │
│  │recon()   │ │scanning()│ │web_enum()│ │
│  └──────────┘ └──────────┘ └──────────┘ │
│  ┌──────────┐ ┌──────────┐              │
│  │phase_    │ │write_    │              │
│  │exploit() │ │report()  │              │
│  └──────────┘ └──────────┘              │
│  ┌──────────┐ ┌──────────┐              │
│  │run_cmd() │ │check_    │              │
│  │          │ │tools()   │              │
│  └──────────┘ └──────────┘              │
└──────────────────────────────────────────┘
```

### 8.3 Threading Model

```
┌─────────────────────────────────────┐
│          Thread Pool                 │
│  (configurable: --threads N)        │
├─────────────────────────────────────┤
│                                     │
│  Phase 1 (Recon) ─── Sequential     │
│   ├── Amass        ─── Thread 1     │
│   ├── Sublist3r    ─── Thread 2     │
│   ├── theHarvester ─── Thread 3     │
│   ├── DNSRecon     ─── Thread 1     │
│   └── WhatWeb      ─── Thread 2     │
│                                     │
│  Phase 2 (Scanning) ─── Sequential  │
│   ├── RustScan     ─── Main Thread  │
│   └── Nmap         ─── Main Thread  │
│                                     │
│  Phase 3 (Web) ─── Parallel         │
│   ├── Gobuster     ─── Thread 1     │
│   ├── FFUF (param) ─── Thread 2     │
│   ├── Dirsearch    ─── Thread 3     │
│   ├── Nikto        ─── Thread 1     │
│   ├── WPScan       ─── Thread 2     │
│   └── Nuclei       ─── Thread 3     │
│                                     │
│  Phase 4 (Exploit) ─── Parallel     │
│   ├── Sqlmap       ─── Thread 1     │
│   ├── XSStrike     ─── Thread 2     │
│   ├── Commix       ─── Thread 3     │
│   └── Hydra        ─── Thread 1     │
│                                     │
└─────────────────────────────────────┘
```

---

## 9. Tool Integration Matrix

### 9.1 Tool Inventory

| # | Tool | Version (Min) | Phase | Purpose | Output Format | Timeout |
|---|------|---------------|-------|---------|---------------|---------|
| 1 | Amass | 4.2.0 | Recon | Subdomain enumeration | Plaintext | 600s |
| 2 | Sublist3r | 1.0 | Recon | Fast subdomain discovery | Plaintext | 300s |
| 3 | theHarvester | 4.0 | Recon | OSINT (emails, subdomains) | HTML | 180s |
| 4 | DNSRecon | 1.0 | Recon | DNS record enumeration | CSV/Plaintext | 120s |
| 5 | WhatWeb | 0.5.5 | Recon | Technology fingerprinting | JSON | 120s |
| 6 | RustScan | 2.0+ | Scanning | Fast port discovery | Plaintext | 300s |
| 7 | Nmap | 7.94 | Scanning | Service/OS detection | Plaintext + XML | 600s |
| 8 | Gobuster | 3.6 | Web | Directory brute-force | Plaintext | 300s |
| 9 | FFUF | 2.1 | Web | Parameter + VHOST fuzzing | JSON | 300s |
| 10 | Dirsearch | 0.4.3 | Web | Extended directory enum | Plaintext | 600s |
| 11 | Nikto | 2.5.0 | Web | Web server vuln scanning | Plaintext | 600s |
| 12 | WPScan | 3.8 | Web | WordPress vuln scanning | Plaintext | 600s |
| 13 | Nuclei | 3.0+ | Web | Template-based vuln scanning | Plaintext + JSON | 600s |
| 14 | Sqlmap | 1.8 | Exploit | SQL injection detection | Directory | 900s |
| 15 | XSStrike | 3.0 | Exploit | XSS detection | Plaintext | 600s |
| 16 | Commix | 3.0 | Exploit | Command injection detection | Directory | 600s |
| 17 | Hydra | 9.6 | Exploit | Auth brute-force | Plaintext | 600s |

### 9.2 Tool Dependencies Graph

```
WhatWeb ──detects──> WordPress? ──yes──> WPScan
RustScan ──provides open ports──> Nmap
Nmap ──provides service info──> (Context for all Web/Exploit tools)
```

---

## 10. Data Flow & Pipeline Design

### 10.1 Execution Flow

```
START
  │
  ├─ Parse CLI arguments
  ├─ Create output directory structure
  ├─ Pre-flight: Check all tool binaries exist
  │
  ├─ Phase 1: Reconnaissance (sequential)
  │   ├── Amass      ───> recon/amass.txt
  │   ├── Sublist3r  ───> recon/sublist3r.txt
  │   ├── theHarvester ──> recon/theharvester.html
  │   ├── DNSRecon   ───> recon/dnsrecon.txt
  │   └── WhatWeb    ───> recon/whatweb.json
  │
  ├─ Phase 2: Scanning (sequential, piped)
  │   ├── RustScan   ───> scanning/rustscan.txt
  │   └── Nmap       ───> scanning/nmap.txt, nmap.xml
  │                    (ports auto-fed from RustScan output)
  │
  ├─ Phase 3: Web Enumeration (parallel)
  │   ├── Gobuster   ───> web/gobuster.txt
  │   ├── FFUF params──> web/ffuf_params.txt
  │   ├── FFUF vhost ───> web/ffuf_vhost.txt
  │   ├── Dirsearch  ───> web/dirsearch.txt
  │   ├── Nikto      ───> web/nikto.txt
  │   ├── WPScan*    ───> web/wpscan.txt  (*conditional)
  │   └── Nuclei     ───> web/nuclei.txt, nuclei.json
  │
  ├─ Phase 4: Exploitation (parallel)
  │   ├── Sqlmap     ───> exploit/sqlmap/
  │   ├── XSStrike   ───> exploit/xsstrike.txt
  │   ├── Commix     ───> exploit/commix/
  │   └── Hydra      ───> exploit/hydra.txt
  │
  ├─ Generate HTML report ───> report.html
  ├─ Generate JSON summary ──> summary.json  (optional)
  │
  └─ END (print duration and output path)
```

### 10.2 Data Transformations

| Source | Transformation | Destination |
|--------|---------------|-------------|
| RustScan stdout | Regex extract port numbers, join with commas | Nmap `-p` argument |
| WhatWeb JSON | String search for "WordPress" | Boolean trigger for WPScan |
| All phase outputs | Read text files, wrap in HTML blocks | `report.html` |

---

## 11. User Interface & Experience

### 11.1 CLI Interface

```
Usage: autowebpnt -d <domain> [OPTIONS]

Required:
  -d, --domain DOMAIN    Target domain (e.g., example.com)

Options:
  --skip-recon           Skip reconnaissance phase
  --skip-scan            Skip port scanning phase
  --skip-web             Skip web enumeration phase
  --skip-exploit         Skip exploitation phase
  --threads N            Max parallel threads (default: 3)
  --company NAME         Client or company name for report header (default: "Authorized Security Audit")
  --show-creds           Show unredacted credentials in report (default: True)
  --no-creds             Mask credentials in report
  -h, --help             Show this help message and exit
```

### 11.2 Runtime Output Example

```
  ┌── [ EXECUTIVE SECURITY AUDIT COMPLETED ] ──────────────────────────────────────────┐
  │  Target Domain       : example.com
  │  Assessment Time     : 847.3 seconds
  │  Subdomains Mapped   : 14 hosts
  ├────────────────────────────────────────────────────────────────────────────────────┤
  │  📕 Final PDF Report    : autowebpnt_report_example_com_20260720_143000.pdf
  └────────────────────────────────────────────────────────────────────────────────────┘
```

### 11.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — all requested phases completed |
| 1 | Missing required argument or invalid usage |
| 2 | Pre-flight check failed (missing tool binary) |
| 3 | Directory or workspace environment initialization error |

---

## 12. Output & Reporting

### 12.1 Report Output Structure

`autoWebPeNT` generates a client-ready executive PDF report named:
`autowebpnt_report_<sanitized_target>_<timestamp>.pdf` directly in the execution directory.

Intermediate raw tool logs (Amass, Nmap, Gobuster, Sqlmap, Nuclei, etc.) are generated inside a temporary workspace directory (`/tmp/autowebpnt_<target>_<random>/`) during pipeline execution and automatically cleaned up upon assessment completion.
├── recon/
│   ├── amass.txt
│   ├── sublist3r.txt
│   ├── theharvester.html
│   ├── dnsrecon.txt
│   └── whatweb.json
├── scanning/
│   ├── rustscan.txt
│   ├── nmap.txt
│   └── nmap.xml
├── web/
│   ├── gobuster.txt
│   ├── ffuf_params.txt
│   ├── ffuf_vhost.txt
│   ├── dirsearch.txt
│   ├── nikto.txt
│   ├── wpscan.txt          (conditional)
│   ├── nuclei.txt
│   └── nuclei.json
├── exploit/
### 12.2 Executive PDF Report Structure

The generated PDF report incorporates the following 8 main sections:

1. **Executive Summary & Security Posture**: Overall Risk Rating, Security Score (0-100), and breakdown of Critical, High, Medium, and Low findings.
2. **Confirmed Security Vulnerabilities & PoC Evidence**: Complete vulnerability cards detailing severity, OWASP mapping, justification, impact, decoded PoC payload, and verification steps.
3. **Discovered Technology Stack & Fingerprinting**: Identified server software, frameworks, CMS engines, and WAF detection notes.
4. **Target Intelligence & Subdomain Discovery**: Subdomain mapping table with DNS resolution status.
5. **Open Ports & Network Services**: Port state, protocol, service banners, and version detection.
6. **Actionable Prioritized Remediation Roadmap**: Prioritized mitigation matrix (P0 Immediate, P1 High, P2 Routine).
7. **Regulatory & Framework Compliance Matrix**: Compliance mapping for OWASP Top 10 (2021), NIST SP 800-53, and PCI-DSS 4.0.
8. **Raw Tool Execution Vault & Audit Logs**: Full execution logs from all tools across the four phases.

### 12.3 Color Scheme (Dark Terminal Theme)

| Element | Color | Hex Code |
|---------|-------|----------|
| Background | Near-black | `#0a0a0a` |
| Primary text | Terminal green | `#00ff00` |
| Phase headers | Amber/Orange | `#ffaa00` |
| Vulnerabilities (critical) | Bright red | `#ff4444` |
| Success indicators | Green | `#00ff00` |
| Info/secondary text | Grey | `#888888` |
| Report title | Red | `#ff4444` |

---

## 13. Installation & Deployment

### 13.1 Distribution Channels

| Channel | Method | URL |
|---------|--------|-----|
| **Launchpad PPA** | `sudo add-apt-repository ppa:yourname/autowebpnt && sudo apt install autowebpnt` | `ppa:yourname/autowebpnt` |
| **Direct .deb** | `sudo dpkg -i autowebpnt_1.0.0_all.deb` | (distributed internally) |
| **GitHub Releases** | Download `.deb` from GitHub releases page | `github.com/yourorg/autowebpnt/releases` |

### 13.2 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Kali Linux 2024.1 | Kali Linux Rolling |
| Python | 3.8 | 3.11+ |
| RAM | 2 GB | 8 GB+ |
| Disk | 10 GB free | 50 GB+ (for wordlists + outputs) |
| Network | Internet access | High-speed (for scans) |
| Dependencies | 17 apt packages (see control file) | All installed via apt |

### 13.3 Installation Steps

```bash
# Option 1: PPA (recommended)
sudo add-apt-repository -y ppa:yourname/autowebpnt
sudo apt update
sudo apt install -y autowebpnt

# Option 2: Local .deb
wget https://github.com/yourorg/autowebpnt/releases/download/v1.0.0/autowebpnt_1.0.0_all.deb
sudo dpkg -i autowebpnt_1.0.0_all.deb
sudo apt-get install -f

# Verify
autowebpnt --help
```

### 13.4 Post-Installation

```bash
# Ensure wordlists are available
ls /usr/share/wordlists/rockyou.txt
# If missing: sudo apt install wordlists

# Run a smoke test
autowebpnt -d example.com -o ~/smoke_test --skip-recon --skip-scan --skip-web
```

---

## 14. Security & Compliance

### 14.1 Authorization

- The tool assumes **pre-verified authorization** for all targets
- No authorization confirmation prompts within the tool
- Users are responsible for ensuring they have written permission for all scanned targets
- The HTML report footer states: *"For authorized security testing only"*

### 14.2 Data Handling

- All scan outputs are stored locally in the specified output directory
- No telemetry, analytics, or call-home functionality
- No credentials are stored or logged by the framework itself
- Credentials discovered by Hydra or Sqlmap are written to output files — users must handle them according to their organization's data classification policy

### 14.3 Logging

- Logs are written to the output directory only
- No system-wide logging (syslog, journald) without explicit configuration
- Timestamps are included in all log entries

### 14.4 Responsible Disclosure

- The tool is intended for **authorized** penetration testing only
- The project documentation includes a clear acceptable use policy
- The `--help` output displays: *"For authorized security testing only"*

---

## 15. Error Handling & Resilience

### 15.1 Error Categories

| Category | Example | Behavior |
|----------|---------|----------|
| **Missing dependency** | Tool not installed | Pre-flight check fails, exit code 2 |
| **Tool execution failure** | Sqlmap crashes mid-scan | Log error, continue to next tool |
| **Timeout** | Nuclei scan exceeds 600s | Kill process, log timeout, continue |
| **Network error** | Target unreachable | Log error, continue with next phase |
| **Permission error** | Cannot write to output dir | Exit with error code 3 |

### 15.2 Error Handling Logic

```
For each tool execution:
  1. Run command with timeout via subprocess.run(timeout=...)
  2. If returncode == 0: success, log output
  3. If returncode != 0: log stderr as warning, continue
  4. If subprocess.TimeoutExpired: log "Timed out after Ns", continue
  5. If OSError (missing binary): should be caught by pre-flight check
```

### 15.3 Resilience Guarantees

- A single tool failure **never** aborts the entire pipeline
- Each phase continues even if previous phases had partial failures
- The HTML report is generated regardless of phase success/failure
- At minimum, the report will contain: target name, date, and error messages

---

## 16. Performance Requirements

### 16.1 Execution Time Benchmarks (Estimated)

| Phase | Small Target | Medium Target | Large Target |
|-------|--------------|---------------|--------------|
| Reconnaissance | 2-5 min | 5-15 min | 15-30 min |
| Scanning | 1-3 min | 5-15 min | 15-60 min |
| Web Enumeration | 5-15 min | 15-45 min | 45-120 min |
| Exploitation | 5-20 min | 20-60 min | 60-180 min |
| **Total** | **13-43 min** | **45-135 min** | **135-390 min** |

*Note: Actual times depend on target complexity, network latency, and concurrent threads.*

### 16.2 Resource Usage (Estimated)

| Resource | Idle | Running (3 threads) | Running (10 threads) |
|----------|------|---------------------|----------------------|
| CPU | <1% | 40-70% | 70-95% |
| RAM | 50 MB | 500 MB - 2 GB | 2-4 GB |
| Disk I/O | Minimal | Moderate | High (logging) |
| Network | None | High (scans) | Very High |

---

## 17. Roadmap & Milestones

### 17.1 Version Roadmap

```
v1.0.0 [Current] — Core Pipeline
├── 15 integrated tools
├── 4-phase pipeline
├── Phase-skip flags
├── HTML reporting
├── Launchpad PPA distribution
└── Error handling & timeouts

v1.1.0 — Enhanced Reporting & Usability
├── JSON summary output
├── CVSS scoring integration
├── Severity color coding in reports
├── Multi-target support (-f targets.txt)
└── Progress bar for long-running phases

v1.2.0 — Expanded Coverage
├── API endpoint discovery (Arjun)
├── GraphQL introspection testing (InQL)
├── JWT token analysis
├── CORS misconfiguration detection
└── WebSocket security testing

v2.0.0 — Advanced Features
├── Screenshot capture (EyeWitness/Gowitness)
├── Credential validation (CrackMapExec)
├── BeEF hook integration
├── Real-time Slack/Telegram alerting
├── Report diff across multiple scans
└── Dockerized deployment
```

### 17.2 Release Milestones

| Milestone | Date | Deliverable |
|-----------|------|-------------|
| M1 — Core Pipeline | Week 1 | Python script with all 4 phases |
| M2 — Error Handling | Week 2 | Timeout, error capture, graceful degradation |
| M3 — Reporting | Week 3 | HTML report generation |
| M4 — Packaging | Week 4 | .deb build + Launchpad PPA upload |
| M5 — Documentation | Week 5 | README, man page, usage examples |
| M6 — Testing | Week 6 | Full test against authorized targets |
| M7 — v1.0.0 Release | Week 7 | Public PPA release |

---

## 18. Testing Strategy

### 18.1 Unit Testing

| Component | Test Case | Expected Result |
|-----------|-----------|-----------------|
| `run_cmd()` | Valid command | Returns stdout |
| `run_cmd()` | Invalid command | Returns error string |
| `run_cmd()` | Timeout scenario | Returns timeout message |
| `check_tools()` | All tools installed | Returns True |
| `check_tools()` | One tool missing | Prints error, exits |
| `ensure_dir()` | Directory exists | No error |
| `ensure_dir()` | New directory | Creates directory |

### 18.2 Integration Testing

| Test | Scenario |
|------|----------|
| Full pipeline | Run against a deliberately vulnerable VM (DVWA, HackTheBox) |
| Phase skip | Run with each `--skip-*` flag individually and combined |
| Missing tool | Uninstall one tool, verify graceful error |
| No open ports | Target with firewall blocking all ports |
| WordPress detection | Target running WordPress → verify WPScan triggers |

### 18.3 Test Targets (Authorized)

| Target | Type | Expected Findings |
|--------|------|-------------------|
| DVWA (localhost) | Deliberately vulnerable web app | SQLi, XSS, command injection |
| HackTheBox / TryHackMe | CTF-style machines | Varies by box |
| Custom test server | Honeypot with known vulns | Matches against expected CVEs |

### 18.4 Acceptance Criteria

1. `autowebpnt -d <test-target>` completes all 4 phases without fatal error
2. HTML report is generated and contains all phase outputs
3. Each `--skip-*` flag correctly suppresses its phase
4. Missing tool dependency produces a clear error message
5. Package installs cleanly via `apt` on a fresh Kali instance

---

## 19. Limitations & Known Constraints

### 19.1 Technical Constraints

1. **Python 3.8+ only** — Uses `subprocess.run` features not available in older Python
2. **Kali Linux only** — Tool paths and wordlist locations assume Kali defaults
3. **Internet required** — Multiple tools (Amass, Sublist3r, Nuclei) need internet access
4. **No stealth/evasion** — Tools run with default aggressive settings; noisy on wire
5. **No rate limiting** — Hydra can lock out accounts; users must use caution
6. **Single target only** — v1.0 processes one domain at a time

### 19.2 Functional Limitations

1. **WordPress-centric conditional logic** — Only WPScan is conditionally triggered; other CMS tools (JoomScan, Droopescan) are not integrated in v1.0
2. **No post-exploitation** — Framework stops at credential extraction; no lateral movement
3. **No false positive validation** — Reported findings are raw tool output, not verified
4. **Basic HTML report** — No interactive filtering, charting, or drill-down in v1.0
5. **No authenticated scanning** — Tools run without session cookies or API tokens

---

## 20. Appendices

### Appendix A: Complete Command Reference

```bash
# Full assessment
autowebpnt -d target.com -o ./results

# Recon + Scan only (no web or exploit)
autowebpnt -d target.com --skip-web --skip-exploit

# Web + Exploit only (skip recon and scanning)
autowebpnt -d target.com --skip-recon --skip-scan

# Custom output directory with more threads
autowebpnt -d target.com -o ~/engagements/client1 --threads 5

# Quick smoke test (skip everything except recon)
autowebpnt -d target.com --skip-scan --skip-web --skip-exploit
```

### Appendix B: Dependencies (All apt packages)

```
python3 (>= 3.8)
amass
sublist3r
theharvester
dnsrecon
whatweb
rustscan
nmap
gobuster
ffuf
dirsearch
nikto
wpscan
nuclei
sqlmap
xsstrike
commix
hydra
hashcat
john
```

Recommended (optional): `seclists`, `dirbuster`, `wordlists`

### Appendix C: Wordlist Paths

| Wordlist | Path | Source Package |
|----------|------|---------------|
| Directory (small) | `/usr/share/wordlists/dirb/common.txt` | `dirb` |
| Directory (medium) | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | `dirbuster` |
| Subdomains | `/usr/share/wordlists/amass/subdomains.lst` | `amass` |
| Passwords | `/usr/share/wordlists/rockyou.txt` | `wordlists` |
| Usernames | `/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt` | `seclists` |

### Appendix D: Environment Variables (Future)

| Variable | Purpose | Default |
|----------|---------|---------|
| `AUTOWEBPNT_THREADS` | Default thread count | `3` |
| `AUTOWEBPNT_TIMEOUT` | Default tool timeout (seconds) | `900` |
| `AUTOWEBPNT_WORDLIST_DIR` | Custom wordlist directory | `/usr/share/wordlists/` |
| `AUTOWEBPNT_OUTPUT_DIR` | Default output path | `./autowebpnt_output` |

### Appendix E: Glossary

| Term | Definition |
|------|------------|
| **Phase** | A logical group of related tools (Recon, Scanning, Web Enum, Exploit) |
| **Pipeline** | The complete ordered execution of all phases |
| **Orchestrator** | The Python script that manages tool execution |
| **Pre-flight check** | Startup verification that all dependencies are installed |
| **NSE** | Nmap Scripting Engine |
| **VHOST** | Virtual host (name-based hosting on a single IP) |

---

## Document Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | 2026-07-18 | Security Team | Initial draft |
| 0.2 | 2026-07-19 | Security Team | Added architecture diagrams, tool matrix |
| 1.0 | 2026-07-20 | Security Team | Finalized for v1.0 development |

---

**End of PRD — autoWebPeNT v1.0.0**

---

This PRD is ready to drive development. Want me to now build the **project repository** with all the files — `setup.py`, `debian/` packaging, `README.md`, `LICENSE`, CI/CD pipeline (GitHub Actions), and the fully working Python script — all structured as a real open-source project you can push to GitHub and connect to Launchpad?