# Phishing Analysis & Incident Response Lab

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1566-red)](https://attack.mitre.org/techniques/T1566/)
[![NIST IR](https://img.shields.io/badge/NIST-SP%20800--61r2-blue)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
[![Python](https://img.shields.io/badge/Python-3.10+-green)](https://www.python.org/)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise-orange)](https://www.splunk.com/)

> End-to-end SOC workflow: detect phishing in Splunk, enrich IOCs with threat intel APIs, triage on a live Flask dashboard, automate response with Shuffle SOAR — mapped to **MITRE ATT&CK** and **NIST SP 800-61r2**.

**Author:** Azaldo Mazibuko · Portfolio Project 3 · Target roles: SOC Analyst / Junior Cloud Security

---

## Table of contents

- [What this lab proves](#what-this-lab-proves)
- [Architecture](#architecture)
- [Documentation gallery (step-by-step)](#documentation-gallery-step-by-step)
- [Demo video](#demo-video)
- [Quick start](#quick-start)
- [Repository structure](#repository-structure)
- [Case study: PHI-2026 campaign](#case-study-phi-2026-campaign)
- [MITRE ATT&CK mapping](#mitre-attck-mapping)
- [Splunk detection (SPL)](#splunk-detection-spl)
- [Related documentation](#related-documentation)
- [Portfolio context](#portfolio-context)

---

## What this lab proves

| Capability | Evidence |
|------------|----------|
| SIEM detection & dashboards | Splunk ingest of `phishing_mail.log`, SPL rules, scheduled alerts |
| Manual phishing analysis | .eml header review (SPF/DKIM/DMARC), IOC spreadsheet |
| Threat intel automation | `ioc_enrichment.py` + Flask **Live Triage** (VT, AbuseIPDB, URLScan) |
| SOAR orchestration | Shuffle webhook on HIGH severity |
| IR documentation | `incident_report.md`, `NIST_IR_Playbook.md`, SOC triage playbook |
| Emerging threats | Quishing (QR phishing) scenario + detection notes |
| SOC dashboard | Flask app fed by **real log data** (`log_parser.py`) |

---

## Architecture

```
┌──────────────────┐     ┌─────────────────┐     ┌──────────────────────┐
│ phishing_mail.log│────►│ Splunk Enterprise│────►│ Alert PHI-2026-001   │
│ (+ .eml samples) │     │ SPL + dashboards │     │ (scheduled / email)  │
└────────┬─────────┘     └────────┬────────┘     └──────────┬───────────┘
         │                        │                          │
         │                        ▼                          ▼
         │               ┌─────────────────┐        ┌─────────────────┐
         └──────────────►│ Flask SOC Console│        │ Shuffle SOAR     │
                         │ /  /case /triage │        │ webhook → enrich │
                         └────────┬────────┘        └─────────────────┘
                                  │
                         ┌────────▼────────┐
                         │ enrichment.py   │
                         │ VT · AbuseIPDB  │
                         │ · URLScan.io    │
                         └────────┬────────┘
                                  ▼
                         ┌─────────────────┐
                         │ ioc_report.json │
                         │ incident_report │
                         └─────────────────┘
```

---

## Documentation gallery (step-by-step)

Screenshots are organized in [`screenshots/STEP BY STEP/`](screenshots/STEP%20BY%20STEP/) (numbered `01`–`20`). Full index: [`screenshots/README.md`](screenshots/README.md).

### Phase 1 — Lab environment

| Step | Screenshot | Description |
|------|------------|-------------|
| 01 | ![01](screenshots/STEP%20BY%20STEP/01-virtualbox-lab-setup.png) | VirtualBox lab setup |
| 02 | ![02](screenshots/STEP%20BY%20STEP/02-environment-splunk-host.png) | Splunk / host environment |

### Phase 2 — Phishing analysis

| Step | Screenshot | Description |
|------|------------|-------------|
| 03 | ![03](screenshots/STEP%20BY%20STEP/03-phishing-eml-sample.png) | Phishing .eml sample |
| 04 | ![04](screenshots/STEP%20BY%20STEP/04-email-header-analysis.png) | SPF / DKIM / DMARC analysis |
| 05 | ![05](screenshots/STEP%20BY%20STEP/05-ioc-extraction-spreadsheet.png) | IOC extraction spreadsheet |

### Phase 3 — Splunk SIEM

| Step | Screenshot | Description |
|------|------------|-------------|
| 06 | ![06](screenshots/STEP%20BY%20STEP/06-splunk-ingest-mailserver01.png) | Ingest — host `mailserver01` |
| 07 | ![07](screenshots/STEP%20BY%20STEP/07-splunk-phishing-log-search.png) | Search mail logs |
| 08 | ![08](screenshots/STEP%20BY%20STEP/08-splunk-spl-detection-table.png) | SPL detection table |
| 09 | ![09](screenshots/STEP%20BY%20STEP/09-splunk-save-as-alert.png) | Save as alert |
| 10 | ![10](screenshots/STEP%20BY%20STEP/10-splunk-alert-email-action.png) | Alert email action |
| 11 | ![11](screenshots/STEP%20BY%20STEP/11-splunk-stats-by-recipient.png) | Stats by recipient |
| 12 | ![12](screenshots/STEP%20BY%20STEP/12-splunk-stats-by-src-ip.png) | Stats by attacker IP |
| 13 | ![13](screenshots/STEP%20BY%20STEP/13-splunk-repeat-phishing-alert.png) | Repeat phishing source alert |

### Phase 4 — IOC enrichment (Python)

| Step | Screenshot | Description |
|------|------------|-------------|
| 14 | ![14](screenshots/STEP%20BY%20STEP/14-python-ioc-enrichment-code.png) | `ioc_enrichment.py` |
| 15 | ![15](screenshots/STEP%20BY%20STEP/15-terminal-enrichment-run.png) | Enrichment engine running |
| 16 | ![16](screenshots/STEP%20BY%20STEP/16-ioc-enrichment-summary.png) | Summary output |

### Phase 5 — Shuffle SOAR

| Step | Screenshot | Description |
|------|------------|-------------|
| 17 | ![17](screenshots/STEP%20BY%20STEP/17-shuffle-soar-overview.png) | Shuffle workflow overview |
| 18 | ![18](screenshots/STEP%20BY%20STEP/18-shuffle-workflow-build.png) | Workflow build |
| 19 | ![19](screenshots/STEP%20BY%20STEP/19-shuffle-webhook-execution.png) | Webhook execution |

### Phase 6 — Quishing

| Step | Screenshot | Description |
|------|------------|-------------|
| 20 | ![20](screenshots/STEP%20BY%20STEP/20-quishing-qr-lure.png) | QR phishing lure (`samples/quishing_lure.png`) |

### Phase 7 — Flask SOC dashboard

| Step | Screenshot | Description |
|------|------------|-------------|
| 21 | ![21](screenshots/STEP%20BY%20STEP/21-flask-soc-dashboard.png) | SOC console — live stats from `phishing_mail.log` |
| 22 | ![22](screenshots/STEP%20BY%20STEP/22-flask-live-triage.png) | Live IOC triage (VT / AbuseIPDB / URLScan) |
| 23 | ![23](screenshots/STEP%20BY%20STEP/23-flask-case-detail.png) | Case detail — PHI-2026-004 quishing |

Additional Splunk / Shuffle / terminal images remain in their topic folders under [`screenshots/`](screenshots/).

---

## Demo video

Full lab walkthrough (~44 MB):

**[Download / watch: `media/phishing-ir-lab-demo.mp4`](media/phishing-ir-lab-demo.mp4)**

```powershell
# Play locally (Windows)
start media\phishing-ir-lab-demo.mp4
```

> **GitHub tip:** Files over 100 MB are rejected. This video is ~44 MB and is fine for a normal push. For larger recordings, use [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github) or Git LFS.

---

## Quick start

### Prerequisites

- Windows 10/11 (lab built on ASUS VivoBook, 8 GB RAM)
- Python 3.10+
- Splunk Enterprise (local, port 8000) — optional for SIEM section
- API keys: [VirusTotal](https://www.virustotal.com/), [AbuseIPDB](https://www.abuseipdb.com/), [URLScan.io](https://urlscan.io/)

### Install

```powershell
cd Phishing-IR-Lab
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Edit .env with your API keys
```

### Run Flask SOC console

```powershell
python app.py
```

| URL | Page |
|-----|------|
| http://127.0.0.1:5000/ | Dashboard (parsed from `phishing_mail.log`) |
| http://127.0.0.1:5000/triage | Live IOC enrichment |
| http://127.0.0.1:5000/case/PHI-2026-001 | Case detail |

### Run CLI enrichment

```powershell
python ioc_enrichment.py
# Output: ioc_report.json
```

### Generate quishing QR

```powershell
python scripts\generate_quishing_qr.py
# Output: samples/quishing_lure.png
```

### Re-organize screenshots

```powershell
.\scripts\organize_screenshots.ps1
```

---

## Repository structure

```
Phishing-IR-Lab/
├── app.py                      # Flask SOC dashboard
├── log_parser.py               # Parses phishing_mail.log → cases/events
├── enrichment.py               # Shared VT / AbuseIPDB / URLScan logic
├── ioc_enrichment.py           # CLI wrapper
├── phishing_mail.log           # Simulated mail server telemetry
├── incident_report.md          # NIST-aligned IR report (PHI-2026-001)
├── NIST_IR_Playbook.md         # Full IR lifecycle playbook
├── requirements.txt
├── .env.example
├── templates/                  # Flask HTML (dark SOC UI)
├── docs/
│   ├── SOC_Phishing_Triage_Playbook.md
│   └── QUISHING.md
├── scripts/
│   ├── generate_quishing_qr.py
│   └── organize_screenshots.ps1
├── samples/
│   └── quishing_lure.png
├── screenshots/                # Portfolio evidence (see README inside)
│   └── STEP BY STEP/           # 01–20 numbered build timeline
└── media/                      # Demo video (phishing-ir-lab-demo.mp4)
```

---

## Case study: PHI-2026 campaign

| Field | Value |
|-------|-------|
| **Campaign window** | 2026-05-13 20:27–20:35 UTC |
| **Attacker IP** | `103.14.120.67` |
| **Payload host** | `185.199.108.153` |
| **Phishing URL** | `http://185.199.108.153/owa/auth/logon.aspx` |
| **Sender** | `badguy@malicious-sender.xyz` |
| **Victims** | john.doe, jane.smith, bob.wilson, finance@company.com |
| **Auth** | SPF fail · DKIM none · DMARC fail |
| **Cases** | PHI-2026-001 … 004 (004 = quishing) |

---

## MITRE ATT&CK mapping

| ID | Technique | Lab evidence |
|----|-----------|--------------|
| T1566.001 | Spearphishing Attachment | Documented scenario / playbook |
| T1566.002 | Spearphishing Link | URL in mail logs, Splunk SPL |
| T1204.002 | User Execution: Malicious File | Quishing QR scan path |
| T1078 | Valid Accounts | Credential harvest goal (OWA lure) |
| T1534 | Internal Spearphishing | BEC scenario in playbook |
| T1657 | Financial theft | BEC / wire fraud scenario |

---

## Splunk detection (SPL)

**Phishing + auth failures:**

```spl
source="phishing_mail.log" (DMARC_FAIL OR SPF_FAIL OR category=phishing OR category=quishing)
| rex "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "sender=(?<sender>\S+)"
| rex "recipient=(?<recipient>\S+)"
| table _time, src_ip, sender, recipient, category
| sort -_time
```

**Repeat attacker IP:**

```spl
source="phishing_mail.log" "category=phishing"
| rex "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as hits by src_ip
| where hits >= 2
```

---

## Related documentation

| Document | Purpose |
|----------|---------|
| [`incident_report.md`](incident_report.md) | Closed case write-up |
| [`NIST_IR_Playbook.md`](NIST_IR_Playbook.md) | Full NIST IR phases |
| [`docs/SOC_Phishing_Triage_Playbook.md`](docs/SOC_Phishing_Triage_Playbook.md) | 1-page triage decision tree |
| [`docs/QUISHING.md`](docs/QUISHING.md) | QR phishing detection |

---

## Portfolio context

This is **Project 3** in a cybersecurity portfolio:

1. **Splunk SOC Detection Lab** — on-prem attacks (Metasploit, Mimikatz, Sysmon)
2. **Azure SOC Lab** — Sentinel, KQL, Logic Apps automation
3. **Phishing IR Lab** (this repo) — email threats, IOC enrichment, SOAR, Flask triage

---

## License & disclaimer

Educational / portfolio use only. Simulated logs and IOCs. Do not commit `.env` or live API keys. Malicious URLs and IPs are lab artifacts — never visit phishing URLs outside an isolated analysis environment.

---

*Built with Splunk · Python · Flask · Shuffle · MITRE ATT&CK · NIST SP 800-61r2*
