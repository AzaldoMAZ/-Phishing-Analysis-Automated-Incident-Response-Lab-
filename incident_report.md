# 🛡️ INCIDENT REPORT — PHISHING EMAIL CAMPAIGN
---

## CASE INFORMATION

| Field               | Details                                        |
|---------------------|------------------------------------------------|
| **Case ID**         | PHI-2026-001                                   |
| **Severity**        | 🔴 HIGH                                        |
| **Status**          | ✅ CLOSED — Contained                          |
| **Date Reported**   | 2026-05-13                                     |
| **Date Resolved**   | 2026-05-21                                     |
| **Analyst**         | Azaldo Mazibuko — SOC Analyst                  |
| **Classification**  | Phishing / Credential Harvesting               |
| **MITRE Technique** | T1566.001 — Spearphishing Link                 |
| **NIST IR Phase**   | Post-Incident Activity (Phase 5 Complete)      |

---

## 1. EXECUTIVE SUMMARY

On 13 May 2026, a targeted phishing campaign was detected against employees at **company.com**. The attacker impersonated the Microsoft IT Service Desk using a lookalike domain (`microsoft-support.com`) and directed victims to a credential-harvesting page hosted at `185.199.108.153`.

The email failed all three standard authentication checks (SPF, DKIM, DMARC). The incident was detected automatically via a **Splunk SIEM detection rule**, triaged using a custom **Python IOC Enrichment script** querying VirusTotal, AbuseIPDB, and URLScan.io, and the response was **automated via a Shuffle SOAR webhook pipeline**.

No user credentials were confirmed compromised. All phishing infrastructure was identified, documented, and IOC blocklists were updated.

---

## 2. TIMELINE OF EVENTS

| Time (UTC)       | Event                                                                  | Phase        |
|------------------|------------------------------------------------------------------------|--------------|
| 08:29:00 May 13  | Phishing email sent from `badguy@malicious-sender.xyz`                 | Detection    |
| 08:30:15 May 13  | Email relayed through `103.14.120.67` (India) — delivered to targets   | Detection    |
| 08:30:16 May 13  | **Splunk SIEM alert triggered** — `PHI-2026-001: Phishing Email Detected` | Detection  |
| 08:30:17 May 13  | **Shuffle SOAR webhook fires** — automated triage initiated            | Analysis     |
| 08:30:18 May 13  | **VirusTotal queried automatically** for `103.14.120.67`               | Analysis     |
| 14:29:00 May 13  | SOC analyst reviewed `.eml` artifact manually                          | Analysis     |
| 14:31:00 May 13  | Manual header analysis completed — SPF/DKIM/DMARC failures confirmed   | Analysis     |
| 14:35:00 May 13  | `ioc_enrichment.py` executed — IOCs queried across 3 threat platforms  | Analysis     |
| 14:36:00 May 13  | `ioc_report.json` generated and saved to evidence directory            | Containment  |
| 14:38:00 May 13  | URLScan.io confirmed phishing URL resolves to 404 (infrastructure down)| Containment  |
| 14:45:00 May 13  | Splunk "Phishing Incident Command Center" dashboard reviewed           | Post-Incident|
| 2026-05-21       | SOAR pipeline validated — Splunk-to-Shuffle-to-VirusTotal confirmed    | Post-Incident|
| 2026-05-21       | Final incident report filed — case closed                              | Post-Incident|

---

## 3. AFFECTED ASSETS

| Asset                     | Type          | Impact                         |
|---------------------------|---------------|--------------------------------|
| `finance@company.com`     | Email Account | Targeted — No confirmed breach |
| `bob.wilson@company.com`  | Email Account | Targeted — No confirmed breach |
| `jane.smith@company.com`  | Email Account | Targeted — No confirmed breach |
| `john.doe@company.com`    | Email Account | Targeted — No confirmed breach |
| `mx.company.com`          | Mail Server   | Received spoofed email         |

---

## 4. ATTACK ANALYSIS

### 4.1 — Email Header Findings

The attacker crafted a spoofed email designed to appear as an internal Microsoft notification. Key technical findings from the headers:

- **SPF: FAIL** — The sending IP `103.14.120.67` is not an authorized sender for `malicious-sender.xyz`
- **DKIM: NONE** — No DKIM signature was present; the email was not cryptographically verified
- **DMARC: FAIL** — The domain `microsoft-support.com` failed the DMARC policy check

> 💡 **Analyst Note:** A triple authentication failure (SPF + DKIM + DMARC) is the strongest technical indicator of a spoofed/phishing email. All three failing simultaneously is highly indicative of malicious intent, not misconfiguration.

### 4.2 — Social Engineering Tactics

| Tactic          | How It Was Used                                              |
|-----------------|--------------------------------------------------------------|
| **Authority**   | Impersonated "IT Service Desk" — a trusted internal figure   |
| **Urgency**     | "Password expires in 2 hours"                                |
| **Fear**        | "Failure to verify will result in immediate lockout"         |
| **Legitimacy**  | Used Microsoft branding and OWA-style URL path               |

### 4.3 — Phishing Link Analysis

The embedded link used a **bare IP address** instead of a domain — a common evasion technique to bypass domain-based blocklists.

```
Display text : "Verify Account Now"
Actual URL   : http://185.199.108.153/owa/auth/logon.aspx
IP Owner     : FASTLY CDN / GitHub Pages infrastructure
Status       : 404 Not Found (infrastructure taken offline or URL rotated)
```

> 💡 **Analyst Note:** Attackers frequently use legitimate CDN/hosting infrastructure (GitHub Pages, Cloudflare) to host phishing pages. This makes IP-level blocking difficult as the same IP serves thousands of legitimate sites.

---

## 5. INDICATORS OF COMPROMISE (IOCs)

> These were added to the Splunk SIEM blocklist and shared with the threat intel team.

| IOC                                              | Type       | Source              | Verdict                |
|--------------------------------------------------|------------|---------------------|------------------------|
| `103.14.120.67`                                  | IP Address | Email Headers       | ⚠️ Suspicious (relay)  |
| `185.199.108.153`                                | IP Address | Phishing URL        | ⚠️ Suspicious (hosting)|
| `malicious-sender.xyz`                           | Domain     | Email Headers (SPF) | 🔴 Malicious           |
| `microsoft-support.com`                          | Domain     | From: Header        | 🔴 Lookalike/Typosquat |
| `http://185.199.108.153/owa/auth/logon.aspx`     | URL        | Email Body          | 🔴 Phishing Page       |
| `badguy@malicious-sender.xyz`                    | Email      | Sender Address      | 🔴 Threat Actor        |

---

## 6. MITRE ATT&CK MAPPING

| Phase             | Technique ID  | Technique Name                           |
|-------------------|---------------|------------------------------------------|
| Initial Access    | **T1566.001** | Phishing: Spearphishing Link             |
| Credential Access | **T1078**     | Valid Accounts (intended outcome)        |
| Defense Evasion   | **T1036**     | Masquerading (lookalike domain)          |
| Defense Evasion   | **T1027**     | Obfuscated Files or Info (bare IP URL)   |
| Collection        | **T1056**     | Input Capture (credential harvest page)  |

---

## 7. SIEM DETECTION EVIDENCE

### Splunk Detection Rules Triggered

**Rule 1 — Phishing Email Detected:**
```spl
source="phishing_mail.log" (DMARC_FAIL OR SPF_FAIL OR "category=phishing")
| rex "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "sender=(?<sender>\S+)"
| rex "recipient=(?<recipient>\S+@\S+)"
| table _time, src_ip, sender, recipient
| sort -_time
```

**Rule 2 — Repeat Offender Detection (HIGH Priority):**
```spl
source="phishing_mail.log" "category=phishing"
| rex "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as phishing_attempts by src_ip
| where phishing_attempts >= 2
| eval threat_level="HIGH"
```

**Dashboard:** Phishing Incident Command Center — Splunk `index=main host="mailserver01"`
- Panel 1: Top Targeted Users (Pie Chart — 3 victims identified)
- Panel 2: Attacker IP Distribution (Bar Chart — `103.14.120.67` with 6 attempts)

---

## 8. SOAR AUTOMATION EVIDENCE

### Shuffle Workflow: "Phishing Automated Triage"

| Step | Component     | Action                                        |
|------|---------------|-----------------------------------------------|
| 1    | Splunk Alert  | Fires webhook on phishing detection            |
| 2    | Shuffle Webhook | Receives JSON payload (IP, sender, recipient)|
| 3    | VirusTotal v3 | Automatically queries IP address report       |
| 4    | Result        | Threat intelligence returned in seconds       |

**Webhook URL:** `https://shuffler.io/api/v1/hooks/webhook_1fe4f40c-49e8-47ee-8906-86b31f3cf8ac`

**Test Payload sent from Splunk:**
```json
{
  "result": {
    "src_ip": "103.14.120.67",
    "sender": "badguy@malicious-sender.xyz",
    "recipient": "john.doe@company.com",
    "threat_category": "phishing"
  }
}
```
**Result:** ✅ `success: true` — Execution ID confirmed end-to-end pipeline.

---

## 9. CONTAINMENT & REMEDIATION ACTIONS

### ✅ Completed Actions
- [x] Phishing email isolated and preserved as `.eml` artifact
- [x] All IOCs documented and enriched via VirusTotal, AbuseIPDB, URLScan.io
- [x] IOC report (`ioc_report.json`) generated for SIEM ingestion
- [x] Splunk detection rules created and validated (46 events indexed)
- [x] SOAR automation pipeline built and tested end-to-end
- [x] Phishing Incident Command Center dashboard created in Splunk
- [x] Confirmed no user clicked the link (infrastructure returned 404)

### 📋 Recommended Actions
- [ ] **Block** IP `103.14.120.67` and `185.199.108.153` at perimeter firewall
- [ ] **Block** domains `malicious-sender.xyz` and `microsoft-support.com` at DNS/proxy
- [ ] **Alert** all targeted employees — forward to Security Awareness team
- [ ] **Update** email gateway rules to quarantine SPF+DKIM+DMARC triple failures
- [ ] **Report** `malicious-sender.xyz` to domain registrar for takedown
- [ ] **Enable** Sysmon endpoint telemetry correlation for lateral movement detection

---

## 10. LESSONS LEARNED

1. **Automation is critical at scale** — The SOAR pipeline reduced triage time from ~30 minutes to under 5 seconds for initial IOC enrichment.
2. **Triple auth failure = instant escalation** — SPF + DKIM + DMARC simultaneously failing should be auto-quarantined, not just flagged.
3. **Bare IP URLs are a red flag** — Legitimate services never use raw IPs in email links. This is now a Splunk detection rule.
4. **Finance teams are high-value targets** — Mandatory phishing awareness training is recommended quarterly for all finance personnel.
5. **SIEM dashboards enable rapid situational awareness** — The Splunk dashboard immediately revealed 3 victims, 6 attack attempts, and 1 primary threat actor IP.

---

## 11. ANALYST SIGN-OFF

| Field            | Value                           |
|------------------|---------------------------------|
| **Analyst**      | Azaldo Mazibuko                 |
| **Reviewed By**  | Senior SOC Analyst              |
| **Date Filed**   | 2026-05-21                      |
| **Case Status**  | ✅ CLOSED — Contained           |
| **Tools Used**   | Splunk, Shuffle, VirusTotal, AbuseIPDB, URLScan.io, Python |

---

*This report was generated as part of the Enterprise Phishing Analysis & Incident Response Lab.*  
*MITRE ATT&CK Framework: https://attack.mitre.org/techniques/T1566/*  
*NIST SP 800-61r2: Computer Security Incident Handling Guide*