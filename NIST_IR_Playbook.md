# 📋 NIST IR PLAYBOOK — PHISHING INCIDENT RESPONSE
### Based on NIST SP 800-61r2: Computer Security Incident Handling Guide

---

> **Classification:** SOC Internal — Unrestricted Lab Use  
> **Version:** 1.0  
> **Author:** Azaldo Mazibuko — SOC Analyst  
> **Last Updated:** 2026-05-21  
> **Applies To:** All phishing email incidents flagged by SIEM or user reports  

---

## 🗺️ NIST IR LIFECYCLE OVERVIEW

```
┌─────────────────┐    ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PHASE 1       │ ─► │   PHASE 2       │ ─► │   PHASE 3 & 4    │ ─► │   PHASE 5       │
│   Preparation   │    │   Detection &   │    │   Containment,   │    │  Post-Incident  │
│                 │    │   Analysis      │    │   Eradication &  │    │  Activity       │
│                 │    │                 │    │   Recovery       │    │                 │
└─────────────────┘    └─────────────────┘    └──────────────────┘    └─────────────────┘
```

---

## PHASE 1 — PREPARATION

> *"An organization's ability to respond to an incident is directly tied to how well it prepared before the incident occurred."*

### 1.1 Tools & Infrastructure (Pre-Configured)

| Tool             | Purpose                                    | Status       |
|------------------|--------------------------------------------|--------------|
| **Splunk SIEM**  | Log ingestion, detection rules, dashboards | ✅ Active    |
| **Shuffle SOAR** | Automated triage pipeline                  | ✅ Active    |
| **Python Script**| IOC enrichment (`ioc_enrichment.py`)       | ✅ Ready     |
| **VirusTotal**   | IP/URL/hash threat intelligence            | ✅ API Key   |
| **AbuseIPDB**    | IP reputation scoring                      | ✅ API Key   |
| **URLScan.io**   | URL submission and analysis                | ✅ API Key   |
| **Sysmon**       | Windows endpoint telemetry                 | ✅ Active    |

### 1.2 Detection Rules Pre-Built in Splunk

1. **PHI-2026-001** — Phishing Email Detected (SPF/DKIM/DMARC failure)
2. **PHI-2026-002** — Repeat Phishing Source (2+ attempts from same IP = HIGH)

### 1.3 Communication Contacts

| Role                  | Responsibility                          |
|-----------------------|-----------------------------------------|
| Tier 1 SOC Analyst    | Initial triage, IOC extraction          |
| Tier 2 SOC Analyst    | Deep-dive analysis, attribution         |
| IR Team Lead          | Escalation decisions, executive comms   |
| Email Admin           | Mail gateway quarantine & blocking      |
| Network Admin         | Firewall rule updates                   |
| Legal/Compliance      | Data breach notification requirements   |

---

## PHASE 2 — DETECTION & ANALYSIS

### 2.1 Detection Sources

Phishing incidents can be detected through the following vectors:

- ✅ **Splunk SIEM Alert** — Automated rule fires on mail log anomalies
- ✅ **Shuffle SOAR** — Webhook triggered, automated VirusTotal query initiated
- 📞 **User Report** — Employee forwards suspicious email to `security@company.com`
- 📧 **Email Gateway** — Mail filter flags message as high-risk

### 2.2 Initial Triage Checklist (Tier 1 — Target: < 15 minutes)

```
[ ] 1. Acknowledge the Splunk alert — assign case ID (format: PHI-YYYY-NNN)
[ ] 2. Confirm the alert is NOT a false positive (check: is this a known newsletter?)
[ ] 3. Identify the sender address and domain
[ ] 4. Check SPF / DKIM / DMARC status in the mail logs
[ ] 5. Extract all IOCs: sender IP, sender domain, embedded URLs
[ ] 6. Run ioc_enrichment.py against extracted IOCs
[ ] 7. Check SOAR execution — did Shuffle successfully query VirusTotal?
[ ] 8. Determine scope: how many recipients received this email?
[ ] 9. Determine impact: did any user click the link or provide credentials?
[ ] 10. Set severity level:
        - LOW: Blocked by gateway, no user interaction
        - MEDIUM: Delivered but no clicks confirmed
        - HIGH: User clicked link or credentials potentially harvested
        - CRITICAL: Confirmed credential theft or malware execution
```

### 2.3 IOC Extraction Process

**Automated (via SOAR pipeline):**
```
Splunk Alert → Shuffle Webhook → VirusTotal Query → Result logged
```

**Manual (via Python script):**
```bash
python ioc_enrichment.py
# Enter IP, URL, or hash when prompted
# Output saved to: ioc_report.json
```

**Key fields to extract from email headers:**
```
Received: from [ATTACKER_IP]
From: "Display Name" <sender@domain.xyz>
Reply-To: attacker@different-domain.com
Authentication-Results: spf=FAIL; dkim=NONE; dmarc=FAIL
X-Mailer: [mail client - can reveal attacker tooling]
```

### 2.4 Severity Assessment Matrix

| Factor                          | LOW    | MEDIUM    | HIGH      | CRITICAL    |
|---------------------------------|--------|-----------|-----------|-------------|
| Auth failures (SPF/DKIM/DMARC)  | 0      | 1         | 2         | 3           |
| Users targeted                  | 1      | 2-5       | 6-20      | 20+         |
| Confirmed link clicks           | 0      | 0         | 1+        | 1+          |
| Credentials confirmed stolen    | No     | No        | Unknown   | Yes         |
| Malware detected                | No     | No        | Suspected | Confirmed   |

---

## PHASE 3 — CONTAINMENT

### 3.1 Short-Term Containment (Within 1 hour)

```
[ ] 1. QUARANTINE: Ask email admin to remove/quarantine the phishing email 
        from ALL mailboxes (not just the reporter's)
[ ] 2. ISOLATE: If any user clicked the link:
        - Disconnect their machine from the network immediately
        - Preserve disk image before any remediation
[ ] 3. BLOCK (Firewall): Submit the following to the network team:
        - Attacker source IPs
        - Phishing hosting IPs
[ ] 4. BLOCK (DNS): Submit phishing domains to the DNS/proxy filter team:
        - Sender domains
        - Lookalike/typosquat domains
        - Embedded URL domains
[ ] 5. RESET: If credentials may have been harvested:
        - Force password reset for all targeted users
        - Revoke active sessions (SSO/OAuth tokens)
        - Enable MFA if not already enabled
```

### 3.2 Long-Term Containment

```
[ ] Update Splunk detection rule with new IOC signatures
[ ] Add sender IP and domain to threat intelligence feed blocklist
[ ] Update email gateway rules to block similar sender patterns
[ ] Notify other SOC teams / ISAC partners if campaign appears coordinated
```

### 3.3 Evidence Preservation

All evidence must be preserved **before** any remediation actions:

| Evidence Type      | Location                              | Retention   |
|--------------------|---------------------------------------|-------------|
| Original `.eml`    | `Phishing-IR-Lab/artifacts/`          | 90 days     |
| IOC Report JSON    | `Phishing-IR-Lab/ioc_report.json`     | 90 days     |
| Splunk Logs        | `index=main source="phishing_mail.log"` | 90 days  |
| SOAR Execution Log | Shuffle Dashboard → Executions        | 30 days     |
| Disk Image         | Secure evidence storage (if endpoint)  | 1 year     |

---

## PHASE 4 — ERADICATION & RECOVERY

### 4.1 Eradication Steps

```
[ ] 1. Confirm ALL copies of the phishing email have been removed from all mailboxes
[ ] 2. Confirm phishing URLs are blocked at all gateway layers (firewall, DNS, proxy)
[ ] 3. Scan the affected user's machine for malware (if link was clicked)
        - Run full AV/EDR scan
        - Check for persistence mechanisms (scheduled tasks, registry run keys)
        - Review Sysmon logs for suspicious process execution post-click
[ ] 4. Check for any unauthorized account access (SSO logs, Azure AD sign-in logs)
[ ] 5. Report phishing domain to registrar and hosting provider for takedown
```

### 4.2 Recovery Steps

```
[ ] 1. Return isolated machine(s) to production after clean scan
[ ] 2. Restore any affected services
[ ] 3. Confirm business operations have resumed normally
[ ] 4. Monitor for 72 hours post-recovery for any re-infection indicators
```

---

## PHASE 5 — POST-INCIDENT ACTIVITY

### 5.1 Metrics to Record

| Metric                           | Value (PHI-2026-001) |
|----------------------------------|----------------------|
| Time to Detect                   | < 1 second (SIEM)   |
| Time to Initial Triage           | 15 minutes           |
| Time to Containment              | 30 minutes           |
| Time to Full Resolution          | 8 days (full lab)    |
| Number of Users Targeted         | 3                    |
| Number of Confirmed Compromises  | 0                    |
| IOCs Identified                  | 5                    |
| Automated Enrichments (SOAR)     | 1 (VirusTotal)       |

### 5.2 Lessons Learned Meeting Agenda

1. What happened? (Brief incident summary)
2. What did we do well? (Detection speed, automation)
3. What could we improve? (Process gaps)
4. What rule/control changes do we need? (SIEM, gateway)
5. Action items with owners and deadlines

### 5.3 Playbook Improvements Identified

Based on PHI-2026-001, the following improvements are recommended:

- ✅ Add AbuseIPDB score to automated SOAR enrichment
- ✅ Add email domain WHOIS lookup to enrichment pipeline
- 🔲 Integrate Microsoft Defender ATP alerts into Splunk
- 🔲 Build Shuffle node to auto-create Jira/ServiceNow ticket on detection
- 🔲 Add auto-email notification to targeted users when phishing is detected

---

## APPENDIX A — SPL DETECTION QUERIES

### Query 1: Phishing Email Detection
```spl
source="phishing_mail.log" (DMARC_FAIL OR SPF_FAIL OR "category=phishing")
| rex "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "sender=(?<sender>\S+)"
| rex "recipient=(?<recipient>\S+@\S+)"
| table _time, src_ip, sender, recipient
| sort -_time
```

### Query 2: Repeat Attacker Detection
```spl
source="phishing_mail.log" "category=phishing"
| rex field=_raw "src_ip=(?<src_ip>[^\s,]+)"
| stats count as phishing_attempts by src_ip
| where phishing_attempts >= 2
| eval threat_level="HIGH"
```

### Query 3: Targeted User Analysis
```spl
index=main host="mailserver01" "category=phishing"
| rex "recipient=(?<recipient>\S+)"
| stats count by recipient
| sort -count
```

---

## APPENDIX B — MITRE ATT&CK REFERENCE

| Phase             | ID            | Name                                     | Mitigation                  |
|-------------------|---------------|------------------------------------------|-----------------------------|
| Initial Access    | T1566.001     | Phishing: Spearphishing Link             | Email filtering, MFA        |
| Credential Access | T1078         | Valid Accounts                           | MFA, PAM, Zero Trust        |
| Defense Evasion   | T1036         | Masquerading                             | Domain monitoring, DMARC    |
| Defense Evasion   | T1027         | Obfuscated Files or Info                 | URL inspection, sandboxing  |
| Collection        | T1056         | Input Capture                            | Browser isolation           |

---

## APPENDIX C — QUICK REFERENCE CONTACTS

| Escalation Need              | Contact                    |
|------------------------------|----------------------------|
| Email quarantine/block       | Email Admin (`emailadmin@company.com`) |
| Firewall rule update         | Network Ops (`netops@company.com`)     |
| Endpoint isolation           | IT Help Desk               |
| Legal/breach notification    | Legal (`legal@company.com`)            |
| Executive notification       | IR Team Lead               |

---

*Playbook Version: 1.0 | NIST SP 800-61r2 Aligned*  
*Next Review Date: 2026-08-21*  
*Classification: Internal SOC Use Only*
