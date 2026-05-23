# SOC Phishing Triage Playbook
**Version 1.0 · Azaldo Mazibuko · Phishing IR Lab**  
**Scope:** User-reported or SIEM-detected suspicious email · **SLA:** Acknowledge P1 within 15 min

---

## Quick reference — lab IOCs (PHI-2026 campaign)

| IOC | Value |
|-----|-------|
| Attacker relay IP | `103.14.120.67` |
| Payload host | `185.199.108.153` |
| Phishing URL | `http://185.199.108.153/owa/auth/logon.aspx` |
| Sender domain | `malicious-sender.xyz` |
| Lookalike HELO | `microsoft-support.com` |
| Splunk alert | `PHI-2026-001: Phishing Email Detected` |

---

## Decision tree

```
                    ┌─────────────────────────┐
                    │  Alert or user report   │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │ Preserve evidence       │
                    │  · Export .eml          │
                    │  · Screenshot headers   │
                    │  · Note report time     │
                    └───────────┬─────────────┘
                                │
              ┌─────────────────▼─────────────────┐
              │ Did user click link / scan QR /   │
              │ open attachment?                  │
              └─────────┬───────────────┬─────────┘
                     YES               NO
                        │               │
         ┌──────────────▼───┐    ┌──────▼──────────────────┐
         │ P1 — Contain     │    │ Continue triage below   │
         │ · Isolate host     │    └──────┬──────────────────┘
         │ · Force pwd reset  │           │
         │ · Block URL at     │    ┌──────▼──────────────────┐
         │   proxy/firewall   │    │ Header auth check       │
         └──────────────┬─────┘    │ SPF / DKIM / DMARC      │
                        │          └──────┬──────────────────┘
                        │          ┌──────▼──────────────────┐
                        │          │ All three FAIL?         │
                        │          └──┬──────────────┬───────┘
                        │            YES             NO
                        │             │              │
                        │    ┌────────▼────────┐  ┌──▼─────────────┐
                        │    │ Escalate HIGH   │  │ Lower priority │
                        │    │ Extract IOCs    │  │ May be spoof/  │
                        │    └────────┬────────┘  │ marketing FP   │
                        │             │           └────────────────┘
                        │    ┌────────▼────────────────────────┐
                        │    │ QR / image only — no body URL?  │
                        │    └──┬───────────────────────┬──────┘
                        │      YES (QUISHING)          NO
                        │       │                      │
                        │  ┌────▼─────────────┐  ┌─────▼──────────┐
                        │  │ Decode QR/OCR    │  │ Extract URLs,  │
                        │  │ Run same enrich  │  │ IPs, domains,  │
                        │  │ on decoded URL   │  │ hashes         │
                        │  └────┬─────────────┘  └─────┬──────────┘
                        │       │                      │
                        └───────┴──────────┬───────────┘
                                           │
                              ┌────────────▼────────────┐
                              │ Run IOC enrichment      │
                              │ · ioc_enrichment.py     │
                              │ · Flask /triage page    │
                              │ · VT / AbuseIPDB /      │
                              │   URLScan               │
                              └────────────┬────────────┘
                                           │
                              ┌────────────▼────────────┐
                              │ Severity HIGH or          │
                              │ log-corroborated?         │
                              └──┬─────────────────┬──────┘
                                YES                NO
                                 │                  │
                    ┌────────────▼────────┐   ┌─────▼─────────────┐
                    │ · Splunk hunt       │   │ Monitor / advise  │
                    │ · Shuffle webhook   │   │ user                │
                    │ · Block IOCs        │   │ Disposition: FP or  │
                    │ · Notify IR lead    │   │ Benign              │
                    └────────────┬────────┘   └─────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Assign disposition      │
                    │ · True Positive         │
                    │ · False Positive        │
                    │ · Benign                │
                    │ · Undetermined          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Document in IR report   │
                    │ Update case in dashboard│
                    └─────────────────────────┘
```

---

## Triage checklist (copy per case)

| Step | Action | Tool / command |
|------|--------|----------------|
| 1 | Confirm alert in SIEM | Splunk: `source="phishing_mail.log" category=phishing OR category=quishing` |
| 2 | Identify victims | Dashboard cases table or `\| stats count by recipient` |
| 3 | Check authentication | Header: SPF, DKIM, DMARC — all fail = escalate |
| 4 | Extract IOCs | URLs, IPs, domains, attachment hashes |
| 5 | Enrich IOCs | `python ioc_enrichment.py` or **Live Triage** at `/triage` |
| 6 | Hunt related mail | Same `src_ip=103.14.120.67` or sender domain |
| 7 | Quishing? | Search `QR code payload` — enrich **decoded** URL, not body text |
| 8 | Contain | Block IOCs; reset creds if user clicked |
| 9 | Disposition | TP / FP / Benign / Undetermined |
| 10 | Close | Update `incident_report.md`; screenshot dashboard |

---

## Escalation triggers (auto P1)

- User clicked link, opened attachment, or scanned QR  
- Finance / executive recipient (`finance@`, C-suite impersonation)  
- Credential-harvest URL (OWA, O365, VPN login mimic)  
- ≥ 3 recipients in same campaign (see dashboard **Recipients** chart)  
- HIGH severity from enrichment **or** `category=quishing` in logs  

---

## Splunk hunts (paste-ready)

**All phishing from mail server:**
```spl
index=main host="mailserver01" (DMARC_FAIL OR SPF_FAIL OR category=phishing OR category=quishing)
| rex "src_ip=(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "recipient=(?<recipient>\S+)"
| table _time, src_ip, sender, recipient, category
| sort -_time
```

**Repeat attacker IP:**
```spl
source="phishing_mail.log" src_ip=103.14.120.67
| stats count by recipient, sender
```

---

## Disposition definitions

| Code | Meaning | When to use |
|------|---------|-------------|
| **True Positive** | Confirmed malicious phishing | Auth fails + malicious IOCs / user harm |
| **False Positive** | Alert fired, email benign | Marketing / misconfigured SPF only |
| **Benign** | Suspicious but intended (lab) | Simulated training phish |
| **Undetermined** | Insufficient evidence | Pending user interview |

---

## MITRE mapping (quick)

| Scenario | Techniques |
|----------|------------|
| Link in email | T1566.002, T1078 |
| Malicious attachment | T1566.001, T1204.002 |
| QR / quishing | T1566.002, T1204.002, T1078 |
| BEC / wire fraud | T1534, T1657 |

---

*Related docs: `NIST_IR_Playbook.md` (full IR lifecycle) · `QUISHING.md` (QR detection) · `incident_report.md` (sample closed case)*
