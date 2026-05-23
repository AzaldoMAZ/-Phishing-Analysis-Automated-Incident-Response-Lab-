# Quishing (QR Phishing) — Lab Scenario

## Attack summary

| Field | Value (from `phishing_mail.log`) |
|-------|--------------------------------|
| Message ID | Q1R2S |
| Time (UTC) | 2026-05-13T20:35:12Z |
| Recipient | finance@company.com |
| Sender | badguy@malicious-sender.xyz |
| Source IP | 103.14.120.67 |
| Decoded URL | http://185.199.108.153/owa/auth/logon.aspx |
| Channel | qr_image |
| Splunk category | quishing |

## MITRE ATT&CK

- **T1566.002** — Spearphishing Link (payload delivered via QR, not body hyperlink)
- **T1204.002** — User Execution: Malicious File (user scans image attachment)
- **T1078** — Valid Accounts (credential harvest goal)

## Detection approach

1. **Mail gateway** — Flag `QR_IMAGE_ATTACHMENT` in SpamAssassin-style rules (see log line `spamd[5678]`).
2. **URL extraction** — OCR / QR decode on image attachments; compare decoded URL to threat intel (same pipeline as link phishing).
3. **Splunk SPL** (example):

```spl
source="phishing_mail.log" category=quishing OR "QR code payload decoded"
| rex "target=(?<url>https?://\S+)"
| rex "recipient=(?<recipient>\S+)"
| table _time, recipient, url, src_ip, channel
```

4. **SOC triage** — No URL in email body → desktop safe-link scanners may not trigger; train users to report QR in PDF/image attachments.
5. **Enrichment** — Run decoded URL through VirusTotal / URLScan (same as `enrichment.py` / Live Triage page).

## Generate the lure (portfolio artifact)

```powershell
cd Phishing-IR-Lab
.\venv\Scripts\Activate.ps1
python scripts\generate_quishing_qr.py
```

Output: `samples/quishing_lure.png`

## IR report text (paste into `incident_report.md`)

> A secondary quishing vector targeted `finance@company.com` (message Q1R2S). The email contained a QR image encoding the same OWA credential-harvest URL (`185.199.108.153`). urlfilter decoded the payload and logged `category=quishing`. Detection relied on QR decode + threat intel enrichment, not traditional body-URL rules.
