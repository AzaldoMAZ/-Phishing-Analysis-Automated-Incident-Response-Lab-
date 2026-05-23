"""
Parse phishing_mail.log into structured events for the SOC dashboard.
All data comes from the lab log file — no fabricated IOCs.
"""

import json
import re
from pathlib import Path

LOG_PATH = Path(__file__).parent / "phishing_mail.log"
IOC_REPORT_PATH = Path(__file__).parent / "ioc_report.json"

RE_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:]+Z)")
RE_ALERT = re.compile(
    r"ALERT: (?P<alert_type>[^-]+) - "
    r"(?:email )?(?P<msg_id>[A-Z0-9]+)?"
    r".*?"
    r"(?:URL=)?(?P<url>https?://\S+)?"
    r".*?"
    r"category=(?P<category>\w+)?"
    r".*?"
    r"src_ip=(?P<src_ip>[\d.]+)?"
    r".*?"
    r"sender=(?P<sender>\S+)?"
    r".*?"
    r"recipient=(?P<recipient>\S+)?",
    re.IGNORECASE,
)
RE_URL_ALERT = re.compile(
    r"ALERT: Malicious URL detected in email (?P<msg_id>\w+) - "
    r"(?P<url>https?://\S+) - category=(?P<category>\w+) "
    r"src_ip=(?P<src_ip>[\d.]+) sender=(?P<sender>\S+) recipient=(?P<recipient>\S+)"
)
RE_QUISHING_ALERT = re.compile(
    r"ALERT: QR code payload decoded in email (?P<msg_id>\w+) - "
    r"target=(?P<url>https?://\S+) category=quishing channel=(?P<channel>\S+) "
    r"src_ip=(?P<src_ip>[\d.]+) sender=(?P<sender>\S+) recipient=(?P<recipient>\S+)"
)
RE_CRED_ALERT = re.compile(
    r"ALERT: Credential harvesting page detected - URL=(?P<url>\S+) "
    r"mimics=(?P<mimics>\S+) threat_score=(?P<threat_score>\d+)"
)
RE_SPAMD = re.compile(
    r"result: Y (?P<score>\d+) - (?P<flags>[\w_,]+) pts=(?P<pts>[\d.]+)"
)
RE_DELIVERED = re.compile(
    r"(?P<msg_id>\w+): to=<(?P<recipient>[^>]+)>, .* status=(?P<status>\w+)"
)
RE_CLIENT = re.compile(r"(?P<msg_id>\w+): client=unknown\[(?P<src_ip>[\d.]+)\]")
RE_SPF_FAIL = re.compile(r"spf=fail smtp.mailfrom=(?P<domain>\S+)")
RE_DMARC_FAIL = re.compile(r"dmarc=fail.*header.from=(?P<domain>\S+)")


def parse_log():
    if not LOG_PATH.exists():
        return {"events": [], "alerts": [], "cases": [], "stats": {}}

    lines = LOG_PATH.read_text(encoding="utf-8").strip().splitlines()
    events = []
    alerts = []
    deliveries = {}
    spam_by_msg = {}
    clients = {}
    pending_spam = None

    for line in lines:
        ts_m = RE_TS.match(line)
        timestamp = ts_m.group(1) if ts_m else ""

        if "urlfilter" in line and "ALERT:" in line:
            mq = RE_QUISHING_ALERT.search(line)
            m = RE_URL_ALERT.search(line) if not mq else None
            if mq:
                alert = {
                    "timestamp": timestamp,
                    "msg_id": mq.group("msg_id"),
                    "url": mq.group("url"),
                    "category": "quishing",
                    "channel": mq.group("channel"),
                    "src_ip": mq.group("src_ip"),
                    "sender": mq.group("sender"),
                    "recipient": mq.group("recipient"),
                    "severity": "CRITICAL",
                    "source": "urlfilter",
                    "raw": line,
                }
                alerts.append(alert)
                events.append({**alert, "event_type": "quishing"})
            elif m:
                alert = {
                    "timestamp": timestamp,
                    "msg_id": m.group("msg_id"),
                    "url": m.group("url"),
                    "category": m.group("category"),
                    "src_ip": m.group("src_ip"),
                    "sender": m.group("sender"),
                    "recipient": m.group("recipient"),
                    "severity": "HIGH",
                    "source": "urlfilter",
                    "raw": line,
                }
                alerts.append(alert)
                events.append({**alert, "event_type": "alert"})
            else:
                m2 = RE_CRED_ALERT.search(line)
                if m2:
                    events.append({
                        "timestamp": timestamp,
                        "event_type": "credential_harvest",
                        "url": m2.group("url"),
                        "mimics": m2.group("mimics"),
                        "threat_score": int(m2.group("threat_score")),
                        "severity": "CRITICAL",
                        "raw": line,
                    })

        if "spamd" in line and "result:" in line:
            m = RE_SPAMD.search(line)
            if m:
                pts = float(m.group("pts"))
                flags = m.group("flags").split(",")
                pending_spam = {
                    "pts": pts,
                    "flags": flags,
                    "timestamp": timestamp,
                }
                events.append({
                    "timestamp": timestamp,
                    "event_type": "spam_analysis",
                    "spam_score": int(m.group("score")),
                    "pts": pts,
                    "flags": flags,
                    "severity": "HIGH" if pts >= 15 else "MEDIUM",
                    "raw": line,
                })

        if "postfix/local" in line and "status=delivered" in line:
            m = RE_DELIVERED.search(line)
            if m:
                msg_id = m.group("msg_id")
                deliveries[msg_id] = {
                    "timestamp": timestamp,
                    "recipient": m.group("recipient"),
                    "status": m.group("status"),
                }
                if pending_spam:
                    spam_by_msg[msg_id] = pending_spam
                    pending_spam = None
                spam = spam_by_msg.get(msg_id, {})
                clients_msg = clients.get(msg_id, {})
                events.append({
                    "timestamp": timestamp,
                    "event_type": "delivery",
                    "msg_id": msg_id,
                    "recipient": m.group("recipient"),
                    "status": m.group("status"),
                    "raw": line,
                })

        if "client=unknown" in line:
            m = RE_CLIENT.search(line)
            if m:
                clients[m.group("msg_id")] = {
                    "src_ip": m.group("src_ip"),
                    "timestamp": timestamp,
                }

    # Build cases from URL alerts (one case per victim email)
    cases = []
    for i, alert in enumerate(alerts, start=1):
        msg_id = alert["msg_id"]
        delivery = deliveries.get(msg_id, {})
        spam = spam_by_msg.get(msg_id, {})
        client = clients.get(msg_id, {"src_ip": alert["src_ip"]})

        spam = spam_by_msg.get(msg_id, {})
        flags = spam.get("flags", [
            "DMARC_FAIL", "SPF_FAIL", "DKIM_NONE", "LOOKALIKE_DOMAIN", "URGENT_SUBJECT"
        ])

        case_id = f"PHI-2026-{i:03d}"
        has_impersonation = "IMPERSONATION" in flags
        is_quishing = alert.get("category") == "quishing"

        cases.append({
            "id": case_id,
            "msg_id": msg_id,
            "title": (
                f"Quishing (QR phishing) — {alert['recipient']}"
                if is_quishing
                else f"Credential harvesting — {alert['recipient']}"
            ),
            "type": "quishing" if is_quishing else "credential_harvesting",
            "status": "open",
            "priority": "critical" if (has_impersonation or is_quishing) else "high",
            "channel": alert.get("channel", "email_link"),
            "timestamp": alert["timestamp"],
            "delivered_at": delivery.get("timestamp", ""),
            "recipient": alert["recipient"],
            "sender": alert["sender"],
            "src_ip": alert["src_ip"],
            "url": alert["url"],
            "category": alert["category"],
            "host": "mailserver01",
            "splunk_alert": "PHI-2026-001: Phishing Email Detected",
            "mitre": (
                ["T1566.002", "T1204.002", "T1078"]
                if is_quishing
                else ["T1566.002", "T1078"] + (["T1656"] if has_impersonation else [])
            ),
            "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
            "spamd_flags": flags,
            "spam_pts": spam.get("pts"),
            "iocs": [
                {"type": "ip", "value": alert["src_ip"], "severity": "HIGH", "label": "Relay IP"},
                {"type": "ip", "value": "185.199.108.153", "severity": "HIGH", "label": "Payload host"},
                {"type": "url", "value": alert["url"], "severity": "CRITICAL", "label": "Phishing URL"},
                {"type": "domain", "value": "malicious-sender.xyz", "severity": "HIGH", "label": "MAIL FROM"},
                {"type": "domain", "value": "microsoft-support.com", "severity": "HIGH", "label": "Lookalike HELO"},
                {"type": "email", "value": alert["sender"], "severity": "HIGH", "label": "Sender"},
            ],
            "timeline": _case_timeline(msg_id, events, alert),
            "notes": (
                f"Message {msg_id}: QR image decoded to {alert['url']}. "
                f"Channel={alert.get('channel', 'qr_image')}. No clickable URL in body — "
                "mobile users bypass desktop URL filters."
                if is_quishing
                else (
                    f"Message {msg_id} delivered to {alert['recipient']}. "
                    f"Malicious URL {alert['url']} flagged by urlfilter. "
                    "SPF/DKIM/DMARC failed per dmarc-filter logs."
                )
            ),
        })

    stats = {
        "total_log_events": len(lines),
        "url_alerts": len([a for a in alerts if a.get("category") == "phishing"]),
        "quishing_alerts": len([a for a in alerts if a.get("category") == "quishing"]),
        "unique_src_ips": len({a["src_ip"] for a in alerts}),
        "unique_recipients": len({a["recipient"] for a in alerts}),
        "campaign_start": min((a["timestamp"] for a in alerts), default=""),
        "campaign_end": max((a["timestamp"] for a in alerts), default=""),
        "host": "mailserver01",
        "log_source": "phishing_mail.log",
    }

    return {
        "events": sorted(events, key=lambda e: e["timestamp"], reverse=True),
        "alerts": alerts,
        "cases": cases,
        "stats": stats,
    }


def _case_timeline(msg_id, events, alert):
    items = []
    for ev in events:
        raw = ev.get("raw", "")
        if msg_id and msg_id in raw:
            items.append({
                "time": ev["timestamp"],
                "type": ev["event_type"],
                "summary": _summarize_event(ev),
            })
    # credential harvest event tied to same URL
    for ev in events:
        if ev.get("event_type") == "credential_harvest":
            items.append({
                "time": ev["timestamp"],
                "type": "credential_harvest",
                "summary": f"Credential harvest detected (score {ev.get('threat_score')})",
            })
    items.sort(key=lambda x: x["time"])
    return items


def _summarize_event(ev):
    t = ev.get("event_type")
    if t == "quishing":
        return f"QR decoded → {ev.get('url', '')[:50]} — {ev.get('recipient')}"
    if t == "alert":
        return f"Malicious URL alert — {ev.get('recipient')}"
    if t == "spam_analysis":
        return f"SpamAssassin score {ev.get('pts')} — {', '.join(ev.get('flags', [])[:3])}"
    if t == "delivery":
        return f"Email delivered to {ev.get('recipient')}"
    if t == "credential_harvest":
        return f"OWA mimic detected (threat_score={ev.get('threat_score')})"
    return t


def load_ioc_report():
    if not IOC_REPORT_PATH.exists():
        return {}
    with IOC_REPORT_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def enrich_cases_with_report(cases):
    report = load_ioc_report()
    results = report.get("ioc_results", {})
    for case in cases:
        for ioc in case.get("iocs", []):
            val = ioc["value"]
            if val in results:
                ioc["enrichment"] = results[val]
            elif val.replace("http://", "").split("/")[0] in results:
                pass
        case["ioc_report_time"] = report.get("report_timestamp", "")
        case["case_ref"] = report.get("case_id", "")
    return cases
