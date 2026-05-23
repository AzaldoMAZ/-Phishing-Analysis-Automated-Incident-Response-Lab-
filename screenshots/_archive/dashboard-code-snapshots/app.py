"""
SOC Phishing Triage Dashboard — Flask Web App
Run with: python app.py
Open browser at: http://localhost:5000
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_FILE = os.path.join(BASE_DIR, "ioc_report.json")
ENRICH_SCRIPT = os.path.join(BASE_DIR, "ioc_enrichment.py")


def build_report_from_json() -> dict:
    """Load ioc_report.json and reshape it for the template."""

    # ── Default / fallback data if file is missing ─────────────────────────
    default_iocs = [
        {"value": "103.14.120.67",   "type": "IP Address", "source": "Email Headers",  "verdict": "Suspicious", "platform": "AbuseIPDB",  "vt_link": "https://www.virustotal.com/gui/ip-address/103.14.120.67"},
        {"value": "185.199.108.153", "type": "IP Address", "source": "Phishing URL",   "verdict": "Suspicious", "platform": "VirusTotal", "vt_link": "https://www.virustotal.com/gui/ip-address/185.199.108.153"},
        {"value": "malicious-sender.xyz",    "type": "Domain", "source": "SPF Header",      "verdict": "Malicious",  "platform": "VirusTotal", "vt_link": "https://www.virustotal.com/gui/domain/malicious-sender.xyz"},
        {"value": "microsoft-support.com",   "type": "Domain", "source": "From: Header",    "verdict": "Malicious",  "platform": "VirusTotal", "vt_link": "https://www.virustotal.com/gui/domain/microsoft-support.com"},
        {"value": "http://185.199.108.153/owa/auth/logon.aspx", "type": "URL", "source": "Email Body", "verdict": "Malicious", "platform": "URLScan.io", "vt_link": "https://www.virustotal.com/gui/url/aHR0cDovLzE4NS4xOTkuMTA4LjE1My9vd2EvYXV0aC9sb2dvbi5hc3B4"},
    ]

    # ── Try to load enrichment output ───────────────────────────────────────
    iocs = default_iocs
    if os.path.exists(REPORT_FILE):
        try:
            with open(REPORT_FILE, "r") as f:
                raw = json.load(f)

            # Normalise — ioc_enrichment.py may store as list or dict
            if isinstance(raw, list):
                parsed = []
                for entry in raw:
                    verdict = entry.get("verdict", "Unknown")
                    ioc_val = entry.get("ioc", entry.get("value", "N/A"))
                    ioc_type = entry.get("type", "Unknown")
                    platform = entry.get("platform", "VirusTotal")
                    vt_link = None
                    if ioc_type.lower() in ("ip", "ip address"):
                        vt_link = f"https://www.virustotal.com/gui/ip-address/{ioc_val}"
                    elif ioc_type.lower() in ("domain", "url"):
                        vt_link = f"https://www.virustotal.com/gui/domain/{ioc_val}"
                    parsed.append({
                        "value":    ioc_val,
                        "type":     ioc_type,
                        "source":   entry.get("source", "IOC Enrichment"),
                        "verdict":  verdict,
                        "platform": platform,
                        "vt_link":  vt_link,
                    })
                iocs = parsed if parsed else default_iocs
        except Exception:
            iocs = default_iocs

    # ── Tally counts ────────────────────────────────────────────────────────
    malicious_count  = sum(1 for i in iocs if i["verdict"] == "Malicious")
    suspicious_count = sum(1 for i in iocs if i["verdict"] == "Suspicious")
    clean_count      = sum(1 for i in iocs if i["verdict"] == "Clean")
    ioc_types        = len(set(i["type"] for i in iocs))

    # ── Static timeline ──────────────────────────────────────────────────────
    timeline = [
        {"time": "2026-05-13  08:29 UTC", "color": "red",    "description": "Phishing email sent from badguy@malicious-sender.xyz to 3 internal targets"},
        {"time": "2026-05-13  08:30 UTC", "color": "red",    "description": "Email relayed through 103.14.120.67 (India) — delivered to mailboxes"},
        {"time": "2026-05-13  08:30 UTC", "color": "orange", "description": "Splunk SIEM alert fired — PHI-2026-001: Phishing Email Detected"},
        {"time": "2026-05-13  08:30 UTC", "color": "blue",   "description": "Shuffle SOAR webhook triggered — automated VirusTotal triage initiated"},
        {"time": "2026-05-13  14:29 UTC", "color": "blue",   "description": "Analyst manually reviewed .eml artifact — SPF/DKIM/DMARC triple failure confirmed"},
        {"time": "2026-05-13  14:35 UTC", "color": "blue",   "description": "ioc_enrichment.py executed — 5 IOCs queried across VirusTotal, AbuseIPDB, URLScan.io"},
        {"time": "2026-05-13  14:38 UTC", "color": "green",  "description": "URLScan.io confirmed phishing URL returns 404 — infrastructure taken offline"},
        {"time": "2026-05-13  14:45 UTC", "color": "green",  "description": "All IOCs documented — incident report filed. Case closed: Contained"},
    ]

    return {
        "case_id":         "PHI-2026-001",
        "analyst":         "Azaldo Mazibuko",
        "generated_at":    datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "total_iocs":      len(iocs),
        "malicious_count": malicious_count,
        "suspicious_count":suspicious_count,
        "clean_count":     clean_count,
        "ioc_types":       ioc_types,
        "iocs":            iocs,
        "timeline":        timeline,
    }


@app.route("/")
def index():
    report = build_report_from_json()
    return render_template("index.html", report=report)


@app.route("/run", methods=["POST"])
def run_enrichment():
    """Trigger ioc_enrichment.py non-interactively and redirect back."""
    try:
        subprocess.run(
            [sys.executable, ENRICH_SCRIPT, "--auto"],
            timeout=60,
            capture_output=True
        )
    except Exception:
        pass
    return redirect(url_for("index"))


@app.route("/api/report")
def api_report():
    """JSON endpoint — useful for Shuffle SOAR or other integrations."""
    from flask import jsonify
    return jsonify(build_report_from_json())


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  🛡️  SOC Phishing Triage Dashboard")
    print("  📍  http://localhost:5000")
    print("  ℹ️   Press CTRL+C to stop")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
