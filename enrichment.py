"""
Shared IOC enrichment for CLI (ioc_enrichment.py) and Flask triage page.
"""

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")

# Known-malicious from phishing_mail.log (used when APIs unavailable)
LOG_HIGH_IOCS = {
    "103.14.120.67",
    "185.199.108.153",
    "malicious-sender.xyz",
    "microsoft-support.com",
    "http://185.199.108.153/owa/auth/logon.aspx",
}

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I
)

DEFAULT_IOCS = {
    "ip_addresses": ["103.14.120.67", "185.199.108.153"],
    "domains": ["malicious-sender.xyz", "microsoft-support.com"],
    "urls": ["http://185.199.108.153/owa/auth/logon.aspx"],
}


def parse_iocs_from_text(text):
    """Extract unique IPs, domains, URLs from pasted headers or IOC list."""
    ips = list(dict.fromkeys(RE_IP.findall(text)))
    urls = list(dict.fromkeys(RE_URL.findall(text)))
    domains = []
    for match in RE_DOMAIN.findall(text):
        low = match.lower()
        if low in ("company.com", "localhost"):
            continue
        if any(low in u for u in urls):
            continue
        if not any(low == ip for ip in ips):
            domains.append(low)
    domains = list(dict.fromkeys(domains))
    return {"ip_addresses": ips, "domains": domains, "urls": urls}


def _score_findings(findings, ioc_value):
    verdicts = [f.get("verdict", "") for f in findings]
    if any(v == "MALICIOUS" for v in verdicts):
        return "HIGH"
    if any("SUBMITTED" in v for v in verdicts):
        return "MEDIUM"
    if any(f.get("error") for f in findings):
        if ioc_value in LOG_HIGH_IOCS or ioc_value.rstrip("/") in LOG_HIGH_IOCS:
            return "HIGH"
        return "LOW"
    return "LOW"


def check_virustotal_ip(ip):
    if not VT_KEY or "YOUR_" in VT_KEY:
        return {"source": "VirusTotal", "error": "API key not configured"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            return {
                "source": "VirusTotal",
                "malicious_votes": mal,
                "total_engines": sum(stats.values()),
                "verdict": "MALICIOUS" if mal > 0 else "CLEAN",
            }
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_virustotal_domain(domain):
    if not VT_KEY or "YOUR_" in VT_KEY:
        return {"source": "VirusTotal", "error": "API key not configured"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal = stats.get("malicious", 0)
            return {
                "source": "VirusTotal",
                "malicious_votes": mal,
                "total_engines": sum(stats.values()),
                "verdict": "MALICIOUS" if mal > 0 else "CLEAN",
            }
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_abuseipdb(ip):
    if not ABUSE_KEY or "YOUR_" in ABUSE_KEY:
        return {"source": "AbuseIPDB", "error": "API key not configured"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            return {
                "source": "AbuseIPDB",
                "abuse_confidence_score": f"{score}%",
                "country": data.get("countryCode", "?"),
                "verdict": "MALICIOUS" if score > 25 else "CLEAN",
            }
        return {"source": "AbuseIPDB", "error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"source": "AbuseIPDB", "error": str(e)}


def check_urlscan(url):
    if not URLSCAN_KEY or "YOUR_" in URLSCAN_KEY:
        return {"source": "URLScan.io", "error": "API key not configured"}
    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_KEY, "Content-Type": "application/json"},
            json={"url": url, "visibility": "public"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "source": "URLScan.io",
                "scan_id": data.get("uuid"),
                "result_url": data.get("result"),
                "verdict": "SUBMITTED — check result in ~30s",
            }
        return {"source": "URLScan.io", "error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"source": "URLScan.io", "error": str(e)}


def enrich_ioc(ioc_type, value):
    findings = []
    if ioc_type == "ip_addresses":
        findings.append(check_virustotal_ip(value))
        time.sleep(0.5)
        findings.append(check_abuseipdb(value))
    elif ioc_type == "domains":
        findings.append(check_virustotal_domain(value))
    elif ioc_type == "urls":
        findings.append(check_urlscan(value))

    severity = _score_findings(findings, value)
    log_backed = value in LOG_HIGH_IOCS and any(f.get("error") for f in findings)

    return {
        "ioc": value,
        "type": ioc_type.replace("_", " ").title(),
        "findings": findings,
        "severity": severity,
        "log_corroborated": log_backed,
    }


def run_enrichment(iocs=None, save=True):
    iocs = iocs or DEFAULT_IOCS
    results = []
    report = {
        "report_timestamp": datetime.now().isoformat(),
        "analyst": "SOC Analyst Trainee",
        "case_id": "PHI-2026-001",
        "ioc_results": {},
    }

    for ip in iocs.get("ip_addresses", []):
        entry = enrich_ioc("ip_addresses", ip)
        results.append(entry)
        report["ioc_results"][ip] = {"type": "IP Address", "findings": entry["findings"]}
        time.sleep(0.5)

    for domain in iocs.get("domains", []):
        entry = enrich_ioc("domains", domain)
        results.append(entry)
        report["ioc_results"][domain] = {"type": "Domain", "findings": entry["findings"]}
        time.sleep(0.5)

    for url in iocs.get("urls", []):
        entry = enrich_ioc("urls", url)
        results.append(entry)
        report["ioc_results"][url] = {"type": "URL", "findings": entry["findings"]}
        time.sleep(0.5)

    if save:
        out = Path(__file__).parent / "ioc_report.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    high_count = sum(1 for r in results if r["severity"] == "HIGH")
    return {"results": results, "report": report, "high_count": high_count}
