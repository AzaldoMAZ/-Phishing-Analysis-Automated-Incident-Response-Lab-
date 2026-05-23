#!/usr/bin/env python3
"""
=============================================================
  Phishing IOC Enrichment Script
  Author  : SOC Analyst Trainee
  Project : Phishing Analysis & Incident Response Lab
  Purpose : Automatically query threat intelligence APIs
            for every IOC extracted from a phishing email.
=============================================================
"""

import requests   # Used to make HTTP calls to the APIs
import json       # Used to format the final report nicely
import time       # Used to pause between API calls (rate limiting)
from datetime import datetime  # Used to timestamp our report

# ─────────────────────────────────────────────────────────────
#  SECTION 1 — YOUR API KEYS
#  Replace the placeholder strings with your real keys.
#  Get them from:
#    VirusTotal :7cb28dcd779767d4b4bd736eb8602c0bace5a7671966ba639e72fa7d85af2325
#    AbuseIPDB  :c11b21db008773ff55342a4fe468bea2b2ec06359741ef987a2bd3bd81c7109c12b4c881aa43d87e
#    URLScan    :019e22df-d5d1-751c-83bf-e2bd5779df90
# ─────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_KEY_HERE"
ABUSEIPDB_API_KEY  = "YOUR_ABUSEIPDB_KEY_HERE"
URLSCAN_API_KEY    = "YOUR_URLSCAN_KEY_HERE"

# ─────────────────────────────────────────────────────────────
#  SECTION 2 — THE IOCs FROM OUR PHISHING EMAIL
#  These are the Indicators of Compromise we extracted
#  manually during Phase 3 of the lab.
# ─────────────────────────────────────────────────────────────
IOCS = {
    "ip_addresses": [
        "103.14.120.67",     # IOC #1: Originating relay server
        "185.199.108.153"    # IOC #2: IP hiding inside the phishing link
    ],
    "domains": [
        "malicious-sender.xyz",    # IOC #3: Actual sending domain (SPF fail)
        "microsoft-support.com"    # IOC #4: Lookalike/typosquat domain
    ],
    "urls": [
        "http://185.199.108.153/owa/auth/logon.aspx"  # IOC #5: Phishing URL
    ]
}

# ─────────────────────────────────────────────────────────────
#  SECTION 3 — API QUERY FUNCTIONS
#  Each function talks to one threat intelligence service.
# ─────────────────────────────────────────────────────────────

def check_virustotal_ip(ip):
    """
    Queries VirusTotal for an IP address.
    Returns how many security vendors flagged it as malicious.
    """
    print(f"  [*] Querying VirusTotal for IP: {ip}")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "source": "VirusTotal",
                "malicious_votes": malicious,
                "suspicious_votes": suspicious,
                "total_engines": total,
                "verdict": "MALICIOUS" if malicious > 0 else "CLEAN"
            }
        else:
            return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_virustotal_domain(domain):
    """
    Queries VirusTotal for a domain name.
    """
    print(f"  [*] Querying VirusTotal for domain: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return {
                "source": "VirusTotal",
                "malicious_votes": malicious,
                "total_engines": total,
                "verdict": "MALICIOUS" if malicious > 0 else "CLEAN"
            }
        else:
            return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_abuseipdb(ip):
    """
    Queries AbuseIPDB for an IP address.
    Returns the Abuse Confidence Score (0-100%).
    A score above 25% is a strong indicator of malicious activity.
    """
    print(f"  [*] Querying AbuseIPDB for IP: {ip}")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            total_reports = data.get("totalReports", 0)
            return {
                "source": "AbuseIPDB",
                "abuse_confidence_score": f"{score}%",
                "country": country,
                "isp": isp,
                "total_reports": total_reports,
                "verdict": "MALICIOUS" if score > 25 else "CLEAN"
            }
        else:
            return {"source": "AbuseIPDB", "error": f"HTTP {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"source": "AbuseIPDB", "error": str(e)}


def check_urlscan(url_to_scan):
    """
    Submits a URL to URLScan.io for safe analysis.
    URLScan visits the URL in their cloud and takes a screenshot.
    Your computer never touches the malicious site directly.
    """
    print(f"  [*] Submitting URL to URLScan.io: {url_to_scan}")
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"url": url_to_scan, "visibility": "public"}

    try:
        response = requests.post(submit_url, headers=headers,
                                  json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get("uuid", "N/A")
            result_url = data.get("result", "N/A")
            return {
                "source": "URLScan.io",
                "scan_id": scan_id,
                "result_url": result_url,
                "verdict": "SUBMITTED — check result_url in 30 seconds"
            }
        else:
            return {"source": "URLScan.io", "error": f"HTTP {response.status_code} — {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"source": "URLScan.io", "error": str(e)}


# ─────────────────────────────────────────────────────────────
#  SECTION 4 — MAIN ENGINE
#  This ties everything together and builds the final report.
# ─────────────────────────────────────────────────────────────

def run_enrichment():
    print("\n" + "="*60)
    print("  PHISHING IOC ENRICHMENT ENGINE")
    print(f"  Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    # This dictionary will hold ALL our results
    final_report = {
        "report_timestamp": datetime.now().isoformat(),
        "analyst": "SOC Analyst Trainee",
        "case_id": "PHI-2026-001",
        "subject": "URGENT: Office365 Password Expiry Notification",
        "ioc_results": {}
    }

    # --- Check IP Addresses ---
    print("[+] CHECKING IP ADDRESSES")
    print("-" * 40)
    for ip in IOCS["ip_addresses"]:
        print(f"\n[IOC] IP: {ip}")
        ip_results = []
        ip_results.append(check_virustotal_ip(ip))
        time.sleep(1)  # Be polite to the API — don't spam it
        ip_results.append(check_abuseipdb(ip))
        time.sleep(1)
        final_report["ioc_results"][ip] = {"type": "IP Address", "findings": ip_results}

    # --- Check Domains ---
    print("\n\n[+] CHECKING DOMAINS")
    print("-" * 40)
    for domain in IOCS["domains"]:
        print(f"\n[IOC] Domain: {domain}")
        domain_results = []
        domain_results.append(check_virustotal_domain(domain))
        time.sleep(1)
        final_report["ioc_results"][domain] = {"type": "Domain", "findings": domain_results}

    # --- Check URLs ---
    print("\n\n[+] SUBMITTING URLs TO URLSCAN.IO")
    print("-" * 40)
    for url in IOCS["urls"]:
        print(f"\n[IOC] URL: {url}")
        url_results = []
        url_results.append(check_urlscan(url))
        time.sleep(1)
        final_report["ioc_results"][url] = {"type": "URL", "findings": url_results}

    # --- Save the Report ---
    report_filename = "ioc_report.json"
    with open(report_filename, "w") as f:
        json.dump(final_report, f, indent=4)

    print("\n\n" + "="*60)
    print("  ENRICHMENT COMPLETE!")
    print(f"  Full report saved to: {report_filename}")
    print("="*60 + "\n")

    # --- Print a clean summary to the terminal ---
    print("[SUMMARY]")
    for ioc, data in final_report["ioc_results"].items():
        verdicts = [f.get("verdict", "ERROR") for f in data["findings"]]
        overall = "🚨 MALICIOUS" if "MALICIOUS" in verdicts else "✅ CLEAN"
        print(f"  {data['type']:<12} {ioc:<45} {overall}")
    print()


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT — This runs when you execute the script
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_enrichment()
