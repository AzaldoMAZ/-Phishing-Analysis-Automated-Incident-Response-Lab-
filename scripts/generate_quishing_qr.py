#!/usr/bin/env python3
"""
Generate a quishing (QR phishing) lure image for the Phishing IR Lab.
Uses the same payload URL from phishing_mail.log / Splunk alerts.
"""

from pathlib import Path

import qrcode

# Same URL detected in urlfilter logs (message Q1R2S / A1B2C / C3D4E)
PAYLOAD_URL = "http://185.199.108.153/owa/auth/logon.aspx"

OUT_DIR = Path(__file__).resolve().parent.parent / "samples"
OUT_FILE = OUT_DIR / "quishing_lure.png"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    img = qrcode.make(PAYLOAD_URL)
    img.save(OUT_FILE)
    print("Quishing QR generated")
    print(f"  Payload : {PAYLOAD_URL}")
    print(f"  Saved   : {OUT_FILE}")
    print("\nUse in IR report + screenshots/quishing/ for portfolio.")


if __name__ == "__main__":
    main()
