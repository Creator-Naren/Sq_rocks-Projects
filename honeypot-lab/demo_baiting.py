#!/usr/bin/env python3
"""Drive the honeypot end-to-end: start it, simulate bait clicks, analyse.

Simulated source IPs use the reserved documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so nothing touches a real
host. User agents are varied to exercise the browser/OS/device classifier.

Run:  python3 demo_baiting.py
Writes: sim_honeypot_log.jsonl, victim_log_analysis.txt
"""

from __future__ import annotations

import os
import threading
import time

import requests

from honeypot_tracker import HoneyServer, HoneyHandler, analyze

HOST, PORT = "127.0.0.1", 8091
LOG = "sim_honeypot_log.jsonl"
BASE = f"http://{HOST}:{PORT}"

# (campaign, source ip, user-agent, accept-language, referer)
VICTIMS = [
    ("q4-payroll-email", "203.0.113.24",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
     "en-US,en;q=0.9", "https://mail.example.com/"),
    ("q4-payroll-email", "198.51.100.7",
     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
     "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 "
     "Mobile/15E148 Safari/604.1",
     "en-GB,en;q=0.9", "https://mail.example.com/"),
    ("benefits-sms", "203.0.113.99",
     "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
     "en-IN,en;q=0.8", ""),
    ("linkedin-dm", "192.0.2.55",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) "
     "Gecko/20100101 Firefox/142.0",
     "de-DE,de;q=0.9", "https://www.linkedin.example/"),
    ("q4-payroll-email", "198.51.100.7",          # same person, second device
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
     "en-GB,en;q=0.9", "https://outlook.example/"),
    ("benefits-sms", "192.0.2.200",               # automated scanner
     "python-requests/2.34.2", "", ""),
    ("linkedin-dm", "203.0.113.150",              # indexing bot
     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
     "", ""),
]


def main() -> None:
    if os.path.exists(LOG):
        os.remove(LOG)

    server = HoneyServer((HOST, PORT), HoneyHandler, log_path=LOG,
                         salt="demo-campaign-2026", trust_proxy=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    print(f"[*] honeypot up at {BASE}\n")

    print("--- simulated bait clicks ---")
    for campaign, ip, ua, lang, ref in VICTIMS:
        headers = {"User-Agent": ua, "X-Forwarded-For": ip}
        if lang:
            headers["Accept-Language"] = lang
        if ref:
            headers["Referer"] = ref
        try:
            r = requests.get(f"{BASE}/bait/x?c={campaign}", headers=headers,
                             timeout=5)
            print(f"    click -> c={campaign:<18} ip={ip:<14} "
                  f"HTTP {r.status_code}")
        except requests.RequestException as exc:
            print(f"    click FAILED: {exc}")

    server.shutdown()

    entries = server.entries
    report = analyze(entries)
    print("\n" + report)
    with open("victim_log_analysis.txt", "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    print(f"\n[written] victim_log_analysis.txt and {LOG}")


if __name__ == "__main__":
    main()
