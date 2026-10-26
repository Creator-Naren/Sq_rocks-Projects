#!/usr/bin/env python3
"""Bait-link honeypot tracker for an AUTHORIZED awareness campaign.

Serves a benign "you clicked a training bait" landing page and records click
metadata so the campaign owner can measure who took the bait. This is the
tracking half of a baiting/watering-hole awareness exercise — the defensive
counterpart to the attack technique.

Ethics & privacy
    * Bind to loopback by default; --allow-remote required to expose it.
    * IP addresses are pseudonymized with a salted hash by default
      (GDPR-friendly). --raw-ip stores cleartext and should only be used with
      authorization and a documented retention period.
    * Log only what the campaign needs; honour a retention/deletion policy.

Usage
    python3 honeypot_tracker.py                     # serve on 127.0.0.1:8080
    python3 honeypot_tracker.py --port 8090 --salt mycampaign2026
    python3 honeypot_tracker.py --report            # analyse the log
    python3 honeypot_tracker.py --report --log f.jsonl
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import sys
import threading
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_LOG = "honeypot_log.jsonl"

AWARENESS_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security Awareness Test</title></head>
<body style="font-family:sans-serif;max-width:40rem;margin:4rem auto">
<h1>This was a security-awareness bait link</h1>
<p>You followed a simulated bait link as part of an authorized training
exercise. Nothing was installed and no credentials were collected.</p>
<p><strong>A real attacker would already have:</strong></p>
<ul>
  <li>fingerprinted your browser and OS,</li>
  <li>be able to run a drive-by script or fake login page,</li>
  <li>recorded that this address is live and monitored.</li>
</ul>
<p>Report unexpected links to IT. Hover before you click, and verify the
destination domain.</p>
</body></html>
""".encode("utf-8")


def parse_ua(ua: str) -> tuple[str, str, str, bool]:
    """Return (browser, os, device, is_bot) using lightweight heuristics."""
    u = ua.lower()
    bot_pat = r"bot|crawler|spider|curl|wget|python-requests|httpie|scrapy|headless"
    if re.search(bot_pat, u):
        return "Bot/CLI", "unknown", "bot", True

    browser = "Other"
    for name, token in (("Edge", "edg/"), ("Opera", "opr/"),
                        ("Chrome", "chrome/"), ("Firefox", "firefox/"),
                        ("Safari", "safari")):
        if token in u:
            browser = name
            break

    if "android" in u:
        os_ = "Android"
    elif "iphone" in u or "ipad" in u:
        os_ = "iOS"
    elif "windows" in u:
        os_ = "Windows"
    elif "mac os x" in u or "macintosh" in u:
        os_ = "macOS"
    elif "linux" in u:
        os_ = "Linux"
    else:
        os_ = "Other"

    if "ipad" in u or "tablet" in u:
        device = "Tablet"
    elif "mobile" in u or "android" in u or "iphone" in u:
        device = "Mobile"
    else:
        device = "Desktop"

    return browser, os_, device, False


class HoneyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, log_path=DEFAULT_LOG, salt="",
                 trust_proxy=False, raw_ip=False):
        super().__init__(addr, handler)
        self.log_path = log_path
        self.salt = salt or secrets.token_hex(8)
        self.trust_proxy = trust_proxy
        self.raw_ip = raw_ip
        self.entries: list[dict] = []
        self.lock = threading.Lock()

    def client_ip(self, handler: BaseHTTPRequestHandler) -> str:
        if self.trust_proxy:
            xff = handler.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return handler.client_address[0]

    def _digest(self, value: str) -> str:
        return hashlib.sha256(f"{self.salt}:{value}".encode()).hexdigest()[:12]

    def record(self, handler: BaseHTTPRequestHandler, parsed) -> dict:
        ip = self.client_ip(handler)
        ua = handler.headers.get("User-Agent", "?")
        browser, os_, device, is_bot = parse_ua(ua)
        campaign = (parse_qs(parsed.query).get("c", ["default"])[0]) or "default"

        entry = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "campaign": campaign,
            "visitor": self._digest(f"{ip}|{ua}"),
            "ip": ip if self.raw_ip else self._digest(ip),
            "path": parsed.path,
            "browser": browser,
            "os": os_,
            "device": device,
            "is_bot": is_bot,
            "referer": handler.headers.get("Referer", ""),
            "lang": handler.headers.get("Accept-Language", ""),
            "ua": ua,
        }
        with self.lock:
            self.entries.append(entry)
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry


class HoneyHandler(BaseHTTPRequestHandler):
    server_version = "AwarenessHoneypot/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/stats":
            server: HoneyServer = self.server  # type: ignore[assignment]
            return self._send_json({"clicks": len(server.entries)})

        entry = self.server.record(self, parsed)  # type: ignore[union-attr]
        print(json.dumps(entry))

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(AWARENESS_HTML)))
        self.end_headers()
        self.wfile.write(AWARENESS_HTML)

    def _send_json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence default request logging
        pass


def analyze(entries: list[dict]) -> str:
    total = len(entries)
    bots = sum(1 for e in entries if e["is_bot"])
    humans = total - bots
    visitors = {e["visitor"] for e in entries}

    def counts(key):
        c = Counter(e[key] for e in entries)
        return ", ".join(f"{k}={v}" for k, v in c.most_common())

    per_visitor: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        per_visitor[e["visitor"]].append(e)

    lines = [
        "=" * 64,
        "BAIT-LINK HONEYPOT — CAPTURED VICTIM ANALYSIS",
        "=" * 64,
        f"total clicks        : {total}",
        f"unique visitors     : {len(visitors)}",
        f"  human clicks      : {humans}",
        f"  bot/automated     : {bots}",
        f"click-through rate  : {len(visitors)} unique visitors across "
        f"{len({e['campaign'] for e in entries})} campaign(s)",
        "",
        f"by campaign         : {counts('campaign')}",
        f"by browser          : {counts('browser')}",
        f"by OS               : {counts('os')}",
        f"by device           : {counts('device')}",
        "",
        "--- victim table (pseudonymized) ---",
        f"{'visitor':<14}{'clicks':<7}{'campaign(s)':<24}{'browser':<10}{'os':<9}{'device':<9}{'bot'}",
    ]
    for visitor, evs in sorted(per_visitor.items(),
                               key=lambda kv: -len(kv[1])):
        camps = ",".join(sorted({e["campaign"] for e in evs}))
        br = evs[0]["browser"]
        os_ = evs[0]["os"]
        dev = evs[0]["device"]
        bot = "yes" if any(e["is_bot"] for e in evs) else "no"
        lines.append(f"{visitor:<14}{len(evs):<7}{camps:<24}{br:<10}{os_:<9}{dev:<9}{bot}")

    lines += [
        "",
        "--- first/last click timeline ---",
    ]
    if entries:
        lines.append(f"first: {entries[0]['ts']}  last: {entries[-1]['ts']}")
    lines.append("=" * 64)
    lines.append("Interpretation: a human click on a bait link is a training "
                 "moment, not an incident.\nFeed these pseudonymized stats "
                 "back into awareness training; never name-and-shame.")
    lines.append("=" * 64)
    return "\n".join(lines)


def run_report(log_path: str) -> None:
    if not os.path.exists(log_path):
        sys.exit(f"log not found: {log_path}")
    entries = []
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    print(analyze(entries))


def main() -> None:
    parser = argparse.ArgumentParser(description="Bait-link honeypot tracker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", default=DEFAULT_LOG)
    parser.add_argument("--salt", default="",
                        help="fixed salt for stable visitor IDs across restarts")
    parser.add_argument("--trust-proxy", action="store_true",
                        help="honour X-Forwarded-For (only behind a trusted proxy)")
    parser.add_argument("--raw-ip", action="store_true",
                        help="store cleartext IPs (authorization + retention required)")
    parser.add_argument("--report", action="store_true", help="analyse the log and exit")
    parser.add_argument("--allow-remote", action="store_true",
                        help="confirm you intend to bind a non-loopback interface")
    args = parser.parse_args()

    if args.report:
        run_report(args.log)
        return

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        sys.exit("Refusing to bind a non-loopback interface without --allow-remote.")

    server = HoneyServer((args.host, args.port), HoneyHandler,
                         log_path=args.log, salt=args.salt,
                         trust_proxy=args.trust_proxy, raw_ip=args.raw_ip)
    print(f"[*] awareness honeypot on http://{args.host}:{args.port}/bait/?c=<campaign>")
    print(f"[*] logging to {args.log}  (ip storage: "
          f"{'RAW' if args.raw_ip else 'pseudonymized'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped")


if __name__ == "__main__":
    main()
