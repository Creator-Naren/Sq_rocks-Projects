#!/usr/bin/env python3
"""Local-only login lab for brute-force / credential-stuffing training.

Run ONE of:
    python3 flask_login_lab.py --mode vulnerable
    python3 flask_login_lab.py --mode hardened

Both bind to 127.0.0.1 by default and refuse to expose the lab on a public
interface unless you explicitly opt in. The 'hardened' mode demonstrates the
standard defenses the companion simulator tries to defeat:

    * per-IP sliding-window rate limit  -> HTTP 429 + Retry-After
    * per-account lockout              -> HTTP 423
    * CAPTCHA challenge after N fails  -> login needs a 'captcha' field
    * MFA step-up after a valid password -> never returns full access

Teaching point: rate limiting + lockout stop volume, but only MFA actually
stops account takeover once a password is guessed or leaked.

Endpoints:
    GET  /                lab description
    POST /login           form/JSON: username, password [, captcha]
    GET  /lab/stats       server-side counters
    POST /lab/reset       clear rate-limit / lockout / captcha state
"""

from __future__ import annotations

import argparse
import random
import sys
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# --- seeded accounts (lab fixtures) -----------------------------------------
# Light PBKDF2 so the demo dictionary run is fast; real systems use ~600k.
def _h(pw: str) -> str:
    return generate_password_hash(pw, method="pbkdf2:sha256:1000")


USERS = {
    "admin":      {"hash": _h("letmein"),    "role": "admin",   "mfa": True},
    "riya":       {"hash": _h("Summer2024"), "role": "user",    "mfa": True},
    "demo":       {"hash": _h("password"),   "role": "user",    "mfa": False},
    "svc-backup": {"hash": _h("backup123"),  "role": "service", "mfa": False},
}

# --- tunables ----------------------------------------------------------------
MODE = "vulnerable"
IP_MAX_HITS = 6          # hard cap on login attempts per IP per window
IP_WINDOW = 30.0         # seconds
LOCKOUT_THRESHOLD = 5    # consecutive failures -> lock the account
LOCKOUT_SECONDS = 30.0
CAPTCHA_AFTER = 3        # failures before a CAPTCHA is demanded


class SlidingWindowLimiter:
    """Max N events per rolling window, keyed by IP."""

    def __init__(self, max_hits: int, window: float):
        self.max_hits = max_hits
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, float]:
        now = time.time()
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.max_hits:
                return False, max(self.window - (now - dq[0]), 0.0)
            dq.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class AccountState:
    """Failure tracking -> lockout + CAPTCHA gate (hardened mode)."""

    def __init__(self):
        self.failures: dict[str, int] = defaultdict(int)
        self.locked_until: dict[str, float] = {}
        self._captcha: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def is_locked(self, user: str) -> float:
        with self._lock:
            remaining = self.locked_until.get(user, 0.0) - time.time()
            return max(remaining, 0.0)

    def record_failure(self, user: str) -> None:
        with self._lock:
            self.failures[user] += 1
            if self.failures[user] >= LOCKOUT_THRESHOLD:
                self.locked_until[user] = time.time() + LOCKOUT_SECONDS
                self.failures[user] = 0

    def captcha_required(self, user: str) -> bool:
        with self._lock:
            return self.failures[user] >= CAPTCHA_AFTER

    def captcha_challenge(self, user: str) -> tuple[int, int]:
        with self._lock:
            if user not in self._captcha:
                self._captcha[user] = (random.randint(1, 9), random.randint(1, 9))
            return self._captcha[user]

    def verify_captcha(self, user: str, answer: str) -> bool:
        with self._lock:
            a, b = self._captcha.get(user, (0, 0))
            ok = str(answer).strip() == str(a + b)
            self._captcha.pop(user, None)   # single-use, win or lose
            return ok

    def clear(self, user: str) -> None:
        with self._lock:
            self.failures.pop(user, None)
            self.locked_until.pop(user, None)
            self._captcha.pop(user, None)

    def reset(self) -> None:
        with self._lock:
            self.failures.clear()
            self.locked_until.clear()
            self._captcha.clear()


ip_limiter = SlidingWindowLimiter(IP_MAX_HITS, IP_WINDOW)
accounts = AccountState()
stats: dict[str, int] = defaultdict(int)
stats_lock = threading.Lock()


def _bump(key: str) -> None:
    with stats_lock:
        stats[key] += 1


@app.get("/")
def index():
    return jsonify(
        lab="password-attack-lab",
        mode=MODE,
        login="POST /login {username, password, captcha?}",
    )


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form or {}
    user = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    ip = request.remote_addr or "unknown"
    _bump("total")

    if MODE == "hardened":
        allowed, retry = ip_limiter.check(ip)
        if not allowed:
            _bump("rate_limited")
            resp = jsonify(status="rate_limited",
                           message="Too many requests. Slow down.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(int(retry) + 1)
            return resp

        remaining = accounts.is_locked(user)
        if remaining:
            _bump("locked")
            return jsonify(status="locked",
                           message=f"Account temporarily locked.",
                           retry_after=int(remaining) + 1), 423

        if accounts.captcha_required(user):
            a, b = accounts.captcha_challenge(user)
            supplied = data.get("captcha")
            if supplied is None:
                _bump("captcha_challenged")
                return jsonify(status="captcha_required",
                               challenge=f"{a} + {b} = ?",
                               message="CAPTCHA required after failures."), 401
            if not accounts.verify_captcha(user, supplied):
                _bump("captcha_failed")
                accounts.record_failure(user)
                return jsonify(status="captcha_failed",
                               message="Wrong CAPTCHA answer."), 401

    record = USERS.get(user)
    valid = bool(record) and check_password_hash(record["hash"], password)

    if valid:
        accounts.clear(user)
        _bump("success")
        if MODE == "hardened" and record["mfa"]:
            _bump("mfa_blocked")
            return jsonify(status="mfa_required",
                           password_valid=True,
                           message="Password correct; MFA challenge required."), 200
        return jsonify(status="success",
                       message=f"Welcome {user}", mfa=False), 200

    accounts.record_failure(user)
    _bump("invalid")
    return jsonify(status="invalid", message="Invalid credentials"), 401


@app.get("/lab/stats")
def lab_stats():
    with stats_lock:
        return jsonify(mode=MODE, counters=dict(stats),
                       accounts_locked=[u for u in USERS
                                        if accounts.is_locked(u) > 0])


@app.post("/lab/reset")
def lab_reset():
    ip_limiter.reset()
    accounts.reset()
    with stats_lock:
        stats.clear()
    return jsonify(status="reset")


def main() -> None:
    global MODE
    parser = argparse.ArgumentParser(description="Local login lab (training)")
    parser.add_argument("--mode", choices=["vulnerable", "hardened"],
                        default="vulnerable")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--allow-remote", action="store_true",
                        help="permit binding to a non-loopback interface")
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        sys.exit(f"Refusing to bind {args.host} without --allow-remote "
                 f"(lab is loopback-only by default).")

    MODE = args.mode
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
