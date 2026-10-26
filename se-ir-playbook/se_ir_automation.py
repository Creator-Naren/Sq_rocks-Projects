#!/usr/bin/env python3
"""SE Incident Response automation script.

Implements a simplified NIST-style workflow for social engineering incidents:
- Preparation / Identification context
- Containment (priority actions based on severity/type)
- Eradication / Recovery guidance baked into the action set
- Lessons learned logged in the report
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from typing import Any

SEVERITY_ACTIONS = {
    "CRITICAL": [
        "LOCK user account",
        "Revoke all active sessions and tokens",
        "Force password/MFA reset",
        "Notify SOC on-call immediately",
        "Preserve logs (auth, email, VPN, proxy)",
        "Isolate affected endpoints",
        "Escalate to CISO/Legal (if data loss suspected)",
    ],
    "HIGH": [
        "LOCK user account",
        "Revoke active sessions",
        "Notify SOC team",
        "Preserve mail logs",
        "Disable compromised OAuth/IMAP/SMTP access",
        "Notify affected parties if exfiltration possible",
    ],
    "MEDIUM": [
        "Revoke sessions if suspicious",
        "Notify security inbox",
        "Preserve relevant logs",
        "Run quick phishing URL/attachment scan",
    ],
    "LOW": [
        "Log for trend analysis",
        "User awareness reminder",
    ],
}

TYPE_ACTIONS = {
    "phishing": [
        "Quarantine reported email(s)",
        "Block sender domain and URLs",
        "Scan attachments/URLs in sandbox",
        "Search for other recipients of same campaign",
        "Remove phishing emails from user inboxes if still present",
    ],
    "spear_phishing": [
        "Quarantine emails and block lookalike domain",
        "Search for related emails across tenants",
        "Conduct targeted user briefing",
        "Check for reply-chain or BEC indicators",
    ],
    "vishing": [
        "Block source number(s) if traceable",
        "Verify with carrier/provider where possible",
        "Reinforce callback policy with user",
        "Review MFA bypass attempts",
    ],
    "smishing": [
        "Block SMS sender/shortcode",
        "Scan any clicked URLs in sandbox",
        "Check mobile device posture if corporate-managed",
    ],
    "bec": [
        "Suspend financial transactions pending review",
        "Freeze associated bank/payroll changes",
        "Preserve wire/payment logs",
        "Notify Finance and Legal",
        "Coordinate with bank if funds not yet settled",
    ],
    "baiting": [
        "Isolate device if drive inserted",
        "Preserve USB/forensic artifacts",
        "Scan for malware and persistence",
        "Revoke credentials if used",
    ],
    "watering_hole": [
        "Block known malicious domains/IPs",
        "Push browser patch/EDR policy",
        "Investigate endpoints that visited the site",
        "Check for drive-by indicators",
    ],
    "account_takeover": [
        "Force global sign-out",
        "Invalidate sessions and refresh tokens",
        "Review recent login history and IPs",
        "Enable step-up auth / reset recovery methods",
        "Check mailbox rules (auto-forward/delete)",
    ],
}


def ir_response(incident: dict[str, Any]) -> dict[str, Any]:
    now = datetime.datetime.now()
    sev = incident.get("severity", "MEDIUM").upper()
    typ = incident.get("type", "unknown").lower()
    user = incident.get("user", "unknown")
    alerts = incident.get("related_alerts", [])

    actions = []
    actions += SEVERITY_ACTIONS.get(sev, SEVERITY_ACTIONS["MEDIUM"])
    actions += TYPE_ACTIONS.get(typ, [])

    # deduplicate preserving order
    seen = set()
    deduped = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            deduped.append(a)

    print("\n=== INCIDENT RESPONSE TRIGGERED ===")
    print(f"Time      : {now.isoformat(timespec='seconds')}")
    print(f"Type      : {typ}")
    print(f"Severity  : {sev}")
    print(f"User      : {user}")
    if alerts:
        print(f"Alerts    : {', '.join(alerts)}")
    print("\nActions Taken (containment/eradication/recovery):")
    for a in deduped:
        print(f" [x] {a}")

    report = {
        "incident": incident,
        "actions": deduped,
        "timestamp": now.isoformat(timespec="seconds"),
        "playbook_version": "1.0",
    }
    out = f"ir_report_{typ}_{sev.lower()}.json"
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nIR report saved: {out}")
    print("Next: Lessons Learned review within 7 days (update runbook).")
    return report


def main():
    parser = argparse.ArgumentParser(description="SE IR automation")
    parser.add_argument("--type", default="phishing", choices=list(TYPE_ACTIONS.keys()) + ["unknown"])
    parser.add_argument("--severity", default="HIGH", choices=list(SEVERITY_ACTIONS.keys()))
    parser.add_argument("--user", default="riya@sqrock.com")
    parser.add_argument("--alerts", nargs="*", default=[])
    args = parser.parse_args()
    ir_response({"type": args.type, "severity": args.severity, "user": args.user, "related_alerts": args.alerts})


if __name__ == "__main__":
    main()
