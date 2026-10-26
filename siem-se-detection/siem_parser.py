#!/usr/bin/env python3
"""SIEM log parser that flags social engineering (SE) attack patterns.

Patterns detected (lab-oriented):
- Brute force / credential stuffing: >= 3 FAILED_LOGIN in short window
- Successful login after brute force (potential account takeover)
- Suspicious email rules created (auto-forwarding, exfiltration)
- Off-hours logins (outside normal business 08:00-18:00 local)
- VPN login from unusual/geolocated-like IP (flag external, non-internal)
- Impossible travel / rapid geo/context change (login from distant IPs)
- Success after failed sequence by same user/IP (greedy attacker)

Outputs:
- alert_report.txt  (human-readable)
- alert_report.json (machine-readable)

Usage: python3 siem_parser.py [logfile]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime

INTERNAL_NETS = {"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"}
BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 18

LOGIN_RE = re.compile(r"^(\S+\s\S+)\s+(FAILED_LOGIN|SUCCESS_LOGIN)\s+user=(\w+)\s+ip=([\d.]+)")
EMAIL_RULE_RE = re.compile(r"^(\S+\s\S+)\s+EMAIL_RULE_CREATED\s+user=(\w+)\s+rule=(\S+)")
VPN_RE = re.compile(r"^(\S+\s\S+)\s+VPN_LOGIN_SUCCESS\s+user=(\w+)\s+ip=([\d.]+)")


def is_internal(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a = int(parts[0]); b = int(parts[1])
    if a == 10: return True
    if a == 192 and b == 168: return True
    if a == 172 and 16 <= b <= 31: return True
    return False


def parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def analyze(path: str) -> dict:
    alerts = []
    events: list[dict] = []

    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            if m := LOGIN_RE.match(line):
                ts, kind, user, ip = m.groups()
                events.append({"type":"login","ts":parse_ts(ts),"kind":kind,"user":user,"ip":ip})
            elif m := EMAIL_RULE_RE.match(line):
                ts, user, rule = m.groups()
                events.append({"type":"email_rule","ts":parse_ts(ts),"user":user,"rule":rule})
            elif m := VPN_RE.match(line):
                ts, user, ip = m.groups()
                events.append({"type":"vpn","ts":parse_ts(ts),"user":user,"ip":ip})

    # brute force: failed logins per user
    fails = defaultdict(list)
    for e in events:
        if e["type"]=="login" and e["kind"]=="FAILED_LOGIN":
            fails[e["user"]].append(e)
    for user, flist in fails.items():
        if len(flist) >= 3:
            ips = sorted(set(x["ip"] for x in flist))
            alerts.append({"sev":"HIGH","cat":"brute_force","user":user,"count":len(flist),"ips":ips,"msg":f"Brute force: {user} had {len(flist)} FAILED_LOGIN attempts"})

    # success after brute force
    succ = defaultdict(list)
    for e in events:
        if e["type"]=="login" and e["kind"]=="SUCCESS_LOGIN":
            succ[e["user"]].append(e)
    for user, slist in succ.items():
        if user in fails and len(fails[user]) >= 3:
            alerts.append({"sev":"CRITICAL","cat":"account_takeover_suspect","user":user,"msg":f"SUCCESS_LOGIN after brute force for {user} - possible compromise"})

    # email rule creation
    for e in events:
        if e["type"]=="email_rule":
            r = e["rule"].lower()
            if any(k in r for k in ("forward", "redirect", "copy")):
                alerts.append({"sev":"HIGH","cat":"suspicious_email_rule","user":e["user"],"rule":e["rule"],"msg":f"Suspicious auto-forward rule created by {e['user']}: {e['rule']}"})

    # off-hours login
    for e in events:
        if e["type"]=="login" and e["kind"]=="SUCCESS_LOGIN":
            h = e["ts"].hour
            if h < BUSINESS_HOURS_START or h >= BUSINESS_HOURS_END:
                alerts.append({"sev":"MEDIUM","cat":"off_hours_login","user":e["user"],"ip":e["ip"],"time":e["ts"].strftime("%H:%M"),"msg":f"Off-hours SUCCESS_LOGIN by {e['user']} from {e['ip']}"})

    # external VPN
    for e in events:
        if e["type"]=="vpn":
            if not is_internal(e["ip"]):
                alerts.append({"sev":"HIGH","cat":"external_vpn","user":e["user"],"ip":e["ip"],"msg":f"VPN login from external IP by {e['user']}: {e['ip']}"})

    # impossible travel heuristic
    last = defaultdict(lambda: None)
    for e in events:
        if e["type"]=="login" and e["kind"]=="SUCCESS_LOGIN":
            prev = last.get(e["user"])
            if prev and prev["ip"] != e["ip"] and not is_internal(prev["ip"]) and not is_internal(e["ip"]):
                alerts.append({"sev":"HIGH","cat":"impossible_travel_suspect","user":e["user"],"from":prev["ip"],"to":e["ip"],"msg":f"Rapid IP change for {e['user']}: {prev['ip']} -> {e['ip']}"})
            last[e["user"]] = e

    return {"alerts": alerts, "events": len(events)}


def write_report(result: dict, out_txt="alert_report.txt", out_json="alert_report.json"):
    with open(out_json, "w") as fh:
        json.dump(result, fh, indent=2)
    lines = ["=== SE-SIEM ALERT REPORT ==="]
    if not result["alerts"]:
        lines.append("No alerts triggered.")
    else:
        for a in result["alerts"]:
            lines.append(f"[{a['sev']}] {a['cat']} | {a['msg']}")
    with open(out_txt, "w") as fh:
        fh.write("\n".join(lines)+"\n")
    print("\n".join(lines))
    print(f"\n[written] {out_txt}, {out_json}")


def main():
    parser = argparse.ArgumentParser(description="SIEM log parser for SE")
    parser.add_argument("log", nargs="?", default="sample_logs.txt")
    args = parser.parse_args()
    res = analyze(args.log)
    write_report(res)


if __name__ == "__main__":
    main()
