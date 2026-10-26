#!/usr/bin/env python3
"""OSINT aggregator: build a public GitHub threat profile for awareness.

Aggregates ONLY publicly available GitHub data (unauthenticated REST API)
into a target-profile JSON plus a one-page "attacker perspective" threat
analysis. Framed for *defenders*: it shows what an adversary could learn
from a public footprint so the subject can shrink that footprint.

Usage:
    python3 github_osint_profile.py <github_username> [more users...]
"""

import json
import os
import sys
from datetime import datetime, timezone

import requests

API = "https://api.github.com"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "osint-awareness-tool"}


def _get(url):
    r = requests.get(url, headers=HEADERS, timeout=15)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def _top(items, n=5):
    return dict(sorted(items.items(), key=lambda kv: -kv[1])[:n])


def github_profile(username):
    """Aggregate public GitHub data into an awareness target profile."""
    user = _get(f"{API}/users/{username}")
    if not user:
        return None
    repos = _get(f"{API}/users/{username}/repos?per_page=100&sort=updated") or []

    langs, topics, forks_of = {}, set(), []
    for r in repos:
        if r.get("language"):
            langs[r["language"]] = langs.get(r["language"], 0) + 1
        topics.update(r.get("topics") or [])
        if r.get("fork"):
            forks_of.append(r["name"])

    recent = [
        {"name": r["name"], "updated": (r.get("pushed_at") or "")[:10],
         "language": r.get("language"), "stars": r.get("stargazers_count", 0)}
        for r in repos[:5]
    ]

    profile = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "identity": {
            "name": user.get("name"),
            "company": user.get("company"),
            "location": user.get("location"),
            "bio": user.get("bio"),
            "blog": user.get("blog"),
            "twitter": user.get("twitter_username"),
            "public_email": user.get("email"),
            "hireable": user.get("hireable"),
            "account_created": user.get("created_at"),
        },
        "social_graph": {
            "followers": user.get("followers"),
            "following": user.get("following"),
            "public_repos": user.get("public_repos"),
            "public_gists": user.get("public_gists"),
        },
        "technical_fingerprint": {
            "top_languages": _top(langs),
            "repo_topics": sorted(topics)[:15],
            "recent_repos": recent,
            "fork_count": len(forks_of),
        },
        "exposure_findings": [],
        "footprint_score": 0,
    }
    profile["exposure_findings"] = _assess(profile)
    profile["footprint_score"] = min(
        100, sum(f["weight"] for f in profile["exposure_findings"])
    )
    return profile


def _assess(p):
    """Score each exposed data point by how useful it is to an attacker."""
    f = []
    ident, tech = p["identity"], p["technical_fingerprint"]

    def add(item, detail, weight):
        f.append({"item": item, "detail": detail, "weight": weight})

    if ident["public_email"]:
        add("public_email", ident["public_email"], 25)
    if ident["company"]:
        add("employer", f"Employer disclosed: {ident['company']}", 15)
    if ident["location"]:
        add("location", f"Location disclosed: {ident['location']}", 10)
    if ident["twitter"] or ident["blog"]:
        add("external_links",
            f"Cross-linked to twitter/{ident['twitter']} blog={ident['blog']}", 10)
    if tech["top_languages"]:
        add("tech_stack",
            "Languages reveal frameworks/tools an attacker can pretext around: "
            + ", ".join(tech["top_languages"]), 15)
    if tech["repo_topics"]:
        add("project_interests", "Topics signal current projects/priorities", 10)
    if (p["social_graph"]["followers"] or 0) > 50:
        add("influence", "Notable follower graph aids impersonation/rapport", 5)
    return f


def _report_md(p):
    ident, sg, tech = p["identity"], p["social_graph"], p["technical_fingerprint"]
    findings = "\n".join(
        f"| {f['item']} | {f['detail']} | {f['weight']} |"
        for f in p["exposure_findings"]
    ) or "| (none) | No high-signal exposure found | 0 |"

    return f"""# Attacker-Perspective Threat Analysis — `{p['username']}`

_Generated {p['generated_at']} from public GitHub data only._

## 1. Snapshot
- **Name:** {ident['name']}
- **Employer:** {ident['company']}
- **Location:** {ident['location']}
- **Public email:** {ident['public_email']}
- **Followers / Following:** {sg['followers']} / {sg['following']}
- **Account age since:** {ident['account_created']}
- **Top languages:** {', '.join(tech['top_languages']) or 'n/a'}

## 2. What an attacker can learn (exposure inventory)
| Data point | Why it matters to an adversary | Weight |
|---|---|---|
{findings}

**Footprint score: {p['footprint_score']}/100** (higher = more useful to an attacker).

## 3. Likely attack chain (defensive framing)
1. **Recon** — clone this profile to map role, employer, tools, and contacts.
2. **Pretext** — craft a message that references the real tech stack/topics
   (e.g. "about your repo X", "our shared {next(iter(tech['top_languages']), 'stack')} upgrade").
3. **Channel** — LinkedIn/GitHub DM or the exposed `public_email` above.
4. **Payload** — malicious dependency, "collaboration" repo invite, or a
   calendar/CI-secrets lure themed on the victim's active projects.

## 4. Footprint-reduction checklist
- [ ] Remove or alias the public email; use GitHub's noreply address.
- [ ] Scrub employer/location/bio unless operationally required.
- [ ] Unlink personal Twitter/blog from the professional profile.
- [ ] Keep private repos private; audit commit author emails (`git log`).
- [ ] Review followers/following for unknown or impersonation accounts.
- [ ] Enable 2FA + scoped tokens; never commit secrets or CI credentials.
- [ ] Re-run this tool quarterly to measure footprint drift.

_This report is for authorized awareness training. Only public data is used._
"""


def run(usernames):
    os.makedirs(OUT_DIR, exist_ok=True)
    for username in usernames:
        print(f"[*] Aggregating public profile for '{username}' ...")
        prof = github_profile(username)
        if not prof:
            print(f"    [!] user '{username}' not found, skipping")
            continue
        jpath = os.path.join(OUT_DIR, f"profile_{username}.json")
        with open(jpath, "w") as fh:
            json.dump(prof, fh, indent=2)
        mpath = os.path.join(OUT_DIR, f"attacker_perspective_{username}.md")
        with open(mpath, "w") as fh:
            fh.write(_report_md(prof))
        print(f"    [+] {jpath}")
        print(f"    [+] {mpath}  (footprint score {prof['footprint_score']}/100)")


if __name__ == "__main__":
    targets = sys.argv[1:] or ["torvalds"]
    run(targets)
