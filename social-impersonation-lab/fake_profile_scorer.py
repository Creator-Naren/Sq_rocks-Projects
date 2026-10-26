#!/usr/bin/env python3
"""Fake / bot / impersonation profile scorer for Twitter/X-like data.

Defensive tooling: scores a profile from behavioral heuristics and returns an
*explained* result (every point maps to a named signal), so an analyst can
see why the score is what it is instead of trusting a black box.

Signal families
    age      - brand-new accounts used for disposable attacks
    graph    - follower:following imbalance, mass-following, bought followers
    content  - empty/derelict timelines, default bios
    identity - generic names, auto-generated handles
    impersonation - cloned profile photo, handle mirroring a real person,
                    real display name on a wrong handle

Reference registry (`REAL_ACCOUNTS`) lets the identity signals fire; replace it
with your own known-personnel / verified-brand list in production.

Run:
    python3 fake_profile_scorer.py                 # score the 5 samples
    python3 fake_profile_scorer.py -j profiles.json
    python3 fake_profile_scorer.py -j p.json --min-score 45
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Reference data: the "known real" people/brands an impersonator would clone.
# In production this is your exec/brand/verified-account list.
# ---------------------------------------------------------------------------
REAL_ACCOUNTS = {
    "priyasharma":  {"display_name": "Priya Sharma",  "photo_hash": "a1b2c3"},
    "vikramceo":    {"display_name": "Vikram Nair",   "photo_hash": "ff9988"},
    "sqrockhelpdesk": {"display_name": "Sqrock Help", "photo_hash": "00aa11"},
}

SCAM_WORDS = {"giveaway", "airdrop", "winner", "claim", "bonus", "crypto",
              "investment", "doubler", "free", "prize", "official"}
DIGITS_RE = re.compile(r"\d")
TRAILING_DIGITS_RE = re.compile(r"\d{4,}$")


@dataclass
class Signal:
    name: str
    weight: int
    fired: bool
    reason: str


@dataclass
class Result:
    handle: str
    score: int
    verdict: str
    signals: list[Signal] = field(default_factory=list)
    impersonation: bool = False

    @property
    def fired(self) -> list[Signal]:
        return [s for s in self.signals if s.fired]


def levenshtein(a: str, b: str) -> int:
    """Iterative edit distance (stdlib, no deps)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_handle(handle: str) -> str:
    return re.sub(r"[^a-z0-9]", "", handle.lower())


def verdict_for(score: int) -> str:
    if score >= 70:
        return "HIGH — likely fake/bot"
    if score >= 45:
        return "SUSPICIOUS — investigate"
    if score >= 25:
        return "LOW — weak signals"
    return "LIKELY GENUINE"


def score_profile(profile: dict, ref: dict = REAL_ACCOUNTS) -> Result:
    age = int(profile.get("account_age_days", 365))
    followers = int(profile.get("followers", 0))
    following = int(profile.get("following", 0))
    posts = int(profile.get("posts", 0))
    has_pic = profile.get("has_profile_pic", not profile.get("no_profile_pic", False))
    bio = (profile.get("bio") or "").strip()
    default_bio = bool(profile.get("default_bio", not bio))
    handle = profile.get("handle", "")
    display = (profile.get("display_name") or "").strip()
    verified = bool(profile.get("verified", False))
    photo_hash = profile.get("photo_hash", "")

    raw = handle.lower().strip()
    norm = normalize_handle(handle)
    ratio = following / max(followers, 1)

    sig: list[Signal] = []

    def add(name, weight, fired, reason):
        sig.append(Signal(name, weight, bool(fired), reason))

    # --- age ---------------------------------------------------------------
    if age < 7:
        add("age:brand_new", 30, True, f"created {age}d ago (<1 week)")
    elif age < 30:
        add("age:brand_new", 22, True, f"created {age}d ago (<1 month)")
    elif age < 90:
        add("age:brand_new", 12, True, f"created {age}d ago (<3 months)")

    # --- graph -------------------------------------------------------------
    add("graph:mass_follow", 25, ratio > 10,
        f"following/followers = {ratio:.1f} (>10)")
    add("graph:ratio_elevated", 15, 5 < ratio <= 10,
        f"following/followers = {ratio:.1f} (5-10)")
    add("graph:tiny_followers", 20, followers < 10 and following > 200,
        f"only {followers} followers while following {following}")
    add("graph:following_ceiling", 15, following > 5000,
        f"follows {following} (near platform/API ceiling)")
    add("graph:bought_followers", 10,
        followers > 1000 and age < 60 and posts < 10,
        f"{followers} followers but {age}d old and {posts} posts")

    # --- content -----------------------------------------------------------
    add("content:no_pic", 20, not has_pic, "no profile photo")
    add("content:few_posts", 15, posts < 5, f"only {posts} posts")
    add("content:dormant_old", 10, posts < 5 and age > 730,
        f"{age}d old account with {posts} posts (dormant or hijacked)")
    add("content:default_bio", 10, default_bio, "empty/default bio")

    # --- identity ----------------------------------------------------------
    generic_display = bool(DIGITS_RE.search(display)) or \
        any(w in display.lower() for w in SCAM_WORDS)
    add("identity:generic_name", 10, generic_display,
        f"display name '{display}' uses digits/scam words")
    auto_handle = bool(TRAILING_DIGITS_RE.search(handle)) or \
        (len(norm) > 18 and not re.search(r"[aeiou]{2}", norm))
    add("identity:auto_handle", 10, auto_handle,
        f"handle '{handle}' looks auto-generated")

    # --- impersonation -----------------------------------------------------
    # Impersonation tells are correlated; keep only the strongest so a single
    # clone cannot stack redundant points.
    impersonation: list[Signal] = []
    real_by_hash = {v["photo_hash"]: h for h, v in ref.items()}
    if photo_hash and photo_hash in real_by_hash and raw != real_by_hash[photo_hash]:
        impersonation.append(Signal(
            "impersonation:cloned_photo", 25, True,
            f"photo matches real @{real_by_hash[photo_hash]}"))
    for real_handle, meta in ref.items():
        if norm == real_handle and raw != real_handle:
            impersonation.append(Signal(
                "impersonation:handle_mirror", 20, True,
                f"handle normalizes to real @{real_handle}"))
            break
        if norm and levenshtein(norm, real_handle) <= 2 and norm != real_handle:
            impersonation.append(Signal(
                "impersonation:typosquat_handle", 18, True,
                f"handle is {levenshtein(norm, real_handle)} edits from "
                f"real @{real_handle}"))
            break
    for real_handle, meta in ref.items():
        real_first = meta["display_name"].split()[0].lower()
        if display and real_first and display.lower().startswith(real_first) \
                and norm != real_handle:
            impersonation.append(Signal(
                "impersonation:name_on_wrong_handle", 15, True,
                f"display name '{display}' echoes real "
                f"{meta['display_name']} on a different handle"))
            break
    if impersonation:
        sig.append(max(impersonation, key=lambda s: s.weight))

    # --- mitigation --------------------------------------------------------
    add("mitigation:verified", -20, verified,
        "platform-verified (note: checkmarks can be purchased)")

    total = sum(s.weight for s in sig if s.fired)
    score = max(0, min(total, 100))
    result = Result(handle or display or "?", score, verdict_for(score), sig)
    result.impersonation = any(s.fired and s.name.startswith("impersonation")
                               for s in sig)
    return result


# ---------------------------------------------------------------------------
# 5 anonymized samples for the analysis deliverable.
# ---------------------------------------------------------------------------
SAMPLES = [
    {  # P1: established, consistent engagement -> genuine
        "handle": "ananya_rao",
        "display_name": "Ananya Rao",
        "account_age_days": 1450,
        "followers": 3200,
        "following": 410,
        "posts": 640,
        "has_profile_pic": True,
        "photo_hash": "1122aa",
        "bio": "Product designer at a mid-size SaaS. Opinions my own.",
        "default_bio": False,
        "verified": False,
    },
    {  # P2: classic crypto giveaway bot -> obvious fake
        "handle": "crypto_giveaway_100x8843",
        "display_name": "Crypto Giveaway 100x",
        "account_age_days": 4,
        "followers": 12,
        "following": 4980,
        "posts": 0,
        "has_profile_pic": False,
        "photo_hash": "ff9988",
        "bio": "",
        "default_bio": True,
        "verified": False,
    },
    {  # P3: targeted impersonation of a real person (cloned photo + name)
        "handle": "priya.sharma_",
        "display_name": "Priya S.",
        "account_age_days": 40,
        "followers": 85,
        "following": 900,
        "posts": 3,
        "has_profile_pic": True,
        "photo_hash": "a1b2c3",
        "bio": "Marketing lead | Speaker | DM for collabs",
        "default_bio": False,
        "verified": False,
    },
    {  # P4: old but derelict account, mass-following -> dormant/hijacked
        "handle": "arjun_m",
        "display_name": "Arjun Mehta",
        "account_age_days": 2100,
        "followers": 150,
        "following": 8000,
        "posts": 2,
        "has_profile_pic": True,
        "photo_hash": "77cc44",
        "bio": "Coffee, code, cricket.",
        "default_bio": False,
        "verified": False,
    },
    {  # P5: genuine but brand-new & sparse -> heuristic false-positive risk
        "handle": "sarah.j",
        "display_name": "Sarah James",
        "account_age_days": 20,
        "followers": 40,
        "following": 60,
        "posts": 6,
        "has_profile_pic": True,
        "photo_hash": "9f8e7d",
        "bio": "",
        "default_bio": True,
        "verified": False,
    },
]


def format_result(index: int, r: Result) -> str:
    lines = [f"\n{'=' * 62}",
             f"PROFILE {index}: @{r.handle}",
             f"  Score   : {r.score}%   Verdict: {r.verdict}"]
    if r.impersonation:
        lines.append("  >>> IMPERSONATION OF A KNOWN ACCOUNT DETECTED <<<")
    lines.append("  Signals fired:")
    if not r.fired:
        lines.append("    (none)")
    for s in sorted(r.fired, key=lambda x: -abs(x.weight)):
        sign = "+" if s.weight > 0 else ""
        lines.append(f"    {sign}{s.weight:>3}  {s.name:<38} {s.reason}")
    lines.append(f"{'=' * 62}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fake-profile heuristic scorer")
    parser.add_argument("-j", "--json", help="JSON file with a list of profiles")
    parser.add_argument("--min-score", type=int, default=0,
                        help="only report profiles at/above this score")
    args = parser.parse_args()

    if args.json:
        try:
            profiles = json.load(open(args.json))
        except (OSError, json.JSONDecodeError) as exc:
            sys.exit(f"cannot load {args.json}: {exc}")
    else:
        profiles = SAMPLES

    printed = 0
    for i, profile in enumerate(profiles, start=1):
        result = score_profile(profile)
        if result.score >= args.min_score:
            print(format_result(i, result))
            printed += 1

    print(f"\nScored {len(profiles)} profile(s); reported {printed} "
          f"(min-score={args.min_score}).")
    print("Reminder: heuristics flag *risk*, not proof — verify before acting.")


if __name__ == "__main__":
    main()
