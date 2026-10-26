# Fake-Profile Detection: Analysis of 5 Anonymized Samples

Companion to `fake_profile_scorer.py`. Handles, photos, and bios are
anonymized/synthetic; only the *behavioral shape* is real. Scores come from
`fake_profile_scores.txt`.

## Scoring model

Each fired signal adds weighted points; the total is capped at 100. Every
point is traceable to a named signal so an analyst can challenge it.

| Band | Score | Meaning |
|---|---|---|
| Likely genuine | 0–24 | No meaningful fake signals |
| Low | 25–44 | Weak signals only — probably organic |
| Suspicious | 45–69 | Investigate before trusting |
| High | 70–100 | Likely fake/bot/impersonation |

Impersonation tells (cloned photo, mirrored handle, real name on a wrong
handle) are **correlated**, so only the strongest one is counted — a single
clone cannot stack redundant points. An independent
`IMPERSONATION DETECTED` flag fires whenever any of them is present.

## Results at a glance

| # | Handle | Score | Verdict | Impersonation? |
|---|---|---|---|---|
| 1 | @ananya_rao | 0 | Likely genuine | No |
| 2 | @crypto_giveaway_100x8843 | 100 | High | **Yes** (cloned CEO photo) |
| 3 | @priya.sharma_ | 77 | High | **Yes** (cloned photo + mirrored handle) |
| 4 | @arjun_m | 65 | Suspicious | No |
| 5 | @sarah.j | 32 | Low | No |

---

## Per-profile analysis

### P1 — @ananya_rao — 0 / Likely genuine
A 4-year-old account with 3,200 followers against 410 follows (ratio 0.13),
640 posts, a real photo, and a specific human bio. **Nothing fires.** This is
the correct floor: an established account that posts and has organic
engagement should not be flagged. Its only "weakness" is that the profile is
ordinary — which is exactly what a genuine user looks like.

### P2 — @crypto_giveaway_100x8843 — 100 / High (bot + impersonation)
Textbook disposable scam account. It stacks almost every independent family:
brand-new (4 days), a 415:1 follow ratio, zero posts, no photo, default bio,
a display name containing "Crypto"/"Giveaway"/digits, and an auto-generated
handle (`...100x8843`). Decisively, its **profile photo hash matches a real
executive (@vikramceo)** — a cloned-photo impersonation. This is what a
"giveaway" or fake-support account looks like the moment it is created.

### P3 — @priya.sharma_ — 77 / High (targeted impersonation)
The most dangerous class: **not a mass bot — a targeted clone.** It is only
40 days old with a modest 85 followers, but three things give it away:

- Its **photo hash matches the real @priyasharma** (cloned photo, +25).
- Its handle `priya.sharma_` **normalizes to `priyasharma`** — an
  underscore-added impersonation. Note that a naive "normalize the handle"
  check would treat this as the *real* account; only comparing the raw
  handle exposes it.
- It mass-follows (ratio 10.6) and has almost no posts — a freshly built
  account whose only job is to look real before a social-engineering approach.

Its bio ("Marketing lead | Speaker | DM for collabs") is copied to look
plausible. This profile is built to slide into a target's DMs, not to spam a
timeline. **High confidence, relationship-based risk.**

### P4 — @arjun_m — 65 / Suspicious (dormant or hijacked)
Old (2,100 days) yet derelict: **8,000 follows against 150 followers** and
only 2 posts. The account is old, which defeats the "brand-new" signal, but
the graph is completely unnatural — a real user does not follow 8,000 people
and post twice in six years. Two explanations fit: an abandoned account
**hijacked and repurposed** for mass-following/spam, or a purchased aged
account used to lend false legitimacy (often to an impersonation attempt).
The `content:dormant_old` signal captures this "old shell" pattern.
**Investigate: never trust an aged account on age alone.**

### P5 — @sarah.j — 32 / Low (the false-positive trap)
Brand-new (20 days) with an empty bio, 40 followers, 60 follows, a real
photo, and 6 posts. Only age and the empty bio fire. This is
**indistinguishable from a genuine newcomer** and is deliberately included to
show the model's limits: any rule that flags every young, sparse account
will flag every real person who just signed up. At 32 (Low) it produces a
soft signal, not an accusation. **A new account with organic follows, a real
photo, and early posts should be greeted, not blocked.**

---

## What the samples teach

1. **Volume signals (P2, P4) vs. relationship signals (P3).** Mass bots are
   caught by graph/age/content heuristics. Targeted impersonators are quiet
   and are caught almost entirely by *identity comparison* — cloned photo,
   mirrored/typosquatted handle, real name on a wrong handle. Detection
   needs both families.
2. **Age is a trap in both directions.** New → bot (P2); old → trusted (P4,
   which is actually hijacked). Combine age with graph and content.
3. **Handle normalization hides impersonators.** `priya.sharma_`,
   `priyаsharma` (Cyrillic а), and `priyasharma` can all normalize to the
   same string. Compare raw handles, and add homoglyph/Unicode folding for
   production.
4. **Heuristics produce false positives (P5).** The output is a *risk
   score*, not proof. Use it to prioritise human review, never to
   auto-accuse.

## Recommendations for defenders

- **Maintain a reference registry** of real personnel/brand handles and
  their photo hashes; refresh it — impostors clone the newest photos.
- **Compare raw handles**, add homoglyph folding, and watch for
  punctuation/underscore/digit padding.
- **Correlate behaviors, not single signals.** A 2-day-old account with 900
  follows and 0 posts is a much stronger signal than any one of those.
- **Treat out-of-band contact as the trigger.** If a "colleague" DMs a
  request for money, files, or credentials, verify on a channel you already
  trust — the profile score is only supporting evidence.
- **Feed scores into awareness training**: show staff these five shapes,
  especially the quiet P3 clone that looks the most normal.
- **Add perceptual-hash matching** (pHash/aHash) instead of exact string
  hashes for photos, to catch recompressed clones.
- **Log and monitor** newly created accounts referencing your people/brands,
  and mass-follow events.

## Limitations

- Pure heuristics: no ML, no platform graph data, no temporal posting
  cadence, no language/link analysis.
- `REAL_ACCOUNTS` is a stand-in registry; real deployments need a governed
  source of truth and privacy controls.
- Score is a *prioritisation aid*. Verify before acting — P5 shows why.
