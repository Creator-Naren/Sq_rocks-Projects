# Attacker-Perspective Threat Analysis — `torvalds`

_Generated 2026-10-10T07:38:02.872316+00:00 from public GitHub data only._

## 1. Snapshot
- **Name:** Linus Torvalds
- **Employer:** Linux Foundation
- **Location:** Portland, OR
- **Public email:** None
- **Followers / Following:** 327025 / 0
- **Account age since:** 2011-09-03T15:26:22Z
- **Top languages:** C, OpenSCAD, C++

## 2. What an attacker can learn (exposure inventory)
| Data point | Why it matters to an adversary | Weight |
|---|---|---|
| employer | Employer disclosed: Linux Foundation | 15 |
| location | Location disclosed: Portland, OR | 10 |
| tech_stack | Languages reveal frameworks/tools an attacker can pretext around: C, OpenSCAD, C++ | 15 |
| influence | Notable follower graph aids impersonation/rapport | 5 |

**Footprint score: 45/100** (higher = more useful to an attacker).

## 3. Likely attack chain (defensive framing)
1. **Recon** — clone this profile to map role, employer, tools, and contacts.
2. **Pretext** — craft a message that references the real tech stack/topics
   (e.g. "about your repo X", "our shared C upgrade").
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
