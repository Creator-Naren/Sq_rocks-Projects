#!/usr/bin/env python3
"""Spear-phishing awareness-training email template engine (lab only).

Renders personalized *training* drafts from OSINT fields (name, work email,
employer, location) the way a spear-phish would be built, then annotates each
draft with red flags, psychological triggers, and a debrief so a trainer can
run the simulation and teach from it.

Lab safety: nothing is sent, links point at the internal sink
(lab.internal/awareness-test), and every domain is RFC 2606 reserved
(.example) until the trainer swaps in the authorized simulation domain.

Deliverables: 3 personalized drafts (printed below / spear_phish_drafts.txt)
+ DMARC/SPF/DKIM setup guide for defenders (DMARC_SPF_DKIM_GUIDE.md).

Usage:
    python3 spear_phish_template.py              # 3-draft campaign
    python3 spear_phish_template.py --matrix     # every target x template
    python3 spear_phish_template.py -o FILE      # also write output
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

LAB_LINK = "https://lab.internal/awareness-test"
SENDER_TLD = ".example"  # swap for the authorized simulation domain

TRIGGER_NOTES = {
    "authority":    "Impersonates a trusted role (IT, helpdesk, People Ops) so "
                    "the target defers instead of questioning.",
    "fear":         "Threatens loss (locked account, lost access) to trigger "
                    "fast, emotion-driven compliance.",
    "urgency":      "A countdown suppresses verification habits — act now, "
                    "think later is the attacker's goal.",
    "liking":       "A familiar colleague's name and friendly tone build "
                    "rapport and social obligation to reciprocate.",
    "social_proof": "Claims others already complied, so compliance feels like "
                    "the norm.",
    "curiosity":    "A document or notification that seems to concern the "
                    "target personally pulls them into opening it.",
}


@dataclass(frozen=True)
class Target:
    name: str
    email: str
    company: str
    location: str

    @property
    def first(self) -> str:
        return self.name.split()[0]

    @property
    def slug(self) -> str:
        return "".join(ch for ch in self.company.lower() if ch.isalnum())


@dataclass
class EmailTemplate:
    name: str
    vector: str
    sender_role: str              # local-part of the spoofed From address
    subject: str                  # format-string, fields from render context
    body: str                     # format-string
    attachment: str = ""
    triggers: list[str] = field(default_factory=list)
    red_flags: list[str] = field(default_factory=list)
    debrief: str = ""


def render(tpl: EmailTemplate, target: Target) -> dict[str, str]:
    """Fill a template for one target; returns the draft's mail fields."""
    ctx = {
        "name": target.first,
        "full_name": target.name,
        "email": target.email,
        "company": target.company,
        "sender_domain": f"{target.slug}{SENDER_TLD}",
        "location": target.location,
        "link": LAB_LINK,
        "attachment": tpl.attachment,
    }
    return {
        "from": f"{tpl.sender_role}@{ctx['sender_domain']}",
        "to": target.email,
        "subject": tpl.subject.format_map(ctx),
        "body": tpl.body.format_map(ctx),
    }


def format_draft(index: int, total: int, tpl: EmailTemplate,
                 target: Target, mail: dict[str, str]) -> str:
    triggers = "\n".join(
        f"  - {t.upper()}: {TRIGGER_NOTES[t]}" for t in tpl.triggers
    )
    red_flags = "\n".join(f"  -> {r}" for r in tpl.red_flags)
    attachment = f"\nAttachment : {tpl.attachment}" if tpl.attachment else ""
    return f"""
=== SPEAR-PHISH AWARENESS EMAIL DRAFT {index}/{total} ===
Scenario    : {tpl.name}
Vector      : {tpl.vector}
Target      : {target.name} — {target.company} ({target.location})
From        : {mail['from']}   [SPOOFED — lab simulation]
To          : {mail['to']}{attachment}
Subject     : {mail['subject']}

[EMAIL BODY]
{mail['body'].strip()}

[RED FLAGS for Awareness]
{red_flags}

[PSYCHOLOGICAL TRIGGERS]
{triggers}

[DEBRIEF]
Trainer: {tpl.debrief}
"""


ACCOUNT_LOCKOUT = EmailTemplate(
    name="Account Suspension / Unusual Login",
    vector="credential-harvest link, spoofed IT sender",
    sender_role="it-support",
    subject="Action Required: Your {company} account will be disabled",
    body="""
Hi {name},

Our security team noticed a login to your {company} account from
{location} at 23:41 yesterday.

If this wasn't you, verify your account within 24 hours to avoid
suspension:

[Verify Account] -> {link}

If you recognize this activity, no action is needed after verifying.

Regards,
IT Security Team
{company}
""",
    triggers=["authority", "fear", "urgency"],
    red_flags=[
        "Manufactured crisis: a 24-hour deadline exists to stop you from "
        "verifying anything.",
        "Hover the button — trust the destination domain, never the label "
        "text. This lab link resolves to lab.internal.",
        "Real lockout notices also arrive as an in-portal banner or MFA "
        "prompt; a cold email alone is not how IT suspends accounts.",
        "The login-from-your-city detail is OSINT garnish — knowing your "
        "city proves the sender knows nothing.",
        "Verify out of band: open the portal yourself or call the helpdesk "
        "number in the internal directory.",
    ],
    debrief="Ask what made it feel authentic — the location detail usually "
            "wins. Reinforce the portal-first habit: never click a security "
            "email's link, type the address yourself.",
)

SHARED_DOCUMENT = EmailTemplate(
    name="Shared Document / Attachment Lure",
    vector="malicious attachment, spoofed colleague display name",
    sender_role="asha.kulkarni",
    subject="{full_name} shared \"Benefits_Enrollment_Q4.xlsm\" with you",
    body="""
Hi {name},

Your {company} benefits enrollment sheet is ready for review. I've
attached it here so you don't have to hunt for it in the portal.

[Benefits_Enrollment_Q4.xlsm] -> {link}

Please open it before Friday's cutoff — everyone on the People team has
already signed theirs.

Thanks,
Asha
People Operations, {company}
""",
    attachment="Benefits_Enrollment_Q4.xlsm",
    triggers=["liking", "social_proof", "curiosity"],
    red_flags=[
        "Unexpected attachment — '.xlsm' means macros; watch for "
        "double-extension tricks like 'sheet.xlsx.hta'.",
        "'Enable Content' to unlock the document is the payload, not a "
        "permission prompt.",
        "A familiar display name proves nothing; the sending domain must "
        "match the colleague's real company domain.",
        "'Everyone already signed' pressures you into being the one who "
        "hasn't — social proof on a deadline.",
        "Confirm via chat with the supposed sender before touching the "
        "file — never reply to the email to ask.",
    ],
    debrief="Run the extension drill: have trainees state what each part "
            "of 'Benefits_Enrollment_Q4.xlsm' and a '.xlsx.hta' variant "
            "actually executes. Point at DMARC in the companion guide — "
            "lookalike senders are exactly what it cannot stop.",
)

PASSWORD_EXPIRY = EmailTemplate(
    name="Password Expiry / QR Code (Quishing)",
    vector="quishing — QR code hides the real destination",
    sender_role="password-services",
    subject="Your {company} password expires today at 17:00",
    body="""
Hi {name},

Your {company} single sign-on password expires today at 17:00.

Scan the QR code below (or use the link) to renew it and keep your
session active:

+-------------------------------------------+
|  QR: {link}  |
+-------------------------------------------+

[Renew My Password] -> {link}

After 17:00, access requires an in-person helpdesk reset.

Regards,
Identity Team
{company}
""",
    triggers=["urgency", "fear", "authority"],
    red_flags=[
        "QR codes defeat 'hover to preview' — a scan shows no destination "
        "until you have already opened it.",
        "Password expiry never arrives as a same-day cold email; organizations "
        "warn weeks in advance via portal and manager notices.",
        "An 'in-person reset' threat exists only to make scanning feel like "
        "the easy option.",
        "Never log in from a page reached by scanning an email — type the "
        "SSO portal address yourself.",
        "Report these to the real IT team: same-day expiry + QR = high "
        "confidence phish.",
    ],
    debrief="Contrast this with template 1: both harvest credentials, but "
            "the QR removes the one habit people have (hover the link). "
            "Teach 'scan nothing from email' as a flat rule.",
)


def defense_footer() -> str:
    return """
================ DEFENSE MAPPING (see DMARC_SPF_DKIM_GUIDE.md) ================

Draft 1 — same-domain spoof of it-support@
         Stops with: DMARC p=reject + DKIM/SPF alignment on your domain.
Draft 2 — lookalike sender domain + attachment
         Email auth CANNOT stop this (sender is a different domain).
         Stops with: external-sender banners, attachment sandboxing, training.
Draft 3 — legitimate-looking link behind a QR code
         Email auth CANNOT stop this (payload is in the rendered image).
         Stops with: URL rewriting/safe-links, QR scanning policy, training.

Counter-habit for every draft: stop, open the official portal yourself,
verify through an independent channel before acting.
==============================================================================
"""


def build_campaign(targets: list[Target], matrix: bool) -> list[tuple]:
    templates = [ACCOUNT_LOCKOUT, SHARED_DOCUMENT, PASSWORD_EXPIRY]
    if matrix:
        return [(tpl, tgt) for tgt in targets for tpl in templates]
    return list(zip(templates, targets))


def main() -> None:
    parser = argparse.ArgumentParser(description="Spear-phish awareness "
                                                 "training draft generator")
    parser.add_argument("--matrix", action="store_true",
                        help="render every template against every target")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="also write the output to FILE")
    args = parser.parse_args()

    targets = [
        Target("Riya Sharma", "riya@sqrock.example", "Sqrock",
               "Bangalore, India"),
        Target("Arjun Mehta", "arjun.mehta@northwindlabs.example",
               "Northwind Labs", "Pune, India"),
        Target("Elena Petrova", "elena.petrova@meridianfinance.example",
               "Meridian Finance", "Berlin, Germany"),
    ]

    campaign = build_campaign(targets, args.matrix)
    parts = [
        format_draft(i, len(campaign), tpl, tgt, render(tpl, tgt))
        for i, (tpl, tgt) in enumerate(campaign, start=1)
    ]
    parts.append(defense_footer())
    output = "\n".join(parts)
    print(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[written] {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
