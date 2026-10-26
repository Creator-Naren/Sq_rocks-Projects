#!/usr/bin/env python3
"""Social-engineering awareness-training script generator.

Produces vishing (voice phishing) and smishing (SMS phishing) *awareness*
scripts for security-training use. Every generated script embeds the
psychological trigger it exploits and the corresponding defensive red flag,
so trainers can pause and debrief during the exercise.
"""

from dataclasses import dataclass, field


@dataclass
class Scenario:
    name: str
    channel: str            # "vishing" | "smishing"
    target_company: str
    attacker_role: str
    pretext: str
    opener: str
    hook: str
    urgency_line: str
    ask: str
    triggers: list[str] = field(default_factory=list)
    red_flags: list[str] = field(default_factory=list)
    debrief: str = ""


TRIGGER_NOTES = {
    "authority":    "Impersonates a trusted role (IT, banker, official) so the "
                    "target defers instead of questioning.",
    "fear":         "Threatens loss (locked account, frozen funds, warrant) to "
                    "trigger fast, emotion-driven compliance.",
    "urgency":      "A countdown suppresses verification habits — act now, "
                    "think later is the attacker's goal.",
    "scarcity":     "An expiring benefit or limited window pushes the target "
                    "to act before thinking.",
    "liking":       "Friendly, helpful tone and first-name basis build rapport "
                    "and social obligation to reciprocate.",
    "social_proof": "Claims others already complied, so compliance feels like "
                    "the norm.",
    "pretext_consistency": "A detailed, plausible story that answers questions "
                    "before they are asked reduces suspicion.",
}


def generate_vishing_script(s: Scenario) -> str:
    triggers = "\n".join(f"  - {t.upper()}: {TRIGGER_NOTES[t]}" for t in s.triggers)
    red_flags = "\n".join(f"  -> {r}" for r in s.red_flags)
    return f"""
=== VISHING AWARENESS SCRIPT ===
Scenario    : {s.name}
Caller Role : {s.attacker_role}
Target Org  : {s.target_company}
Pretext     : {s.pretext}

[OPENER]  {s.opener}
[HOOK]    {s.hook}
[URGENCY] {s.urgency_line}
[ASK]     {s.ask}

[RED FLAGS for Awareness]
{red_flags}

[PSYCHOLOGICAL TRIGGERS]
{triggers}

[DEBRIEF]
{s.debrief}
"""


def generate_smishing_script(s: Scenario) -> str:
    triggers = "\n".join(f"  - {t.upper()}: {TRIGGER_NOTES[t]}" for t in s.triggers)
    red_flags = "\n".join(f"  -> {r}" for r in s.red_flags)
    return f"""
=== SMISHING AWARENESS SCRIPT ===
Scenario    : {s.name}
Sender ID   : {s.attacker_role}  (spoofed display name)
Target Org  : {s.target_company}
Pretext     : {s.pretext}

[MESSAGE]
{s.opener}
{s.hook}
{s.urgency_line}
{s.ask}

[RED FLAGS for Awareness]
{red_flags}

[PSYCHOLOGICAL TRIGGERS]
{triggers}

[DEBRIEF]
{s.debrief}
"""


def trigger_analysis(scenarios: list[Scenario]) -> str:
    lines = ["\n================ PSYCHOLOGICAL TRIGGER ANALYSIS ================"]
    counts: dict[str, int] = {}
    for s in scenarios:
        for t in s.triggers:
            counts[t] = counts.get(t, 0) + 1
        lines.append(f"\n{s.name} ({s.channel})")
        lines.append("  " + ", ".join(s.triggers))
    lines.append("\n--- Frequency across all scripts ---")
    for t, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {t:<22} {c}/{len(scenarios)}")
    lines.append(
        "\nKey takeaway: fear + urgency appear in all scripts; authority in\n"
        "every voice script. Training should teach ONE counter-habit: stop and\n"
        "verify through an independent channel (official number / internal\n"
        "portal) before acting.\n"
        "==============================================================="
    )
    return "\n".join(lines)


IT_SCENARIO = Scenario(
    name="IT Helpdesk Password Reset",
    channel="vishing",
    target_company="Sqrock IT",
    attacker_role="IT Support",
    pretext="Password Reset / unusual login activity",
    opener="'Hi, this is Narendra Borhade from IT Support at Sqrock IT. We "
           "detected unusual activity on your account.'",
    hook="'I need to verify your identity — can you confirm your employee ID "
         "and current password?'",
    urgency_line="'Security wants this closed within the hour or your account "
                 "gets suspended.'",
    ask="'Just read me the code when it lands on your phone.'",
    triggers=["authority", "fear", "urgency", "liking"],
    red_flags=[
        "Legitimate IT will NEVER ask for passwords.",
        "MFA codes must never be shared — no real helpdesk requests them.",
        "Always verify via official internal channels (call back on the "
        "published helpdesk number).",
        "Unexpected contact about 'unusual activity' is a manufactured crisis.",
    ],
    debrief="Trainer: ask the trainee what tipped them off. Reinforce the "
            "call-back rule — hang up, dial the known internal number, and ask "
            "if a ticket exists.",
)

BANK_SCENARIO = Scenario(
    name="Bank Card Fraud Alert",
    channel="vishing",
    target_company="First Meridian Bank",
    attacker_role="Fraud Department",
    pretext="Unauthorized transaction pending on debit card",
    opener="'Good morning, this is Narendra Borhade calling from the First "
           "Meridian Bank fraud team regarding your account.'",
    hook="'We blocked a $2,400 charge, but to release your card I must verify "
         "you — full name, and the one-time code we just sent.'",
    urgency_line="'If we don't confirm in the next 10 minutes the card will be "
                 "permanently declined.'",
    ask="'Confirm the 6-digit code so I can reverse the fraud hold.'",
    triggers=["authority", "fear", "urgency", "pretext_consistency"],
    red_flags=[
        "Banks never ask for OTP/CVV or full card details by phone.",
        "Caller ID is trivially spoofed — a real bank name proves nothing.",
        "The 'code we just sent' is the smishing/vishing 2FA-bypass pattern.",
        "Hang up and call the number on the back of your card.",
    ],
    debrief="Trainer: highlight that the caller already 'knew' the target — "
            "partial knowledge is manufactured, not proof of legitimacy.",
)

GOV_SCENARIO = Scenario(
    name="Government Tax Warrant Notice",
    channel="vishing",
    target_company="State Revenue Agency",
    attacker_role="Tax Enforcement Officer",
    pretext="Unpaid taxes / outstanding warrant",
    opener="'This is Narendra Borhade with the State Revenue Agency. This "
           "call is being recorded for compliance.'",
    hook="'There is a warrant for your arrest over unpaid taxes. You can "
         "resolve it today with a settlement payment.'",
    urgency_line="'A field officer is dispatched unless payment clears within "
                 "30 minutes.'",
    ask="'Read me the routing number so we can process the settlement.'",
    triggers=["authority", "fear", "urgency", "pretext_consistency"],
    red_flags=[
        "Government agencies initiate contact by official mail, not threats "
        "by phone.",
        "No agency demands immediate payment or banking details under arrest "
        "threats.",
        "'This call is recorded' is theater designed to borrow legitimacy.",
        "Verify independently via the agency's published website/number.",
    ],
    debrief="Trainer: contrast real agency procedures (written notices, "
            "appeal windows) with the script's impossible timeline.",
)

SMISHING_SCENARIO = Scenario(
    name="Package Delivery Smish",
    channel="smishing",
    target_company="National Parcel Service",
    attacker_role="Narendra Borhade",
    pretext="Held parcel awaiting fee payment",
    opener="'NPS: Your parcel is on hold. A $1.99 fee is required for "
           "re-delivery.'",
    hook="'Track & pay: npspay.example/r/8xQ'",
    urgency_line="'Pay within 2 hours to avoid return to sender.'",
    ask="'Tap the link and enter card details to release delivery.'",
    triggers=["urgency", "fear", "scarcity", "social_proof"],
    red_flags=[
        "Shortened/lookalike domains are the #1 smishing indicator.",
        "Tiny unexpected fees are the pretext for harvesting full card data.",
        "Carriers never collect payment via text links.",
        "Type the official site yourself; never tap the link.",
    ],
    debrief="Trainer: run the 'hover before you click' rule and show how the "
            "displayed brand differs from the actual URL.",
)


def main() -> None:
    scenarios = [IT_SCENARIO, BANK_SCENARIO, GOV_SCENARIO, SMISHING_SCENARIO]
    for s in scenarios:
        if s.channel == "vishing":
            print(generate_vishing_script(s))
        else:
            print(generate_smishing_script(s))
    print(trigger_analysis(scenarios))


if __name__ == "__main__":
    main()
