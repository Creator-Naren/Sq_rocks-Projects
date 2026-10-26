#!/usr/bin/env python3
"""Interactive social-engineering awareness quiz (CLI).

Scenario-based questions across the SE spectrum (phishing, vishing, smishing,
baiting, pretexting, BEC, MFA abuse, physical, OSINT, drive-by download,
quishing). Immediate feedback after every answer, per-category scoring, and a
score report written to JSON.

Design follows the evidence on what makes training stick:
    * realistic scenarios (not definitions)
    * immediate feedback with the "why"
    * repetition across campaigns (re-run and compare reports)

Usage
    python3 se_quiz.py                                   # interactive
    python3 se_quiz.py --name a.participant --shuffle
    python3 se_quiz.py --answers B,A,C,D,...             # non-interactive
    python3 se_quiz.py --questions questions.json        # custom bank
    python3 se_quiz.py --export-questions questions.json # dump the bank
    python3 se_quiz.py --pass-score 80 --out report.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import random
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field

LETTERS = "ABCD"
DEFAULT_OUT = "quiz_report.json"
DEFAULT_PASS = 80


@dataclass
class Question:
    id: str
    category: str
    q: str
    opts: list[str]
    ans: str                       # correct letter
    exp: str                        # explanation shown immediately
    trigger: str = ""               # psychological trigger (cross-module link)

    @classmethod
    def from_dict(cls, d: dict) -> "Question":
        return cls(q=d["q"], opts=d["opts"], ans=d["ans"].strip().upper(),
                   exp=d.get("exp", ""), trigger=d.get("trigger", ""),
                   category=d.get("category", "general"), id=d.get("id", ""))


DEFAULT_QUESTIONS: list[Question] = [
    Question("phish-1", "phishing",
             "An email from 'IT Support' says your account will be disabled "
             "and asks you to verify your password at a link. You should:",
             ["Click the link and log in quickly",
              "Verify through the official app or call IT on a known number",
              "Reply to the email with your password",
              "Forward it to a colleague to check"],
             "B",
             "Never authenticate from an email link. Verify via the official "
             "app or a number you already trust.",
             "authority + urgency"),
    Question("bait-1", "baiting",
             "You find a USB drive labelled 'Payroll 2026' in the parking lot. "
             "You should:",
             ["Hand it to security without plugging it in",
              "Plug it into a work machine to scan it",
              "Plug it into your personal laptop to see whose it is",
              "Keep it; finders keepers"],
             "A",
             "Dropped media is a classic baiting vector (and modern sticks can "
             "emulate a keyboard). Hand it in untouched.",
             "curiosity"),
    Question("vish-1", "vishing",
             "A caller claims to be the helpdesk and asks you to read out the "
             "MFA code that just arrived. You should:",
             ["Read out the code so they can fix it",
              "Give the caller your password to speed things up",
              "Hang up and call the helpdesk on the published number",
              "Press 1 to speak to a supervisor"],
             "C",
             "No legitimate helpdesk needs your MFA code or password. Hang up "
             "and call back on a number you trust.",
             "authority + fear"),
    Question("smish-1", "smishing",
             "A text says a parcel is held and you must pay a $1.99 fee via a "
             "link. You should:",
             ["Tap the link and pay the small fee",
              "Reply STOP to unsubscribe",
              "Forward the text to friends to warn them",
              "Open the official carrier/retailer app and check your order"],
             "D",
             "Small unexpected fees are the pretext to harvest full card "
             "data. Never act on a delivery link; check the real app.",
             "urgency + scarcity"),
    Question("bec-1", "bec",
             "The CEO emails you to send an urgent wire transfer and says to "
             "keep it confidential. You should:",
             ["Process the wire immediately to keep it secret",
              "Verify by calling the executive on a known number and follow "
              "the finance process",
              "Reply to the email to confirm the details",
              "Ask the sender for their bank details"],
             "B",
             "Business email compromise relies on secrecy and urgency to bypass "
             "process. Verify out of band; never skip controls.",
             "authority + urgency"),
    Question("mfa-1", "mfa",
             "Your phone is flooded with MFA push prompts you did not request. "
             "You should:",
             ["Approve the push so the prompts stop",
              "Ignore it and change nothing",
              "Deny the request and report it to security",
              "Share the code in the work chat so IT can investigate"],
             "C",
             "MFA fatigue (push bombing) means someone has your password and is "
             "trying to get you to approve. Deny and report.",
             "fatigue + annoyance"),
    Question("pwd-1", "password",
             "Which practice best defends against credential stuffing (reusing "
             "leaked passwords)?",
             ["Reuse one strong password everywhere so you never forget it",
              "Write passwords in a shared team document",
              "Use your pet's name plus the year",
              "Use a password manager with unique passwords and enable MFA"],
             "D",
             "Unique passwords stop one breach from unlocking other accounts, "
             "and MFA blunts a stolen password.",
             "habit"),
    Question("vish-2", "pretexting",
             "A caller says they are from your bank's fraud team and asks for "
             "the one-time code to release your card. You should:",
             ["Give the one-time code so they can release the card",
              "Hang up and call the number printed on your card",
              "Give your card number and CVV to verify",
              "Provide your online banking password"],
             "B",
             "Banks never ask for OTPs, CVV, or passwords. A 'code we sent' "
             "request is the account-takeover pattern.",
             "authority + fear"),
    Question("phys-1", "physical",
             "Someone without a badge follows you through the secure door "
             "carrying boxes. You should:",
             ["Politely ask them to badge in and report anyone without a badge",
              "Hold the door - it's rude not to",
              "Let them in if their hands are full",
              "Assume they work there and move on"],
             "A",
             "Tailgating bypasses every technical control. Challenge politely "
             "and report; you will never be penalized for it.",
             "politeness + social pressure"),
    Question("phish-2", "phishing",
             "A colleague emails an unexpected 'Benefits' spreadsheet with a "
             "prompt to 'Enable Content' to view it. You should:",
             ["Enable macros so you can see the content",
              "Open it and see what happens",
              "Verify the sender out of band and never enable macros from "
              "email attachments",
              "Disable your antivirus first so it opens"],
             "C",
             "Macro-enabled documents are a top malware delivery vector. "
             "Confirm the sender on another channel; don't enable content.",
             "liking + curiosity"),
    Question("phish-3", "phishing",
             "A login page looks identical to your company SSO and shows a "
             "padlock. What is the reliable check?",
             ["Enter your credentials since the page looks identical",
              "Check the URL and reach the site by typing the known address",
              "Trust it because it has a padlock",
              "Test it with your work email and password"],
             "B",
             "Look-alike pages and TLS certificates are easy to fake. Read the "
             "domain and navigate to the site yourself.",
             "visual trust"),
    Question("osint-1", "osint",
             "How can your own social media usage help a spear-phishing "
             "attacker?",
             ["It can't; social media is separate from work",
              "Only if you post your password",
              "Public role, projects, travel, and relationships feed targeted "
              "pretexts - so limit public details",
              "It only matters for celebrities"],
             "C",
             "Public details become the personal hooks in spear-phishing. "
             "Tighten privacy settings and share less publicly.",
             "open-source reconnaissance"),
    Question("web-1", "drive-by",
             "While browsing, a site shows a pop-up: 'Your Flash/plugin is "
             "outdated - download the update now.' You should:",
             ["Close it and update only through the official OS/app updater",
              "Install the update from the pop-up",
              "Download the installer from the pop-up link",
              "Ignore all updates forever"],
             "A",
             "Fake update pop-ups deliver drive-by payloads. Patch only "
             "through built-in updaters or trusted vendor channels.",
             "urgency"),
    Question("quish-1", "quishing",
             "An unexpected email asks you to scan a QR code to 'renew your "
             "password'. You should:",
             ["Scan the QR to reach the portal quickly",
              "Scan it but don't enter the password",
              "Share the QR with IT so they can scan it",
              "Never scan QR codes from email; navigate to the official site "
              "directly"],
             "D",
             "QR codes hide their destination from hover/preview checks. Go to "
             "the official portal by typing the address yourself.",
             "urgency + convenience"),
]


def load_questions(path: str) -> list[Question]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return [Question.from_dict(d) for d in data]


def export_questions(path: str, bank: list[Question]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(q) for q in bank], fh, indent=2)
    print(f"[written] {path} ({len(bank)} questions)")


def render_question(index: int, total: int, q: Question) -> str:
    lines = [f"\nQ{index}/{total} [{q.category}]  {q.q}"]
    for letter, opt in zip(LETTERS, q.opts):
        lines.append(f"    {letter}) {opt}")
    return "\n".join(lines)


def ask_interactive() -> str:
    while True:
        raw = input("Your answer (A/B/C/D, or 'q' to quit): ").strip().upper()
        if raw == "Q":
            raise KeyboardInterrupt
        if raw and raw[0] in LETTERS:
            return raw[0]
        print("  Please enter A, B, C, or D.")


def run_quiz(bank: list[Question], answers: list[str] | None,
             participant: str, shuffle_questions: bool,
             out_path: str, pass_score: int) -> dict:
    questions = list(bank)
    if shuffle_questions:
        random.shuffle(questions)

    started = datetime.datetime.now()
    results: list[dict] = []
    answer_iter = iter(answers) if answers else None

    print("=" * 64)
    print("SOCIAL-ENGINEERING AWARENESS QUIZ")
    print("=" * 64)

    for i, q in enumerate(questions, 1):
        print(render_question(i, len(questions), q))
        if answer_iter is not None:
            try:
                chosen = next(answer_iter)
            except StopIteration:
                chosen = ""
            print(f"Your answer: {chosen or '(none)'}")
        else:
            try:
                chosen = ask_interactive()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] quiz aborted")
                break

        correct = chosen == q.ans
        if correct:
            print(f"  [CORRECT] {q.exp}")
        else:
            print(f"  [WRONG] Correct answer: {q.ans}. {q.exp}")
        results.append({
            "id": q.id,
            "category": q.category,
            "question": q.q,
            "chosen": chosen,
            "correct_answer": q.ans,
            "is_correct": correct,
            "explanation": q.exp,
            "trigger": q.trigger,
        })

    finished = datetime.datetime.now()
    total = len(results)
    correct_count = sum(1 for r in results if r["is_correct"])
    score = round(correct_count / total * 100, 1) if total else 0.0

    by_cat: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in results:
        by_cat[r["category"]]["total"] += 1
        by_cat[r["category"]]["correct"] += int(r["is_correct"])

    missed = sorted({r["category"] for r in results if not r["is_correct"]})

    print("\n" + "=" * 64)
    print("SCORE REPORT")
    print("=" * 64)
    print(f"participant : {participant}")
    print(f"score       : {correct_count}/{total}  ({score}%)")
    print(f"result      : {'PASS' if score >= pass_score else 'NEEDS REVIEW'}"
          f"  (pass = {pass_score}%)")
    print(f"duration    : {(finished - started).seconds}s")
    print("by category :")
    for cat, c in sorted(by_cat.items()):
        print(f"    {cat:<14} {c['correct']}/{c['total']}")
    if missed:
        print(f"focus next  : {', '.join(missed)}")
    print("=" * 64)

    report = {
        "participant": participant,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "duration_seconds": (finished - started).seconds,
        "total": total,
        "correct": correct_count,
        "score_percent": score,
        "pass_threshold_percent": pass_score,
        "passed": score >= pass_score,
        "by_category": {k: v for k, v in sorted(by_cat.items())},
        "missed_categories": missed,
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[written] score report -> {out_path}")
    return report


def parse_answers(raw: str) -> list[str]:
    return [a[0].upper() for a in re.split(r"[,\s]+", raw.strip()) if a]


def main() -> None:
    parser = argparse.ArgumentParser(description="SE awareness quiz engine")
    parser.add_argument("--name", default="anonymous", help="participant label")
    parser.add_argument("--questions", help="load question bank from JSON")
    parser.add_argument("--export-questions", metavar="FILE",
                        help="write the built-in bank to JSON and exit")
    parser.add_argument("--answers", help="non-interactive answers, e.g. B,A,C,D")
    parser.add_argument("--shuffle", action="store_true")
    parser.add_argument("--pass-score", type=int, default=DEFAULT_PASS)
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args()

    if args.export_questions:
        export_questions(args.export_questions, DEFAULT_QUESTIONS)
        return

    try:
        bank = load_questions(args.questions) if args.questions else DEFAULT_QUESTIONS
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        sys.exit(f"cannot load questions: {exc}")

    answers = parse_answers(args.answers) if args.answers else None
    run_quiz(bank, answers, args.name, args.shuffle, args.out, args.pass_score)


if __name__ == "__main__":
    main()
