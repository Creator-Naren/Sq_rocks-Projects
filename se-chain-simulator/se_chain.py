#!/usr/bin/env python3
"""SE Attack Chain Simulator (authorized lab use only).

Integrates the labs built so far into a single CLI:
- osint: passive profile enrichment (domain/email harvesting context)
- profile: fake-profile scoring (behavioral heuristics)
- phish: URL phishing scoring
- template: spear-phish awareness email drafts
- ir: SE incident response automation
- demo: runs a full end-to-end chain

All modules are defensive/awareness oriented and operate only on lab data.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOME = ROOT.parent
KNIGHT = Path("/home/knight")


MODULES = {
    "osint": "Passive OSINT scan (domain context)",
    "profile": "Fake-profile behavioral scorer",
    "phish": "URL phishing risk scorer",
    "template": "Spear-phish awareness email drafts",
    "ir": "Trigger SE incident response workflow",
    "demo": "Run full SE chain demo (non-interactive)",
}


def run_cmd(cmd: list[str], cwd: Path | None = None) -> int:
    print(f"\n$ {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, cwd=cwd or ROOT, check=False)
        return proc.returncode
    except FileNotFoundError as exc:
        print(f"[!] not found: {exc}")
        return 127


def mod_osint():
    script = HOME / "osint_scan.py"
    if script.exists():
        return run_cmd([sys.executable, str(script)], cwd=HOME)
    return run_cmd([sys.executable, "-c",
                    'print("osint_scan.py not found in Projects/")'])


def mod_profile():
    script = HOME / "social-impersonation-lab" / "fake_profile_scorer.py"
    if script.exists():
        return run_cmd([sys.executable, str(script)], cwd=script.parent)
    return 127


def mod_phish():
    script = HOME / "phish_score.py"
    if script.exists():
        print("Scoring demo URLs...")
        return run_cmd([sys.executable, str(script)], cwd=HOME)
    return 127


def mod_template():
    script = KNIGHT / "spear_phish_template.py"
    if script.exists():
        return run_cmd([sys.executable, str(script)], cwd=KNIGHT)
    return 127


def mod_ir():
    script = HOME / "se-ir-playbook" / "se_ir_automation.py"
    if script.exists():
        return run_cmd([
            sys.executable, str(script),
            "--type", "phishing",
            "--severity", "HIGH",
            "--user", "riya@sqrock.com",
            "--alerts", "brute_force,success_after_brute",
        ], cwd=script.parent)
    return 127


def mod_demo():
    steps = [
        ("osint", mod_osint),
        ("profile", mod_profile),
        ("phish", mod_phish),
        ("template", mod_template),
        ("ir", mod_ir),
    ]
    print("\n=== RUNNING FULL SE CHAIN DEMO ===")
    for name, fn in steps:
        print(f"\n--- [{name}] ---")
        fn()
    print("\n=== DEMO COMPLETE ===")
    return 0


def menu():
    print("\n■■■ SE CHAIN SIMULATOR ■■■■■■■■■■■■■■■■■■■")
    print("■  Sqrock Cybersecurity Internship Lab  ■")
    print("■  Defensive/awareness chain only      ■")
    print("■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■")
    for k, v in MODULES.items():
        print(f" [{k}] {v}")
    try:
        choice = input("\nSelect module (q to quit): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if not choice or choice in ("q", "quit", "exit"):
        print("Goodbye.")
        return
    if choice == "osint":
        mod_osint()
    elif choice == "profile":
        mod_profile()
    elif choice == "phish":
        mod_phish()
    elif choice == "template":
        mod_template()
    elif choice == "ir":
        mod_ir()
    elif choice == "demo":
        mod_demo()
    else:
        print("Invalid choice.")
    menu()


def main():
    parser = argparse.ArgumentParser(description="SE chain simulator")
    parser.add_argument("module", nargs="?", choices=list(MODULES))
    args = parser.parse_args()
    if args.module == "demo":
        sys.exit(mod_demo())
    if args.module:
        mapping = {
            "osint": mod_osint, "profile": mod_profile, "phish": mod_phish,
            "template": mod_template, "ir": mod_ir, "demo": mod_demo,
        }
        sys.exit(mapping[args.module]())
    menu()


if __name__ == "__main__":
    main()
