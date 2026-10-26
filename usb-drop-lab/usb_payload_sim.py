#!/usr/bin/env python3
"""USB-drop awareness simulation — benign recon beacon (LAB ONLY).

This stands in for the payload a malicious USB drive would run. It is
deliberately harmless so it can be used in an authorized "dropped drive"
exercise to measure whether people plug in found media:

    * logs basic host facts to a LOCAL text file
    * writes an awareness README next to it
    * makes NO network connections, installs NO persistence, modifies
      NOTHING outside its own folder

A real payload at this stage would fingerprint the host, escalate, move
laterally, or deploy ransomware. Those are precisely the steps this lab
performs only in the *narrative* printed at the end.

Run:
    python3 usb_payload_sim.py                 # write ./recon_log.txt
    python3 usb_payload_sim.py -o /tmp/log.txt
    python3 usb_payload_sim.py --quiet         # suppress banner
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import os
import platform
import socket
import sys

BANNER = r"""
+---------------------------------------------------------------+
|  USB-DROP AWARENESS SIMULATION  (benign beacon - lab only)    |
|                                                               |
|  If you are seeing this after plugging in a drive you found,  |
|  the exercise just measured exactly one thing: you inserted   |
|  unknown media. No harm was done here -- but a real payload   |
|  could already have run. Report found drives to IT.           |
+---------------------------------------------------------------+
"""


def collect_info() -> dict[str, str]:
    """Gather the same host facts a recon payload would exfiltrate."""
    try:
        user = os.getenv("USERNAME") or os.getenv("USER") or getpass.getuser()
    except Exception:
        user = "unknown"

    try:
        is_admin = str(os.geteuid() == 0) if hasattr(os, "geteuid") else "n/a"
    except Exception:
        is_admin = "n/a"

    return {
        "timestamp": str(datetime.datetime.now()),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "n/a",
        "python": platform.python_version(),
        "user": user,
        "admin": is_admin,
        "cwd": os.getcwd(),
        "interpreter": sys.executable,
    }


AWARENESS_README = """\
USB-DROP AWARENESS NOTICE
=========================
If you are reading this because you plugged in an unexpected USB drive:
you have just triggered a training simulation. Nothing was harmed.

What this benign script did   : wrote host facts to recon_log.txt
What a real payload could do  :
  - steal credentials from browsers and password managers
  - install a backdoor / remote-access trojan for persistence
  - harvest documents and email, then exfiltrate them over the network
  - encrypt files for ransomware, or pivot to other machines

What to do next
  1. Do NOT plug in any other unknown device.
  2. Hand the drive to IT/Security; do not return it to where you found it.
  3. Report how you found it (location) so the exercise can be measured.
  4. Delete recon_log.txt to leave the machine as you found it.
"""


def usb_payload_sim(output_file: str = "recon_log.txt",
                    announce: bool = True) -> str:
    info = collect_info()

    path = os.path.abspath(output_file)
    with open(path, "w", encoding="utf-8") as fh:
        for key, value in info.items():
            fh.write(f"{key}: {value}\n")

    readme = os.path.join(os.path.dirname(path), "AWARENESS_README.txt")
    with open(readme, "w", encoding="utf-8") as fh:
        fh.write(AWARENESS_README)

    if announce:
        print(BANNER)
        for key, value in info.items():
            print(f"  {key:<13}: {value}")
        print(f"\n[SIM] Recon data saved to {path}")
        print(f"[SIM] Awareness notice: {readme}")
        print("[SIM] No network access, no persistence, nothing else touched.")
    else:
        print(f"[SIM] Recon data saved to {path}")

    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benign USB-drop recon simulation (authorized training only)")
    parser.add_argument("-o", "--output", default="recon_log.txt")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    usb_payload_sim(args.output, announce=not args.quiet)


if __name__ == "__main__":
    main()
