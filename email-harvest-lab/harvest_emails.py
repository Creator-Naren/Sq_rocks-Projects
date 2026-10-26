#!/usr/bin/env python3
"""Harvest email addresses from a single web page.

Authorized use only: target domains you own or have written permission to test.
"""
import argparse
import re
import sys

import requests

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}")
HEADERS = {"User-Agent": "EmailHarvestLab/1.0 (authorized security training)"}


def harvest_emails(url):
    resp = requests.get(url, timeout=10, headers=HEADERS)
    resp.raise_for_status()
    return {email.lower() for email in EMAIL_RE.findall(resp.text)}


def main():
    parser = argparse.ArgumentParser(
        description="Scrape email addresses from a page you own or are authorized to test."
    )
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    try:
        found = sorted(harvest_emails(args.url))
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if not found:
        print("No emails found.")
        return

    print(f"Found {len(found)} unique email(s):")
    for email in found:
        print(f"  {email}")


if __name__ == "__main__":
    main()
