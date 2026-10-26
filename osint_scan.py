#!/usr/bin/env python3
"""
OSINT / Passive Reconnaissance Scanner
--------------------------------------
Collects public-only information about a domain:
  - WHOIS registration data
  - DNS records (A, AAAA, MX, NS, TXT, CNAME)
  - IP geolocation (via ip-api.com)

PASSIVE recon: only queries public databases and third-party
services. It never sends traffic to the target's own ports.
"""

import sys
import socket
import argparse

import whois
import requests

try:
    import dns.resolver
except ImportError:
    dns = None


GEO_API = "http://ip-api.com/json/{ip}"


def clean(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    return value


def get_whois(domain):
    print("\n=== WHOIS ===")
    try:
        w = whois.whois(domain)
    except Exception as exc:
        print(f"  [!] WHOIS lookup failed: {exc}")
        return {}
    fields = {
        "Registrar": w.registrar,
        "Org": w.org,
        "Creation date": w.creation_date,
        "Expiration date": w.expiration_date,
        "Updated date": w.updated_date,
        "Name servers": w.name_servers,
        "Emails": w.emails,
        "Country": w.country,
    }
    for label, val in fields.items():
        if val:
            print(f"  {label:16}: {clean(val)}")
    return fields


def get_dns(domain):
    print("\n=== DNS RECORDS ===")
    records = {}
    if dns is None:
        print("  [!] dnspython not installed; falling back to A record only")
        try:
            records["A"] = socket.gethostbyname_ex(domain)[2]
            print(f"  A               : {records['A']}")
        except Exception as exc:
            print(f"  [!] A lookup failed: {exc}")
        return records
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
            print(f"  {rtype:15}: {records[rtype]}")
        except Exception:
            continue
    return records


def get_geo(ip):
    print("\n=== IP GEOLOCATION ===")
    try:
        resp = requests.get(GEO_API.format(ip=ip), timeout=10)
        geo = resp.json()
    except Exception as exc:
        print(f"  [!] Geolocation lookup failed: {exc}")
        return {}
    if geo.get("status") != "success":
        print(f"  [!] ip-api error: {geo.get('message', 'unknown')}")
        return geo
    for label in ("query", "country", "regionName", "city",
                  "isp", "org", "as"):
        if geo.get(label):
            print(f"  {label:12}: {geo[label]}")
    if geo.get("lat") is not None:
        print(f"  {'coords':12}: {geo['lat']}, {geo['lon']}")
    return geo


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as exc:
        print(f"[!] Could not resolve {domain}: {exc}")
        return None


def osint_scan(domain):
    print(f"OSINT PASSIVE SCAN :: {domain}")
    print("=" * 46)
    whois_data = get_whois(domain)
    dns_data = get_dns(domain)
    ip = get_ip(domain)
    geo_data = {}
    if ip:
        print(f"\n=== PRIMARY IP ===\n  {ip}")
        geo_data = get_geo(ip)
    print("\n" + "=" * 46)
    print("Scan complete. All data from public sources.")
    return {"whois": whois_data, "dns": dns_data, "ip": ip, "geo": geo_data}


def main():
    parser = argparse.ArgumentParser(description="Passive OSINT scanner")
    parser.add_argument("domain", help="domain to scan, e.g. example.com")
    args = parser.parse_args()
    osint_scan(args.domain)


if __name__ == "__main__":
    main()
