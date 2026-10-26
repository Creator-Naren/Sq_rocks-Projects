# OSINT Passive Reconnaissance Report

**Target:** example.com (IANA-reserved practice domain)
**Method:** Passive only — public WHOIS databases, public DNS, third-party geolocation API
**Target contact:** None (no packets sent to example.com or its hosts)
**Tool:** `osint_scan.py` (python-whois, dnspython, requests)

## 1. Summary
`example.com` is a reserved documentation domain operated by IANA. It is
fronted by Cloudflare, which proxies DNS and web traffic. All information
below was obtained from public sources without probing the target directly.

## 2. Findings

### WHOIS
| Field | Value |
|-------|-------|
| Registrar | RESERVED — Internet Assigned Numbers Authority |
| Created | 1995-08-14 |
| Expires | 2027-08-13 |
| Name servers | elliott.ns.cloudflare.com, hera.ns.cloudflare.com |

### DNS
| Type | Value |
|------|-------|
| A | 172.66.147.243, 104.20.23.154 |
| AAAA | 2606:4700:8de5:72db:f2de:72:ef6b:ff98 |
| MX | 0 . (null MX — domain sends no mail) |
| NS | elliott.ns.cloudflare.com, hera.ns.cloudflare.com |
| TXT | `v=spf1 -all` (no mail senders authorized) |

### Hosting / Geolocation (Cloudflare edge IP)
| Field | Value |
|-------|-------|
| IP | 104.20.23.154 |
| ASN | AS13335 — Cloudflare, Inc. |
| Location | Toronto, Ontario, Canada |
| Coords | 43.6532, -79.3832 |

## 3. Analysis
- **Infrastructure:** Cloudflare proxy hides the true origin server, so the
  geolocated IP is an anycast edge node, not the backend. Resolving the
  origin would require active techniques (out of scope for passive recon).
- **Mail posture:** Null MX + `v=spf1 -all` confirm the domain is
  intentionally non-mail-sending — strong anti-spoofing hygiene.
- **Enumeration value:** NS/TXT records reveal the DNS provider and email
  policy, useful for mapping an organization's external footprint.

## 4. Passive vs Active Recon
| | Passive (this task) | Active |
|---|---|---|
| Contact with target | None | Direct probes |
| Sources | WHOIS, public DNS, Shodan, APIs | Port scans, banner grabs, fuzzing |
| Detectable | No | Yes (logged/IDS alerts) |

## 5. Recommendations (defensive)
- Keep WHOIS privacy enabled to limit registrar data exposure.
- Maintain null MX / restrictive SPF where mail is not used.
- Audit public DNS (TXT, subdomains) for information leakage.

## 6. Evidence
Raw scanner output: `osint_output.txt`
