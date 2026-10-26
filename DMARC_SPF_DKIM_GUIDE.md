# DMARC / SPF / DKIM Setup Guide for Defenders

Companion to `spear_phish_template.py`. The three training drafts in
`spear_phish_drafts.txt` all abuse one thing: **the attacker chooses the
From address**. SPF, DKIM, and DMARC are the standards that let the
recipient's mail server verify that choice. This guide is the defensive
half of the lab.

---

## 0. Which draft does email auth actually stop?

| Draft | Spoof technique | Stopped by email auth? | Why |
|---|---|---|---|
| 1 — Account suspension | Same-domain spoof of `it-support@yourcompany.com` | **Yes — with `p=reject`** | Attacker cannot sign valid DKIM for your domain, and their IPs are absent from your SPF |
| 2 — Shared document | Lookalike domain `northwindlabs.example` (a *different* domain) | **No** | Auth only says who a domain *claims to be*; a fresh domain passes its own checks |
| 3 — QR / quishing | Link/QR payload carried in content or an image | **No** | Payload is below the envelope — needs URL rewriting, image/QR policy, training |

**Takeaway:** DMARC kills the classic impersonation in Draft 1. Drafts 2 and 3
are why you still run awareness training — plus external-sender banners,
attachment sandboxing, and safe-links.

---

## 1. SPF — who may send for your domain

SPF is a TXT record on the apex domain listing the mail servers allowed to
send as `@yourdomain`.

### Record

```
v=spf1 ip4:203.0.113.10 include:_spf.google.com -all
```

| Piece | Meaning |
|---|---|
| `v=spf1` | required version tag |
| `ip4:203.0.113.10` | this exact IPv4 may send |
| `include:...` | delegate to another provider's SPF (counts as a DNS lookup) |
| `-all` | **fail** everything else — use this once you know all senders |
| `~all` | softfail — acceptable during discovery, tighten later |

### Rules of thumb

- **One SPF record only.** Two records = `permerror` = auth effectively off.
- **Max 10 DNS lookups** (includes/redirects each count). Flattening or a
  macro is needed if you exceed it.
- Inventory *every* sender first: Microsoft 365, Google, your CRM, ticketing,
  invoicing, scanners that "email to PDF". Missing one means mail goes to
  `-all` rejection.
- Never publish `+all` (allows the whole internet).

### Verify

```bash
dig +short TXT yourdomain.example | grep spf
# expect exactly one line, e.g.:
# "v=spf1 ip4:203.0.113.10 include:_spf.google.com -all"
```

---

## 2. DKIM — cryptographic signature per message

DKIM signs each outgoing message with a private key; the recipient verifies
against a public key published in DNS. This is the piece an attacker
spoofing Draft 1 can never produce.

### Generate a key (OpenDKIM)

```bash
opendkim-genkey -b 2048 -s mail -d yourdomain.example -v
# mail.txt -> DNS record to publish
# mail.private -> stays on the signing host, mode 600
```

- **Selector** (`mail` above) is arbitrary; use `mail`, `m1`, `s2026` — you
  need the selector in the hostname: `mail._domainkey.yourdomain.example`.
- **2048-bit minimum**; 1024-bit keys are considered breakable.
- Publish the DNS TXT:

```
mail._domainkey.yourdomain.example.  IN  TXT  (
  "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFA..."
)
```

- Sign `d=yourdomain.example; s=mail` — the **d= domain must align with the
  From header** for DMARC to pass (see below).
- **Rotate yearly**: publish `mail2` selector alongside `mail`, flip signing,
  wait out the cache TTL (~2 days), retire the old key.

### Verify

```bash
dig +short TXT mail._domainkey.yourdomain.example
# send yourself a test mail, then inspect headers:
#   Authentication-Results: ... dkim=pass header.d=yourdomain.example
```

---

## 3. DMARC — the policy that ties SPF + DKIM to the From header

SPF and DKIM alone prove nothing about the *visible* sender. DMARC adds the
missing link: it asks "does SPF **or** DKIM **align** with the From domain?"
and tells the receiver what to do on failure.

### Record

```
_v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.example; adkim=s; aspf=s; sp=reject; fo=1; pct=100
```

| Tag | Meaning |
|---|---|
| `p=` | policy for the main domain: `none` → `quarantine` → `reject` |
| `sp=` | policy for **subdomains** (`mail.yourdomain`) — set `sp=reject` |
| `rua=` | aggregate reports (daily ZIP of who sent as you, pass/fail) |
| `ruf=` | forensic reports of individual failures (`fo=1` = all) |
| `adkim=` / `aspf=` | `r` (relaxed, default) or `s` (strict) alignment |
| `pct=` | fraction of messages the policy applies to — your rollout dial |

Place it at `_dmarc.yourdomain.example` as TXT.

### Why alignment matters for the lab

Draft 1 sends `From: it-support@yourdomain` from a server that is **not** in
your SPF and **cannot** DKIM-sign as your domain → both fail alignment →
DMARC rejects it at the recipient. That is the whole defense.

---

## 4. Rollout plan (do not skip stages)

| Stage | Record | Purpose | Duration |
|---|---|---|---|
| 1. Observe | `p=none; rua=...` | Collect reports; find forgotten senders | 1–2 weeks |
| 2. Fix | correct SPF, add DKIM, onboard every sender | Get legitimate mail to `pass` | until reports are clean |
| 3. Partial | `p=quarantine; pct=10` → `pct=50` | Failures land in spam, not inbox | 1–2 weeks per step |
| 4. Enforce | `p=reject; pct=100; sp=reject` | Impersonation refused outright | — |
| 5. Maintain | watch `rua`, rotate DKIM keys | Catch new senders and drift | ongoing |

Never jump to `p=reject` from `p=none`: mail you forgot about (newsletters,
fax-to-email, legacy printers) will silently fail.

### Read the reports

Aggregate reports are gzip CSV-ish XML. Each row tells you source IP,
SPF/DKIM/DMARC results, and header From. Any row with `dmarc=fail` from an IP
you don't recognize is either a spoof (good — you're blocking it) or a
legit service you must whitelist (fix the record, do **not** relax to `p=none`).

---

## 5. Verification checklist

```bash
# 1. SPF — exactly one record, ends in -all
dig +short TXT yourdomain.example | grep spf

# 2. DMARC — present, eventually p=reject
dig +short TXT _dmarc.yourdomain.example

# 3. DKIM — key reachable via the selector you sign with
dig +short TXT mail._domainkey.yourdomain.example

# 4. End-to-end test email (headers must show all three pass)
swaks --to you@yourdomain.example --from it-support@yourdomain.example \
      --server mx.yourdomain.example
# Look for:
#   spf=pass smtp.mailfrom=yourdomain.example
#   dkim=pass header.d=yourdomain.example
#   dmarc=pass
```

Online cross-checks: MXToolbox / Google Admin Toolbox "Check DNS" for the
three records, and mail-tester.com for a scored end-to-end run.

---

## 6. What email auth cannot do (compensating controls)

1. **Lookalike domains** (Draft 2): `northwind-labs.example` passes its own
   SPF/DKIM perfectly. Counter with: external-sender banners
   (`[EXTERNAL]` prefix), lookalike-domain watch lists, and training.
2. **Display-name spoofing**: `From: Asha Kulkarni <legit-but-wrong@...>`.
   Counter with: strict `aspf=s` where feasible + banners + DMARC on *your*
   domain so attackers can't use it.
3. **QR / legitimate-link payloads** (Draft 3): counter with URL rewriting
   (Safe Links / URL quarantine), image/QR scanning policy, and the
   "scan nothing from email" rule.
4. **Attachments** (Draft 2): sandboxing and macro policy (block `.xlsm`,
   `.hta`, double extensions) at the gateway.
5. **Display-name + reply-to mismatches**: mail auth validates the From
   domain, not the human reading it — always verify via an independent
   channel.

**Order of operations:** publish SPF → sign with DKIM → DMARC `p=none` →
read reports → fix senders → `quarantine` → `reject` → train people for the
residue that no record can stop.

*Lab note: use RFC 2606 reserved domains (`example`, `.example`, TLD `test`)
for every exercise record so nothing leaks outside the lab.*
