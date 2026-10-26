# Baiting & Watering-Hole Attacks: Mitigation Report

Companion to `honeypot_tracker.py`. The honeypot measures one thing — who
clicked a bait link — which is the *detection/awareness* half of this
technique. This report covers the *prevention* half: how drive-by downloads
and watering-hole compromises actually work, and what stops them.

---

## 1. Threat model

**Baiting** — a trap that relies on the victim's curiosity or greed.
- *Physical*: dropped USB drives, CDs, "found" devices, free promotional
  media (see the USB-drop lab).
- *Digital*: fake download links, "your invoice", cracked software, fake
  update prompts, QR codes, free-gift-with-registration pages.

**Watering hole** — instead of baiting the target directly, the attacker
compromises a site the target *already trusts and visits* (`industry forum`,
`vendor portal`, `news site`). Every visitor becomes a victim, and the
target's normal behavior is itself the delivery mechanism. Often combined
with **malvertising**: a malicious ad served through a legitimate ad network
needs no site compromise at all.

**Drive-by download** — the payload mechanism both often use: simply visiting
the page runs code with no user interaction beyond the visit.

---

## 2. How a drive-by download works (the logic we simulate)

```
visit page
   -> injected script / malvertising iframe / compromised 3rd-party JS
      -> browser & plugin fingerprinting (OS, version, extensions)
         -> exploit kit picks a matching exploit  OR  fake "update" social lure
            -> payload delivered (silent install / user-approved download)
               -> execution (loader -> beacon -> credential theft / ransomware)
                  -> persistence, C2, lateral movement
```

Key properties that defenders must counter:
- **No interaction required** for the exploit path; the *fake update* path
  needs only one click.
- **Legitimate domain = trusted domain.** Network allowlists and "we only
  block bad sites" fail when the bad code rides on a good site.
- **The browser is the new endpoint.** The exploit target is almost always
  the browser or a plugin, which is why patch management dominates.
- **Third-party JS is a soft underbelly.** One compromised analytics/marketing
  script compromises every page that loads it.

---

## 3. Detection & measurement (this lab)

The honeypot logs campaign, pseudonymized visitor, IP hash, browser, OS,
device, bot/human flag, referer, and language. That yields the metrics an
awareness program needs:

- **Click-through rate per campaign** — which bait works (the `by campaign`
  breakdown).
- **Device/browser mix** — where to focus hardening and training.
- **Human vs. bot clicks** — do not count scanner traffic as victims; the
  `is_bot` classifier separates them.
- **NAT caveat** — the demo showed one IP hash producing two visitor IDs
  (two devices behind the same egress). **IP is not identity**; never
  attribute a click to a person from IP alone.

Operational detection signals to pair with it:
- Proxy/DNS logs: newly-registered domains, look-alike domains, `*.top/.xyz`
  TLDs, direct-IP navigations, executables downloaded from browser.
- EDR: Office/browser spawning `powershell`, `mshta`, `rundll32`, `wscript`.
- WAF/CMS integrity alerting on your own sites (you as the watering hole).

---

## 4. Mitigations

### 4.1 Web filtering (network layer)
- **DNS filtering / secure DNS** with category blocking + **newly-registered
  domain** and **look-alike domain** feeds.
- **URL reputation + sandboxing** at the SWG/secure web gateway; detonate
  unknown links off-network.
- **Block executable and risky file types** at the proxy based on *content*,
  not just extension (`.exe`, `.scr`, `.js`, `.hta`, `.lnk`, `.iso`, `.img`,
  macro docs).
- **Egress filtering** to known-good destinations where feasible; block
  known C2/malvertising ranges.
- TLS inspection *where legally and operationally appropriate* (be aware of
  privacy and certificate-pinning breakage).

### 4.2 Script blocking & browser hardening
- **NoScript / uBlock Origin** (or enterprise content blockers) to block
  third-party scripts and unknown origins.
- **Disable unneeded plugins/extensions**; remove Java/Flash-style legacy
  runtimes entirely.
- **Browser sandboxing** (built-in) + **Remote Browser Isolation (RBI)** for
  high-risk browsing — the payload executes in a disposable container, not
  on the endpoint.
- **Application isolation / containerization** for the browser.
- Enforce **CSP** and **Subresource Integrity (SRI)** on sites you own.

### 4.3 Patch management (the highest-value control)
- Aggressive update SLAs: browsers and OS **within days**, not months.
- **Auto-update** browsers and all plugins; remove EOL/unsupported software.
- **Virtual patching** via WAF/IPS where immediate upgrades are impossible.
- Track browser/plugin versions as part of asset inventory; report on
  unpatched endpoints.

### 4.4 Endpoint hardening
- **EDR** with exploit-protection and behavioural blocking.
- **Windows Defender Exploit Guard / ASR**: block Office & browser child
  processes, block untrusted executables, block obfuscated scripts.
- **Application control (WDAC/AppLocker)**: only approved apps run; blocks
  dropped payloads even if the drive-by succeeds.
- **Hardened images**: disable macros, autorun, legacy protocols.

### 4.5 Watering-hole-specific defenses
- **If you are the target:** monitor your vendors/industry sites for
  compromise indicators; assume a trusted site can be hostile; isolate
  browsing.
- **If you are the site owner:** CMS hardening, WAF, file-integrity
  monitoring, HSTS, CSP, SRI, minimal third-party JS, vendor review of ad/JS
  supply chain, and prompt patching of your own stack.
- **Supply-chain integrity:** pin and review third-party scripts; audit who
  can edit content (waterholes are often planted via stolen CMS admin creds —
  enforce MFA on admin accounts, separate admin from browsing).

### 4.6 Identity & credential hygiene
- **MFA everywhere**; phishing-resistant (FIDO2) where possible so a fake
  login page yields nothing usable.
- **Password managers** (origin-bound autofill resists look-alike domains).
- Separate **admin accounts** from everyday browsing sessions.

### 4.7 Awareness
- "Hover before you click"; type URLs rather than trusting links.
- Treat **unexpected download prompts and "update" pop-ups** as hostile.
- Verify vendor domains; a valid certificate ≠ a legitimate site.
- Report suspicious clicks/pages immediately (speed matters for IR).

---

## 5. Response if a bait click / drive-by is suspected

1. **Isolate** the endpoint (network quarantine) — don't power off if volatile
   evidence matters; let EDR guide it.
2. **Hunt** with EDR/proxy/DNS logs for the payload's execution and C2.
3. **Reset credentials** used on that host; assume session theft.
4. **Patch/eradicate** the exploited vector; block the IOCs at the gateway.
5. **Notify** affected users and, if data is involved, follow breach process.
6. **Feed back** into training: show the click, the landing page, and what
   would have happened (the honeypot's awareness page does exactly this).

---

## 6. Control matrix (quick reference)

| Vector | Primary control | Secondary controls |
|---|---|---|
| Digital bait / fake download | Web filtering + block risky file types | Awareness, RBI, app control |
| Drive-by exploit | Patch management (browser/OS/plugins) | EDR exploit guard, sandboxing |
| Malvertising / 3rd-party JS | Script blocking (NoScript), DNS/URL filtering | SRI/CSP on owned sites |
| Watering hole (site compromise) | Isolate browsing, integrity monitoring | Vendor monitoring, admin MFA separation |
| Fake update / fake login | Awareness + password manager + FIDO2 | URL reputation, RBI |
| Post-exploitation | EDR + application control | Segmentation, egress filtering |

---

## 7. Privacy & ethics note for honeypot campaigns

The tracker pseudonymizes IPs by default and logs only click metadata. Even
so, a click log is personal data:
- **Get authorization** for the campaign and document lawful basis.
- **Minimize**: don't log more than the exercise needs; keep the salt out of
  the log.
- **Retain briefly** and delete on a schedule; aggregate before sharing.
- **Never name-and-shame** — the metric is program effectiveness, and the
  goal is a conversation, not a gotcha.

**Bottom line:** no single control beats this technique. Patch aggressively,
block scripts and risky downloads, isolate browsing, and train people to
question links — then use the honeypot to measure whether it is working.
