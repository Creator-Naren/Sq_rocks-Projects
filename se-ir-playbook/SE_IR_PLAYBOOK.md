# Social Engineering Incident Response (SE-IR) Playbook

## 1. Preparation (Proactive)
- Maintain incident response contact list (SOC, Legal, HR, Comms, Finance)
- Define severity matrix; document retention and eDiscovery requirements
- Run phishing simulations and tabletop exercises quarterly
- Baseline normal login times and email rule patterns
- Implement containment capabilities: account lockout, session revocation, URL/domain/email quarantine

## 2. Identification
- Detect SE indicators: brute force, success-after-brute, auto-forward rules, off-hours access, external VPN, impossible travel, reported phishing
- Correlate alerts (SIEM, mail gateway, EDR, proxy, IAM)
- Classify incident type (phishing, spear-phishing, vishing, smishing, BEC, baiting, watering hole, ATO) and severity
- Preserve logs immediately (chain of custody)

## 3. Containment
- **Critical/HIGH**: lock account, revoke sessions, force password/MFA reset, isolate endpoints
- Quarantine phishing emails, block sender domains/URLs, sandbox attachments
- For BEC: suspend financial changes and coordinate with bank if needed
- For baiting: isolate device and preserve forensic artifacts
- For ATO: invalidate tokens and inspect mailbox rules

## 4. Eradication
- Remove phishing messages from affected inboxes, search across tenants
- Block IOCs (domains, IPs, hashes, shortcodes)
- Patch exploited vectors (if watering hole)
- Remove malicious email rules and restore legitimate access when safe

## 5. Recovery
- Restore services from known-good state
- Verify MFA, recovery methods, and email rules
- Conduct controlled re-authentication
- Monitor affected accounts for 7-30 days (post-compromise dwell time)

## 6. Lessons Learned
- Conduct post-incident review within 7 days
- Update playbook, detections, and training content
- Track metrics (time-to-detect/contain/recover, click rate, repeat incidents)
- Share sanitized indicators across security communities where appropriate

## Runbook Usage
Execute the automation script:
```bash
python3 se_ir_automation.py --type phishing --severity HIGH --user user@example.com --alerts brute_force,success_after_brute
```
It generates a timestamped JSON report with deduped, type-aware containment actions. This report becomes the audit trail for the incident.