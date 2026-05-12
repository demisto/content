# Darkmon Threat Intelligence Pack

Stay ahead of cyber threats with **Darkmon TIP** — real-time threat intelligence
from the Clear, Deep, and Dark Web, tailored to your assets and operationalized
inside Cortex XSOAR.

## What's in the box

This is an **end-to-end content pack**, not just an integration. It ships
everything a SOC team needs to put Darkmon intelligence into action.

### Integration
- **Darkmon** — 18 commands covering indicator enrichment, IOC feed ingestion
  (TIM), compromised data discovery, board-level VIP email protection,
  ransomware tracking, newly-registered-domain monitoring, vulnerability
  intelligence, and a fully dynamic global search.

### Indicator enrichment (sub-playbooks)
- `Darkmon - Enrich IP`
- `Darkmon - Enrich Domain`
- `Darkmon - Enrich URL`
- `Darkmon - Enrich File Hash`
- `Darkmon - Enrich Email`

These are wired into XSOAR's reputation system via `DBotScore` + `Common.<Type>`
contracts so they slot into any existing playbook with no rewrites.

### Continuous monitoring
- `Darkmon - Compromised Credentials Sweep` (every 4h)
- `Darkmon - VIP Email Monitor` (hourly)
- `Darkmon - Ransomware Mentions Watch` (every 6h)
- `Darkmon - Brand-Targeted NRD Watch` (daily)
- `Darkmon - Critical CVE Pipeline` (daily)

Each ships with its own incident type, layout, dedup pre-process rule, and a
List of tunables (customer domains, brand names, tech stack, severity rules)
so multi-tenant deployments customize without forking.

### Incident response
- `Darkmon - Phishing Email Triage`
- `Darkmon - Compromised Account Response`
- `Darkmon - EDR Alert Enrichment`
- `Darkmon - Ransomware Victim Response`
- `Darkmon - Email Deep Dive`

These response playbooks call **provider-agnostic switchboard** sub-playbooks so
they work whatever your stack looks like.

### Provider-agnostic adapters (Tier 4)
- `Darkmon - Generic Notify` (Slack | Teams | Email | ServiceNow | Jira)
- `Darkmon - Generic Block Indicator` (Palo Alto NGFW | Fortinet | Cisco
  Umbrella | CloudFlare)
- `Darkmon - Generic User Action` (suspend, force password reset on
  Active Directory | Okta | Azure AD)

## Quick start

1. Install this pack from the Cortex Marketplace.
2. Open *Settings → Integrations → Darkmon* and click **Add instance**.
3. Paste your Darkmon API key. Leave **API Base URL** at the default unless
   instructed otherwise.
4. Run `!test-module` from the War Room. Expect "Success".

For full configuration, command examples, and playbook docs, see the
per-artifact READMEs under each subfolder.

## Compliance posture

The pack defaults to **GDPR-strict + secrets redaction**. Passwords, card
numbers, and SSNs never appear in War Room markdown unless the integration's
`redact_secrets` toggle is explicitly set to `false`. Raw values remain
available to playbooks via `rawJSON` so automation isn't blocked.

## Support

This pack is maintained by **Darkmon** as a developer-supported pack.
Visit [darkmon.com](https://darkmon.com) or contact `support@darkmon.com`.

## Versioning

Semantic versioning. See [`ReleaseNotes/`](./ReleaseNotes/) for change history.
