## SpyCloud Enterprise Protection for Cortex® XSOAR™

**From stolen session cookie to closed incident, automatically.**

Most identity-based attacks start outside your network: a session cookie lifted from an infected browser, a login captured by a phishing kit, a password leaked in a third-party breach. Little of it trips a SIEM alert or an EDR sensor, so it often doesn't reach your SOC until the attacker has already used it.

SpyCloud closes that gap. We recapture stolen identity data directly from criminal communities – before it's weaponized – and this pack delivers it into Cortex XSOAR as high-priority incidents. From there, playbooks enrich each exposure, choose the right response by source, severity, and user role, and help automate the action: reset passwords, revoke sessions, force re-authentication, disable accounts, and notify the people who need to know.

The goal is a lower mean time to respond (MTTR) through a repeatable, policy-driven response built on reliable identity evidence – plaintext credentials and session cookies or tokens – not heuristics.

## What's new in 1.0.13: Session theft gets its own incident type

**A password reset doesn't end a stolen session. Revocation does.**

The September 1, 2026 release adds SpyCloud Access Data, built on SpyCloud's highest-fidelity tier of recaptured data (Severity 30). Each Access record connects a known identity to stolen session details, and includes a signal that the stolen token has been tested and works. Your analysts can see who's affected and what active access an attacker holds.

- **New incident type:** SpyCloud Access Data, with its own layout and incoming field mappings
- **Classifier update:** Severity 30 records now map to the SpyCloud Access Data incident type
- **Feed update:** The Severity parameter now includes Severity 30 by default, and its description documents the severity-to-record-type mapping

**Why it matters:** A stolen session can outlive a password reset. An Access record points to a compromised session, so the right fix is session revocation, not a password reset alone. Route SpyCloud Access Data incidents to your own session-revocation playbook and close the gap before the attacker uses it again.

### Before you upgrade to 1.0.13

Existing instances that haven't overridden the Severity parameter will start ingesting SpyCloud Access Data incidents after the upgrade.

Plan for it:

- **Confirm your Severity setting:** Severity 30 is now included by default
- **Check your Fetch Limit:** the default is 200 per fetch
- **Route SpyCloud Access Data incidents** to a session-revocation playbook, not a password-reset playbook alone
- **Match each incident type to a triage owner:** Access Data, Malware Data, Breach Data, and Informative Data

### What an Access incident looks like

1. The record lands in XSOAR as a SpyCloud Access Data incident, with the user, domain, severity, and timestamps attached
2. Enrichment adds previous exposures and cookie or token presence
3. Your playbook branches on user role, such as VIP, admin, or repeatedly exposed user
4. Your playbook revokes sessions, forces re-authentication, and notifies the user and owner through the identity and messaging integrations you already run

## What you get

### Ingest: SpyCloud Enterprise Protection Feed

- Pulls SpyCloud watchlist data (breach, malware, and access records) into XSOAR as incidents on a schedule you control
- Four incident types: SpyCloud Access Data, SpyCloud Malware Data, SpyCloud Breach Data, and SpyCloud Informative Data, each with a purpose-built layout
- Controls for Fetch Limit (default 200), Domain Search (filter the watchlist by domain), and Severity
- A classifier and incoming mapper that populate incident fields, including infected machine ID, target domain and subdomain, password type, plaintext password, confidence, and user browser

### Enrich: SpyCloud Enterprise Protection Enrichment

- Look up exposure for watchlists, domains, emails, IP addresses, usernames, and passwords, on demand, from any playbook task
- With SpyCloud Compass, also enrich from malware-infected device data and exposed corporate applications (SSO, collaboration tools, CRM, and more)

### Respond: Sample playbooks

- **SpyCloud - Breach Investigation:** Triages SpyCloud Breach Data incidents
- **SpyCloud - Malware Incident Enrichment:** Runs `spycloud-compass-device-data` when a SpyCloud Malware Data incident is created and sets the matching incident field

Both are starting points. Clone them, add your own branches, and wire in the identity, ticketing, and messaging integrations you already run.

Works with Cortex XSOAR and Cortex XSIAM.

## How it works

1. **Ingest.** Scheduled jobs pull SpyCloud exposure records from breach, malware (infostealer logs), and phished sources. Each new match raises an incident with the user, artifact type, severity, and timestamps attached.
2. **Enrich.** Playbook tasks call the SpyCloud API for added evidence – previous exposures, password reuse indicators, and cookie or token presence – and attach it to the incident.
3. **Decide.** Playbooks branch on source (breach, malware, or phished), severity, and user role (VIP, admin, repeatedly exposed user) to pick the right response. Edge cases can queue to a human.
4. **Act.** Reset passwords, revoke sessions and tokens, force re-authentication, disable accounts, and notify affected users and owners, using the integrations in your environment.

## The evidence behind every incident

SpyCloud links exposures across personal, professional, past, and present identities, so your analysts react to the same holistic view attackers use to gain initial access. That's post-infection remediation: going beyond wiping the device to address the stolen cookies and passwords left behind.

- **SpyCloud sees it first.** Our data comes from inside criminal communities, not the public dark web forums where stolen data has already been posted, traded, and used. Exposure surfaces up to nine months ahead of public breach disclosure.
- **Evidence, not a guess.** SpyCloud cracks over 90% of 36B+ recaptured password hashes to plaintext, so analysts get concrete evidence of exposure instead of a risk score to second-guess.
- **All three channels criminals use.** Breach, malware, and phished data in one feed: 85,000+ breach sources, 85+ infostealer malware families, and 18+ phishing-as-a-service kit ecosystems.
- **Built for the SOC you already run.** Install from the Marketplace, add your API key, and start from pre-built content. No custom development or professional services needed to get started.

| **Metric** | **Description** |
| --- | --- |
| 65.7B | Distinct identity records recaptured by SpyCloud |
| 17B+ | Session cookies recaptured |
| Up to 9 months | Ahead of public breach disclosure |
| 90%+ | Of 36B+ password hashes cracked to plaintext |
| 220+ | Identity data types, from session cookies and credentials to PII and device fingerprints |

## Get started in five steps

1. Install SpyCloud Enterprise Protection from the Cortex Marketplace.
2. Configure the integration instance with your SpyCloud API key (with access to breach, malware, and phished datasets). Set Severity, Fetch Limit, and Domain Search to match your triage capacity.
3. Import or clone the sample playbooks and set inputs such as severity thresholds and notification channels.
4. Test with a sample exposure record to confirm incident creation and enrichment.
5. Go live and monitor incident volume, response times, and completion rates.

## Measure the impact

- Confirm incident creation for new breach, malware, and phished matches.
- Track time-to-first-action and overall MTTR.
- Monitor automation success: resets, revocations, and notifications.
- Trend exposures by source and by artifact type (passwords versus cookies and tokens).

**Tip:** Add a final playbook task that tags each incident with its source and artifact type to make reporting easy.

## Requirements

- A SpyCloud Enterprise Protection subscription with API access.
- Cortex XSOAR or Cortex XSIAM.
- SpyCloud Compass (optional), for malware-infected device and exposed application enrichment.

## Learn more

- Setup steps, playbooks, and the full integration guide: [SpyCloud Cortex XSOAR documentation](https://docs.spycloud.com/public-sc/docs/palo-alto-cortex-xsoar)
- Integration overview and demo video: [SpyCloud for Cortex XSOAR](https://spycloud.com/products/integrations/cortex-xsoar/)
- Not a SpyCloud customer yet? See it on your own data: [Request a demo](https://spycloud.com/request-a-demo/)
