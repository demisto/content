# KELA Monitor

KELA Monitor alerts you when KELA's sources in the cybercrime ecosystem expose one of your organization's assets: hacking discussions, instant messaging, leaked credentials, network vulnerabilities, credit cards and compromised accounts. This pack fetches those incidents into Cortex and lets analysts list them by incident type.

KELA Monitor is the successor of KELA RaDark (KELA renamed the RaDark module to Monitor). For new deployments use this pack. If you run the KELA RaDark integration on the same monitor, disable its instance before you enable fetching here, otherwise every KELA incident is created twice. This pack does not reuse the RaDark incident type, fields, mapper or layout.

## What does this pack include?

- **KELA Monitor** integration: fetches the incidents of the incident types you choose (one monitor per instance) and provides `kela-monitor-incident-list` and `kela-monitor-incident-scroll`.
- **KELA Monitor - Classifier** and **KELA Monitor - Incoming Mapper**: one incident type per KELA incident type and 41 **KELA Monitor** incident fields.
- Seven incident types, each with its own layout: **KELA Monitor Hacking Discussion**, **KELA Monitor Instant Messaging**, **KELA Monitor Leaked Credentials**, **KELA Monitor Network Vulnerability**, **KELA Monitor Credit Cards**, **KELA Monitor Compromised Accounts**, and **KELA Monitor Incident** for any other KELA type.

The integration is read-only. Passwords, card numbers and other keyed secrets are masked by default (free text such as posts and messages is not), and hacking discussions are fetched as a snippet only.
