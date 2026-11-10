ThreatMon is a digital risk protection and threat intelligence platform. It monitors the surface web, the deep web and the dark web for threats against your organization: phishing and look-alike domains, leaked credentials, black market listings, fake social media accounts, ransomware and dark web chatter about your company, and the weaknesses of your attack surface.

This pack brings ThreatMon into Cortex XSOAR and Cortex XSIAM.

## What does this pack do?

### Incident management

- Fetches ThreatMon alarms as **ThreatMon Alert** incidents, with the description, every finding and finding ID, the recommended mitigation and the screenshots of the findings.
- Follows alarm changes, so alarms that ThreatMon approves later and alarms that move to a fetched status are fetched too. An alarm is never created twice.
- In Cortex XSOAR, mirrors the alarm status in both directions: a change in ThreatMon updates the incident and can close or reopen it, and closing the incident can resolve the alarm in ThreatMon.
- Masks passwords, tokens and cookies in leak findings before they are stored.

### Response

- Submits **takedown** requests for phishing domains, rogue mobile apps and fake social media accounts.
- Submits **data removal** requests for Black Market Monitoring findings.
- Sets the alarm status, with remarks, an assignee and the people to inform.

### Intelligence and enrichment

- Enriches CVEs with **ThreatMon Vulnerability Knowledge** through the standard `cve` command: CVSS, the ThreatMon risk scores, EPSS, exploits and proofs of concept, the CISA KEV entry, the affected company assets and an AI analyst brief with response steps.
- Searches CVEs by period, severity, vendor, product and exploitation signals, and lists the CVEs of the products the company follows.
- Analyses files in the **ThreatMon sandbox** and returns the verdict as a file reputation.
- Lists the **attack surface** that ThreatMon discovered: IP addresses, domains, subdomains, websites, certificates, technologies, DNS records and cloud buckets.
- Returns the **CISO Dashboard**: the Brainify Risk Score, the module scores, the alert statistics and the AI risk report.

### MSSP

- Works on one sub company with the **Customer Name (MSSP)** parameter.
- Lists MSSP customers, and with the API key of the MSSP administrator account creates, changes and deletes them and their monitoring keywords.

## Content

| Item | Name |
| --- | --- |
| Integration | ThreatMon Incident Management |
| Incident type | ThreatMon Alert |
| Layout | ThreatMon Alert Layout |
| Mappers | ThreatMon - Incoming Mapper, ThreatMon - Outgoing Mapper |
| Incident fields | ThreatMon Alarm Code, Status, Alarm Type, Category, Subcategory, Source, Last Update, Finding IDs, Findings, Mitigation |

## Before you start

You need a ThreatMon subscription and its **External API Key**: in ThreatMon, open **Settings**, then **Integrations**, then **Settings**. If IP whitelisting is enabled for your account, send the public IP address of the Cortex server or engine to [support@threatmonit.io](mailto:support@threatmonit.io).

To ingest ThreatMon IOCs as indicators, also install the **ThreatMon Threat Feed** pack.

## Support

Contact [support@threatmonit.io](mailto:support@threatmonit.io) or visit [threatmon.io](https://www.threatmon.io).
