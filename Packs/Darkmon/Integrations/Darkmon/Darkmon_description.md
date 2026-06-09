## Darkmon Threat Intelligence Platform

Connect Cortex XSOAR to **Darkmon TIP** for real-time intelligence from the
Clear, Deep, and Dark Web — tailored to your assets.

### What you get
- **Indicator enrichment** for IPs, domains, URLs, file hashes, and emails,
  with first-class `DBotScore` + `Common.<Type>` outputs.
- **IOC feed** ingestion into Cortex Threat Intel Management.
- **Compromised data** discovery (leaked accounts, bank cards, combo lists,
  public breaches, compromised employee accounts).
- **Board-level VIP email monitoring** — list protected emails and pull every
  leak associated with each.
- **Ransomware tracking** (articles + company-specific mentions).
- **Newly registered domains** and **telnet brute-force IOCs**.
- **Vulnerability intelligence** (CVE feed with CVSS, exploitation status,
  source identifier).
- **Global search** — fully dynamic over every Darkmon data type, future-proof
  for new feature types added to the platform.

### Get an API key
Sign in to your Darkmon tenant, go to **Settings → API Keys**, and create a
key with the scopes your XSOAR instance needs. Paste it into the **API key**
field below.

### Production vs development
The pack ships pointing at the production endpoint. To target your dev or
staging environment, set **API Base URL** to your dev URL on this instance only.

### Data minimization
By default, secrets such as passwords and card numbers are redacted from War
Room markdown output. Raw values remain available to playbooks via context for
automation. Disable **Redact secrets in War Room** only when troubleshooting
in non-production environments.
