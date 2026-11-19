# CYFIRMA – Preemptive External Threat Landscape Management Content Pack

CYFIRMA is a global leader in Preemptive External Threat Landscape Management, empowering organizations to proactively identify emerging cyber threats, understand their exposure, and take preventive action to protect their digital assets and business operations.

Powered by an AI-native intelligence platform, CYFIRMA provides a unified view of an organization's external digital exposure, emerging vulnerabilities, digital risks, and evolving adversary activities. By correlating external threat intelligence with organizational exposure and attacker behaviour, the platform identifies potential attack paths, assesses business impact, and delivers predictive insights that enable security teams to prioritize risks and take preventive action.

Through its integrated external threat management capabilities, CYFIRMA helps organizations strengthen attack surface visibility, protect digital assets and brand reputation, manage third-party exposure, anticipate sector-specific threats, and disrupt adversary reconnaissance through intelligence-driven deception.

By operating upstream of traditional detection and response, CYFIRMA helps reduce the likelihood of successful cyberattacks, improve security investment prioritization, and strengthen organizational cyber resilience. Its approach shifts cybersecurity from reactive incident response to proactive risk management, enabling security leaders to make informed decisions and maintain greater control over their external threat landscape.

### This packs empowers security teams with the following capabilities

- Pulls CYFIRMA alerts into XSOAR as incidents in four categories: Attack Surface, Brand Intelligence, Data Breach/Web Monitoring, and Social/Public Exposure (fetch-incidents in the Cyfirma integration).
- Brings in leaked credentials (customer accounts, compromised employees, and public-account leaks) as separate incidents, always Critical, ready for playbooks such as password reset and session revocation (fetch-incidents in the CyfirmaCompromisedAccounts integration).
- Feeds CYFIRMA STIX 2.1 threat intelligence into XSOAR as indicators: IPs (including IPv6 and CIDR ranges), domains, URLs, file hashes, emails, registry keys, hosts, CVEs, threat actors, malware, campaigns, attack patterns, intrusion sets, tools, courses of action, reports, and locations (fetch-indicators in the CyfirmaThreatIntelligence integration).
- Fetches incrementally on a schedule, and gives clients control over volume: per-category toggles, a third-party alerts option, configurable first-fetch and look-back windows, and a tailored (organization-specific) feed instead of the global "all" feed. Tailoring keeps volume manageable, so the health check blocks a look-back longer than 2 days when it is off.
- One place for external risk. Attack surface, brand abuse, dark web, leaked-credential findings, and threat intelligence all land in XSOAR alongside internal alerts.
- Faster triage. About 30 incident types, a classifier, and three layouts (Attack Surface, Common, Compromised Accounts) show analysts structured grids instead of raw JSON: alert details, network attributes, digital footprints, deepfake details, and compromised-account details.
- Quicker brand and phishing response. Analysts can raise a take-down request directly from an incident (cyfirma-takedown-initiate) and track its status (cyfirma-takedown-list), without logging into another console.
- Vulnerability prioritization. CVE, CVSS (v2 and v3 metrics, score, vector), and KEV data, with vendors and products, help teams patch what attackers are actually exploiting.
- Playbook-ready data. Structured grids, the cyfirma-alert-parser command, and four parsing scripts make it easy to automate enrichment, ticketing, and notifications.
- On-demand lookups for enrichment: search an IOC, threat actor, malware, or vulnerability (cyfirma-ioc-search-get, cyfirma-threat-actor-search-get, cyfirma-malware-search-get, cyfirma-vulnerability-search-get), or list indicators of one type (cyfirma-ip-get, cyfirma-domain-get, cyfirma-url-get, cyfirma-file-get).
- Supports blocking or monitoring: indicators with a BLOCK recommended action are marked as blocked, and country is recorded. For file indicators, every hash is stored and the strongest one (SHA-256, SHA-1, MD5, SHA-512, SSDeep) is used as the value.

<~XSOAR>

## Configure the CYFIRMA Integration in XSOAR

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

**Note:**
Support and maintenance for this content pack is provided by **[Cyfirma](https://www.cyfirma.com)**.

</~XSOAR>
