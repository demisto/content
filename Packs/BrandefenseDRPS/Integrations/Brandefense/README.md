# Brandefense Digital Risk Protection Services

Brandefense is a leading SaaS platform offering Digital Risk Protection Services (DRPS), External Attack Surface Management (EASM), and Actionable Threat Intelligence solutions. This integration connects Cortex XSOAR with the Brandefense platform to automate threat intelligence operations.

## What does this pack do?

- **Fetch incidents and intelligence reports** from Brandefense as XSOAR incidents with deduplication
- **Search IoCs** — Investigate IP addresses, domains, URLs, and file hashes
- **Manage incidents** — View details, indicators, related incidents, and change status
- **Intelligence reports** — Retrieve intelligence with indicators and rules
- **Threat search** — Perform CTI-powered threat searches
- **Asset management** — List and search monitored assets
- **Compromised devices** — Detect and investigate compromised devices
- **Audit logs** — Review platform audit trail
- **Domain risk assessments** — Third-party risk management scoring
- **Phishing response** — Create confirmed phishing incidents and request takedowns
- **Indicator management** — Retrieve consolidated indicators by type (leak, phishing, credit card, CVE, etc.)

---

## Commands

| # | Command | Description |
|---|---------|-------------|
| 1 | `ip` | Investigate an IP address |
| 2 | `domain` | Investigate a domain |
| 3 | `url` | Investigate a URL against Brandefense IoC database |
| 4 | `file` | Investigate a file hash (MD5/SHA1/SHA256) |
| 5 | `brandefense_get_incidents` | Get incidents with filtering |
| 6 | `brandefense_get_incident_detail` | Get specific incident details |
| 7 | `brandefense_change_incident_status` | Change incident status |
| 8 | `brandefense_incident_indicators` | Get incident indicators |
| 9 | `brandefense_get_incident_relatives` | Get related incidents |
| 10 | `brandefense_get_intelligences` | Get intelligence reports |
| 11 | `brandefense_get_intelligence_detail` | Get intelligence details |
| 12 | `brandefense_intelligence_indicators` | Get intelligence indicators |
| 13 | `brandefense_get_intelligence_rules` | Get intelligence rules |
| 14 | `threat_search` | CTI threat search with polling |
| 15 | `brandefense_get_iocs` | Get IoC feeds by type |
| 16 | `brandefense_get_ioc_list` | Consolidated IoC list from last N days |
| 17 | `brandefense_get_assets` | List monitored assets |
| 18 | `brandefense_get_domain_risk_assessment` | Get domain risk assessments |
| 19 | `brandefense_get_compromised_devices` | Get compromised devices |
| 20 | `brandefense_get_audit_logs` | Get audit log entries |
| 21 | `brandefense_create_confirmed_phishing` | Create confirmed phishing incident |
| 22 | `brandefense_takedown_request` | Request takedown for phishing URL |
| 23 | `brandefense_get_indicators` | Get indicators by type and organization |

---

## Fetching Incidents

The integration supports automatic incident fetching with **no-duplicate guarantee**:

- Fetches both **Incidents** and **Intelligence** reports (configurable)
- Tracks seen incident codes across fetch cycles to prevent duplicates
- Uses timestamp + code-based deduplication
- Configurable filters: status, module, category, rules, intelligence category
- Auto-maps to custom incident types: `Brandefense Incident` and `Brandefense Intelligence`

### Configuration
1. Enable **Fetch incidents** in the integration settings
2. Set the **Fetch Interval** (default: 30 minutes)
3. Configure **First time fetching** for initial backfill (default: 3 days)
4. Select which **Fetching Issue Types** to ingest
5. Optionally filter by category, module, status, or rules

---

## Setup

1. Navigate to **Settings → Integrations → Servers & Services**
2. Search for **Brandefense Digital Risk Protection Services**
3. Click **Add instance**
4. Configure:
   - **Server URL**: `https://api.brandefense.io` (default)
   - **API Key**: Your Brandefense API Bearer Token
5. Click **Test** to verify connectivity
6. Set the **Classifier** to `Brandefense - Classifier`
7. Set the **Mapper** to `Brandefense - Incoming Mapper`
