# Brandefense Digital Risk Protection Services

Brandefense is a leading SaaS platform offering **Digital Risk Protection Services (DRPS)**, **External Attack Surface Management (EASM)**, and **Actionable Threat Intelligence** solutions. The AI-driven technology continuously scans the dark, deep, and surface web to discover unknown events, automatically prioritize risks, and deliver actionable intelligence.

This content pack integrates the Brandefense platform with Cortex XSOAR to automate threat intelligence workflows, incident ingestion, and IoC enrichment.

---

## Pack Contents

| Component | Count | Details |
|-----------|-------|---------|
| Integration | 1 | Brandefense |
| Commands | 23 | IoC enrichment, incident management, intelligence, indicators, assets, and more |
| Incident Types | 2 | Brandefense Incident, Brandefense Intelligence |
| Incident Fields | 16 | Custom fields for both incident types |
| Classifier | 1 | Brandefense - Classifier |
| Mapper | 1 | Brandefense - Incoming Mapper |

---

## 1. Prerequisites

- **Cortex XSOAR** version 6.5.0 or later.
- A **Brandefense account** with API access enabled.
- A **Brandefense API Bearer Token** with the following scopes:
  - Asset Read
  - Incident Read / Incident Create
  - Intelligence Read
  - Threat Intelligence Read
  - Threat Search
  - Indicator Read
  - Referrer Log Create
  - Audit Log Read
  - Compromised Device Read
  - Third Party Risk Management Read

### How to Get Your API Key

1. Log in at [https://app.brandefense.io](https://app.brandefense.io).
2. Navigate to **Settings > API Tokens**.
3. Click **Create New Token** and enable the required scopes.
4. Copy the generated token.

---

## 2. Configuration

Navigate to **Settings > Integrations > Servers & Services**, search for **Brandefense Digital Risk Protection Services**, and click **Add instance**.

### Parameters

| # | Parameter | Description | Default | Required |
|---|-----------|-------------|---------|----------|
| 1 | **Server URL** | Brandefense API endpoint | `https://api.brandefense.io` | Yes |
| 2 | **API Key** | Bearer token from Brandefense | — | Yes |
| 3 | **Trust any certificate** | Skip SSL verification (not recommended) | `false` | No |
| 4 | **Use system proxy settings** | Route through system proxy | `false` | No |
| 5 | **Fetch incidents** | Enable automatic incident fetching | — | No |
| 6 | **Incidents Fetch Interval** | Polling interval in minutes | `30` | No |
| 7 | **First time fetching** | Initial backfill period (e.g., `3 days`) | `3 days` | No |
| 8 | **Incident type** | Default XSOAR incident type | — | No |
| 9 | **Max Results** | Maximum items per fetch cycle | `30` | No |
| 10 | **Incident Category** | Filter: BRAND_MONITORING, EXECUTIVE_PROTECTION, EXPOSURE_MANAGEMENT, INTELLIGENCE, FRAUD_MONITORING, INTELLIGENCE_SUPPORT, INVESTIGATION, THIRD_PARTY_RISK_MANAGEMENT | — | No |
| 11 | **Incident Module** | Filter: SENSITIVE_FILE_DISCLOSURE, BREACH_MONITORING, PHISHING_MONITORING, DARKWEB_INTELLIGENCE, SOCIAL_MEDIA_MONITORING, MALICIOUS_FILES, EXECUTIVE_PROTECTION, VULNERABILITY_MANAGEMENT, ATTACK_SURFACE, and more | — | No |
| 12 | **Incident Status** | Filter: OPEN, IN_PROGRESS, CLOSED, RISK_ACCEPTED, REJECTED | `OPEN` | No |
| 13 | **Intelligence Category** | Filter: FRAUD_INTELLIGENCE, STRATEGIC_INTELLIGENCE, TACTICAL_INTELLIGENCE, OPERATIONAL_INTELLIGENCE, SECURITY_NEWS, THREAT_REPORTS | — | No |
| 14 | **Intelligence Search** | Keyword filter for intelligence tags | `CVE` | No |
| 15 | **Fetching Issue Types** | Select: Incident, Intelligence, or both | `Incident,Intelligence` | Yes |
| 16 | **Incident Rules** | Filter by specific detection rules (84 available) | — | No |

Click **Test** to verify connectivity.

---

## 3. Fetch Incidents

When **Fetch incidents** is enabled, the integration periodically polls the Brandefense API for new incidents and intelligence reports.

### Deduplication Strategy

The integration uses a dual-check deduplication approach:

1. **Timestamp-based** — Only processes items newer than or equal to the last fetch timestamp.
2. **Code-based** — Tracks up to 1,000 seen incident/intelligence codes in `last_run` to prevent duplicates when multiple items share the same `created_at` timestamp.

### Classification & Timing

- Each fetched item is tagged with `brandefense_type` = `Incident` or `Intelligence`.
- The classifier routes items to the correct incident type based on this field.
- Default fetch interval: **30 minutes**.
- Default first-fetch lookback: **3 days**.
- Maximum incidents per fetch cycle: configurable (default **30**, hard limit **200**).

---

## 4. Classifier & Mapper

### Classifier: Brandefense - Classifier

Routes fetched events based on the `brandefense_type` field:

| Key | Incident Type |
|-----|---------------|
| `Incident` | Brandefense Incident |
| `Intelligence` | Brandefense Intelligence |

Default incident type: **Brandefense Incident**.

### Mapper: Brandefense - Incoming Mapper

#### Brandefense Incident Field Mappings

| XSOAR Field | Source Field |
|-------------|-------------|
| Name | `title` |
| Severity | `severity` |
| Details | `description` |
| Source Brand | `Brandefense` (static) |
| Source Instance | `Brandefense` (static) |
| Brandefense Incident Code | `code` |
| Brandefense Incident Status | `status` |
| Brandefense Incident Module | `module` |
| Brandefense Incident Module Category | `module_category` |
| Brandefense Incident Type | `brandefense_original_type` |
| Brandefense Incident Tags | `tags` |
| Brandefense Incident Assignee | `assignee` |
| Brandefense Incident Network Type | `network_type` |
| Brandefense Incident Created At | `created_at` |
| Brandefense Reference URL | `reference_url` |
| Brandefense Indicators | `indicators` |
| MITRE Tactics | `mitre_tactics` |
| dbotMirrorId | `code` |

#### Brandefense Intelligence Field Mappings

| XSOAR Field | Source Field |
|-------------|-------------|
| Name | `title` |
| Severity | `severity` |
| Details | `description` |
| Source Brand | `Brandefense` (static) |
| Source Instance | `Brandefense` (static) |
| Brandefense Intelligence Code | `code` |
| Brandefense Intelligence Category | `category` |
| Brandefense Intelligence Tags | `tags` |
| Brandefense Intelligence Created At | `created_at` |
| Brandefense Reference URL | `reference_url` |
| Brandefense Indicators | `indicators` |
| dbotMirrorId | `code` |

---

## 5. Commands

### Reputation / Enrichment Commands

These commands participate in XSOAR auto-enrichment and produce standard DBotScore context.

#### `ip`

Investigate an IP address against Brandefense threat intelligence.

| Argument | Required | Description |
|----------|----------|-------------|
| `ip` | Yes | IP address to investigate (supports arrays). |

| Context Path | Type | Description |
|-------------|------|-------------|
| `IP.Address` | String | The IP address. |
| `IP.Malicious.Vendor` | String | Vendor reporting malicious. |
| `IP.Malicious.Description` | String | Description. |
| `DBotScore.Indicator` | String | Indicator tested. |
| `DBotScore.Score` | Number | DBot score (0-3). |
| `Brandefense.IP.data` | String | IP value. |
| `Brandefense.IP.severity` | String | Severity level. |
| `Brandefense.IP.category` | String | Threat category. |
| `Brandefense.IP.first_seen` | Date | First seen date. |
| `Brandefense.IP.last_seen` | Date | Last seen date. |

#### `domain`

Investigate a domain against Brandefense threat intelligence.

| Argument | Required | Description |
|----------|----------|-------------|
| `domain` | Yes | Domain name to investigate (supports arrays). |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Domain.Name` | String | The domain name. |
| `Domain.Malicious.Vendor` | String | Vendor reporting malicious. |
| `DBotScore.Indicator` | String | Indicator tested. |
| `DBotScore.Score` | Number | DBot score (0-3). |
| `Brandefense.Domain.data` | String | Domain value. |
| `Brandefense.Domain.severity` | String | Severity level. |
| `Brandefense.Domain.category` | String | Threat category. |
| `Brandefense.Domain.first_seen` | Date | First seen date. |
| `Brandefense.Domain.last_seen` | Date | Last seen date. |

#### `url`

Investigate a URL against Brandefense threat intelligence.

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | Yes | URL to investigate (supports arrays). |

| Context Path | Type | Description |
|-------------|------|-------------|
| `URL.Data` | String | The URL. |
| `URL.Malicious.Vendor` | String | Vendor reporting malicious. |
| `DBotScore.Indicator` | String | Indicator tested. |
| `DBotScore.Score` | Number | DBot score (0-3). |
| `Brandefense.URL.data` | String | URL value. |
| `Brandefense.URL.severity` | String | Severity level. |
| `Brandefense.URL.category` | String | Threat category. |
| `Brandefense.URL.first_seen` | Date | First seen date. |
| `Brandefense.URL.last_seen` | Date | Last seen date. |

#### `file`

Investigate a file hash (MD5, SHA1, or SHA256) against Brandefense threat intelligence.

| Argument | Required | Description |
|----------|----------|-------------|
| `file` | Yes | File hash to investigate (supports arrays). |

| Context Path | Type | Description |
|-------------|------|-------------|
| `File.MD5` | String | MD5 hash. |
| `File.SHA1` | String | SHA1 hash. |
| `File.SHA256` | String | SHA256 hash. |
| `File.Malicious.Vendor` | String | Vendor reporting malicious. |
| `DBotScore.Indicator` | String | Indicator tested. |
| `DBotScore.Score` | Number | DBot score (0-3). |
| `Brandefense.File.data` | String | Hash value. |
| `Brandefense.File.severity` | String | Severity level. |
| `Brandefense.File.category` | String | Threat category. |
| `Brandefense.File.first_seen` | Date | First seen date. |
| `Brandefense.File.last_seen` | Date | Last seen date. |

### Incident Management Commands

#### `brandefense_get_incidents`

Get Brandefense incidents with optional filtering.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `status` | No | `OPEN` | Filter: OPEN, IN_PROGRESS, CLOSED, RISK_ACCEPTED, REJECTED. |
| `time_range` | No | — | Predefined time range: `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`, `Last 90 Days`, `Last 6 Months`, `Last 1 Year`, `Custom`. Overrides `period` when set. |
| `created_at_range` | No | — | Custom date range (start,end). Example: `2020-10-10,2023-10-10`. Used when `time_range` is `Custom` or not set. |
| `period` | No | `1` | Fetch period in hours. Fallback when `time_range` is not set. |
| `module` | No | — | Filter by module (e.g., BREACH_MONITORING). |
| `module_category` | No | — | Filter by category (e.g., BRAND_MONITORING). |
| `MaxResults` | No | `100` | Maximum results. |
| `search` | No | — | Search keywords within incident title or code. |
| `severity` | No | — | Filter by severity: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `tags` | No | — | Filter by tags (comma-separated). |
| `network_type` | No | — | Filter by network type: `DARK_WEB`, `SURFACE_WEB`. |
| `mitre_tactics` | No | — | Filter by MITRE ATT&CK tactics (e.g. `RECONNAISSANCE`, `INITIAL_ACCESS`). |
| `ordering` | No | — | Order results: `created_at`, `-created_at`, `severity`, `-severity`. |
| `has_indicator` | No | — | Filter incidents with indicators: `true`, `false`. |
| `has_attachment` | No | — | Filter incidents with attachments: `true`, `false`. |
| `type` | No | — | Filter by incident type (e.g. `COMPROMISED_DEVICE`, `CONFIRMED_PHISHING_ADDRESS`). |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Incident.code` | String | Incident code. |
| `Brandefense.Incident.title` | String | Incident title. |
| `Brandefense.Incident.severity` | String | Severity. |
| `Brandefense.Incident.status` | String | Status. |
| `Brandefense.Incident.created_at` | Date | Creation date. |
| `Brandefense.Incident.reference_url` | String | Link to Brandefense. |
| `Brandefense.Incident.indicators` | Unknown | Associated indicators. |

#### `brandefense_get_incident_detail`

Get detailed information for a specific incident.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Incident code identifier. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.IncidentDetail.code` | String | Incident code. |
| `Brandefense.IncidentDetail.title` | String | Incident title. |
| `Brandefense.IncidentDetail.description` | String | Full description. |
| `Brandefense.IncidentDetail.severity` | String | Severity. |
| `Brandefense.IncidentDetail.status` | String | Status. |
| `Brandefense.IncidentDetail.created_at` | Date | Creation date. |
| `Brandefense.IncidentDetail.reference_url` | String | Link to Brandefense. |

#### `brandefense_change_incident_status`

Change the status of a Brandefense incident.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Incident code identifier. |
| `status` | Yes | New status: OPEN, IN_PROGRESS, CLOSED, RISK_ACCEPTED, REJECTED. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.ChangingStatus.code` | String | Incident code. |
| `Brandefense.ChangingStatus.status` | String | Updated status. |

#### `brandefense_incident_indicators`

Get indicators associated with a Brandefense incident.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Incident code identifier. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Incident.Indicators` | Unknown | List of indicators. |

#### `brandefense_get_incident_relatives`

Get related incidents for a specific Brandefense incident.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Incident code identifier. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Incident.Relatives` | Unknown | Related incidents. |

### Intelligence Commands

#### `brandefense_get_intelligences`

Get intelligence reports with optional filtering.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `category` | No | — | Filter: STRATEGIC_INTELLIGENCE, FRAUD_INTELLIGENCE, TACTICAL_INTELLIGENCE, OPERATIONAL_INTELLIGENCE, SECURITY_NEWS, THREAT_REPORTS. |
| `time_range` | No | — | Predefined time range: `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`, `Last 90 Days`, `Last 6 Months`, `Last 1 Year`, `Custom`. Overrides `period` when set. |
| `created_at_range` | No | — | Custom date range (start,end). Used when `time_range` is `Custom` or not set. |
| `period` | No | `24` | Fetch period in hours. Fallback when `time_range` is not set. |
| `search` | No | — | Keyword to filter by tag search. |
| `MaxResults` | No | `100` | Maximum results. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Intelligence.code` | String | Intelligence code. |
| `Brandefense.Intelligence.title` | String | Title. |
| `Brandefense.Intelligence.severity` | String | Severity. |
| `Brandefense.Intelligence.created_at` | Date | Creation date. |
| `Brandefense.Intelligence.reference_url` | String | Link to Brandefense. |

#### `brandefense_get_intelligence_detail`

Get detailed information for a specific intelligence report.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Intelligence code identifier. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.IntelligenceDetail.code` | String | Intelligence code. |
| `Brandefense.IntelligenceDetail.title` | String | Title. |
| `Brandefense.IntelligenceDetail.description` | String | Full description. |
| `Brandefense.IntelligenceDetail.severity` | String | Severity. |
| `Brandefense.IntelligenceDetail.created_at` | Date | Creation date. |
| `Brandefense.IntelligenceDetail.reference_url` | String | Link to Brandefense. |

#### `brandefense_intelligence_indicators`

Get indicators associated with an intelligence report.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Intelligence code identifier. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Intelligence.Indicators` | Unknown | List of indicators. |

#### `brandefense_get_intelligence_rules`

Get rules associated with an intelligence report.

| Argument | Required | Description |
|----------|----------|-------------|
| `code` | Yes | Intelligence code identifier. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Intelligence.Rules` | Unknown | Associated rules. |

### Threat Intelligence Commands

#### `threat_search`

Perform a CTI threat search and poll for results.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `value` | Yes | — | Value to search (domain, IP, hash, etc.). |
| `waitingtime` | Yes | `20` | Polling interval in seconds. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.ThreatSearch.uuid` | String | Search UUID. |
| `Brandefense.ThreatSearch.result` | Unknown | Search results. |

#### `brandefense_get_iocs`

Get Indicators of Compromise from threat intelligence feeds.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `ioc_type` | Yes | — | Type: ip_address, domain, url, hash. |
| `period` | No | `24h` | Time period (e.g., 24h, 7d). |
| `exclude_country` | No | — | Exclude IoCs from specific countries (comma-separated country codes). |
| `include_country` | No | — | Include IoCs only from specific countries (comma-separated country codes). |
| `module` | No | — | Filter IoCs by module. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.IOC.data` | String | IoC value. |
| `Brandefense.IOC.type` | String | IoC type. |
| `Brandefense.IOC.severity` | String | Severity. |
| `Brandefense.IOC.first_seen` | Date | First seen. |
| `Brandefense.IOC.last_seen` | Date | Last seen. |

#### `brandefense_get_ioc_list`

Fetch and consolidate all IoCs from the last N days. Pulls all 4 IoC types (IP, domain, URL, hash) and merges into a single list.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `days` | No | `30` | Days to look back (max 90). |
| `ioc_type` | No | all | Comma-separated IoC types to fetch. |
| `limit` | No | `5000` | Maximum total IoCs to return. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.IOCList.data` | String | IoC value. |
| `Brandefense.IOCList.ioc_type` | String | IoC type. |
| `Brandefense.IOCList.ioc_type_display` | String | Human-readable type. |
| `Brandefense.IOCList.severity` | String | Severity. |
| `Brandefense.IOCList.first_seen` | Date | First seen. |
| `Brandefense.IOCList.last_seen` | Date | Last seen. |

### Asset & Risk Management Commands

#### `brandefense_get_assets`

Get list of monitored assets from Brandefense.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `type` | No | — | Filter by type: DOMAIN, KEYWORD, URL, IP_ADDRESS, CIDR, EXECUTIVE_NAME, EXECUTIVE_EMAIL, EXECUTIVE_ACCOUNT, EXECUTIVE_NICKNAME, BIN_NUMBER, PRODUCT, GIT_REPO, GIT_ACCOUNT, PHISHING_RULE, LOGIN_PAGES, OFFICIAL_SOCIAL_MEDIA_ACCOUNTS, OFFICIAL_MOBILE_APPS, ADMIN_PAGES. |
| `severity` | No | — | Filter: HIGH, MEDIUM, LOW. |
| `status` | No | — | Filter: ACTIVE, SUGGESTED, REJECTED, PASSIVE. |
| `search` | No | — | Keyword search. |
| `module` | No | — | Filter by module code. |
| `max_results` | No | `50` | Maximum results. |
| `ordering` | No | — | Order results (e.g. `-severity`, `-type`, `severity`, `type`). |
| `time_range` | No | — | Predefined time range: `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`, `Last 90 Days`, `Last 6 Months`, `Last 1 Year`, `Custom`. |
| `created_at_range` | No | — | Custom date range (start,end). Example: `2024-01-01,2025-01-01`. Used when `time_range` is `Custom` or not set. |
| `threat_type` | No | — | Filter by threat type. |
| `asset_ilike` | No | — | Filter assets containing the given keyword. |
| `organization` | No | — | Filter by organization code (comma-separated for multiple). |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Asset.id` | Number | Asset ID. |
| `Brandefense.Asset.asset` | String | Asset value. |
| `Brandefense.Asset.type` | String | Asset type. |
| `Brandefense.Asset.severity` | String | Severity. |
| `Brandefense.Asset.status` | String | Status. |

#### `brandefense_get_domain_risk_assessment`

Get third-party domain risk assessments.

| Argument | Required | Description |
|----------|----------|-------------|
| `uuid` | No | Specific assessment UUID. Leave empty to list all. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.DomainRiskAssessment.uuid` | String | Assessment UUID. |
| `Brandefense.DomainRiskAssessment` | Unknown | Assessment data. |

### Operational Commands

#### `brandefense_get_compromised_devices`

Get compromised devices detected by Brandefense.

| Argument | Required | Description |
|----------|----------|-------------|
| `botnet_id` | No | Specific device ID. Leave empty to list all. |
| `username` | No | Filter by username (contains match). |
| `time_range` | No | Predefined time range: `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`, `Last 90 Days`, `Last 6 Months`, `Last 1 Year`, `Custom`. |
| `detection_date_range` | No | Custom date range (start,end). Example: `2020-10-10,2023-10-11`. Used when `time_range` is `Custom` or not set. |
| `search` | No | Search keyword to filter results. |
| `ordering` | No | Order results: `detection_date`, `-detection_date`. |
| `max_results` | No | Maximum number of devices to return. Default: 10. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.CompromisedDevice.id` | Number | Device ID. |
| `Brandefense.CompromisedDevice` | Unknown | Device data. |

#### `brandefense_get_audit_logs`

Get audit log entries from Brandefense.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `type` | No | — | Filter by audit log type. |
| `search` | No | — | Search keyword. |
| `time_range` | No | — | Predefined time range: `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`, `Last 90 Days`, `Last 6 Months`, `Last 1 Year`, `Custom`. |
| `created_at_range` | No | — | Custom date range (start,end). Used when `time_range` is `Custom` or not set. |
| `max_results` | No | `50` | Maximum results. |
| `actor_object_id` | No | — | Filter by user/actor ID (comma-separated for multiple). |
| `ip_address` | No | — | Filter by user IP address. |
| `ordering` | No | — | Order results: `id`, `-id`. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.AuditLog.id` | Number | Log ID. |
| `Brandefense.AuditLog` | Unknown | Log entry data. |

#### `brandefense_create_confirmed_phishing`

Create a confirmed phishing address incident in Brandefense.

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | Yes | The phishing URL to report. |
| `title` | No | Title for the phishing incident. |
| `network_type` | No | Network type: `DARK_WEB`, `SURFACE_WEB`. |
| `severity` | No | Severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `tags` | No | Tags for the incident (comma-separated). |
| `status` | No | Initial status: `OPEN`, `IN_PROGRESS`, `CLOSED`. |
| `asset_ids` | No | Associated asset IDs (comma-separated). |
| `data_source` | No | Source of the phishing data. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.ConfirmedPhishing` | Unknown | Created confirmed phishing incident data. |

#### `brandefense_takedown_request`

Request takedown for a confirmed phishing address.

| Argument | Required | Description |
|----------|----------|-------------|
| `url` | Yes | The phishing URL to request takedown for. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.TakedownRequest` | Unknown | Takedown request response data. |

### Indicator Management Commands

#### `brandefense_get_indicators`

Get indicators from Brandefense. Retrieves Consolidated Data and Incident indicators by type with optional organization, date range, and status filters.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `indicator_type` | Yes | — | Type of indicator: `leak`, `phishing_site`, `credit_card`, `cve`, `social_media`, `sensitive_file_disclosure`, `malicious-file`, `malicious_ads`. Each type has a different response body. |
| `organization_code` | No | — | Organization code(s), comma-separated. Example: `brandefense,other`. |
| `time_range` | No | — | Predefined time range: `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`, `Last 90 Days`, `Last 6 Months`, `Last 1 Year`, `Custom`. |
| `created_at_range` | No | — | Custom date range (start,end). Example: `2020-10-10,2023-10-10`. Used when `time_range` is `Custom` or not set. |
| `incident_status` | No | — | Filter by incident status(es): `OPEN`, `IN_PROGRESS`, `CLOSED`, `RISK_ACCEPTED`, `REJECTED`. Supports multiple values (comma-separated). |
| `page` | No | — | Page number within the paginated result set. |
| `page_size` | No | — | Results per page (10, 20, 50, 100). |
| `limit` | No | `50` | Maximum total results to return. |

| Context Path | Type | Description |
|-------------|------|-------------|
| `Brandefense.Indicator.id` | Number | Indicator ID. |
| `Brandefense.Indicator.created_at` | Date | Indicator creation date. |
| `Brandefense.Indicator.content_object` | Unknown | Indicator content data (varies by type). |
| `Brandefense.Indicator.content_object.data` | String | Primary indicator value (URL, email, hash, etc.). |
| `Brandefense.Indicator.content_object.username` | String | Username (leak type). |
| `Brandefense.Indicator.content_object.password` | String | Password (leak type). |
| `Brandefense.Indicator.content_object.source_platform` | String | Source platform. |
| `Brandefense.Indicator.content_object.threat_actor` | String | Threat actor. |
| `Brandefense.Indicator.content_object.breached_date` | Date | Breach date. |
| `Brandefense.Indicator.threats` | Unknown | Associated threats. |
| `Brandefense.Indicator.threats.title` | String | Threat title. |
| `Brandefense.Indicator.threats.incidents.code` | String | Incident code. |
| `Brandefense.Indicator.threats.incidents.organization.name` | String | Organization name. |

---

## 6. IoC Caching & Threat Lists

The integration implements an **in-memory IoC cache** to reduce redundant API calls during enrichment:

| Setting | Value |
|---------|-------|
| Cache TTL | **6 hours** |
| Max cache entries | **5,000** |
| Eviction policy | Oldest entries removed first when cache exceeds max size |
| Storage | Integration context (persists across playbook runs) |

### How It Works

1. When a reputation command (`ip`, `domain`, `url`, `file`) is called, the cache is checked first.
2. On **cache hit**: the stored result is returned immediately (no API call).
3. On **cache miss**: the API is queried, the result is stored, and the TTL clock starts.
4. Expired entries are automatically removed on the next lookup.

### Managing the Cache

The cache is stored in the integration context. To clear it, reset the integration context from **Settings > Integrations > Instances > (your instance) > Reset Integration Cache**.

---

## 7. Incident Types & Fields

### Incident Types

| Type | Color | Layout |
|------|-------|--------|
| **Brandefense Incident** | Purple (#6E3F9E) | Brandefense Incident Layout |
| **Brandefense Intelligence** | Blue (#2F5FB4) | Brandefense Intelligence Layout |

### Custom Incident Fields

#### Brandefense Incident Fields

| Field Name | CLI Name | Type | Description |
|-----------|----------|------|-------------|
| Brandefense Incident Code | `brandefenseincidentcode` | Short Text | Incident code identifier |
| Brandefense Incident Status | `brandefenseincidentstatus` | Short Text | Current status |
| Brandefense Incident Module | `brandefenseincidentmodule` | Short Text | Associated module |
| Brandefense Incident Module Category | `brandefenseincidentmodulecategory` | Short Text | Module category |
| Brandefense Incident Type | `brandefenseincidenttype` | Short Text | Original incident type |
| Brandefense Incident Tags | `brandefenseincidenttags` | Short Text | Tags |
| Brandefense Incident Assignee | `brandefenseincidentassignee` | Short Text | Assignee |
| Brandefense Incident Network Type | `brandefenseincidentnetworktype` | Short Text | Network type |
| Brandefense Incident Created At | `brandefenseincidentcreatedat` | Short Text | Creation timestamp |
| MITRE Tactics | `mitretactics` | Short Text | Mapped MITRE ATT&CK tactics |

#### Brandefense Intelligence Fields

| Field Name | CLI Name | Type | Description |
|-----------|----------|------|-------------|
| Brandefense Intelligence Code | `brandefenseintelligencecode` | Short Text | Intelligence code identifier |
| Brandefense Intelligence Category | `brandefenseintelligencecategory` | Short Text | Category |
| Brandefense Intelligence Tags | `brandefenseintelligencetags` | Short Text | Tags |
| Brandefense Intelligence Created At | `brandefenseintelligencecreatedat` | Short Text | Creation timestamp |

#### Shared Fields

| Field Name | CLI Name | Type | Description |
|-----------|----------|------|-------------|
| Brandefense Reference URL | `brandefensereferenceurl` | Short Text | Link to Brandefense portal |
| Brandefense Indicators | `brandefenseindicators` | Short Text | Associated IoC indicators |

---

## 8. Detection Rules

The integration supports filtering incidents by **84 detection rules**. Configure these in the **Incident Rules** parameter. Leave unselected to receive all alert types.

<details>
<summary>View all 84 detection rules</summary>

| Category | Rules |
|----------|-------|
| **Breach & Account Monitoring** | Compromised Employee Account Detection, Compromised Client Account Detection, Executive Person Email Leak, Compromised Device Detection, Compromised Employee Accounts via Botnet Attack, Malicious File Identified on Compromised Device, Compromised Supply Chain Device |
| **Phishing & Impersonation** | Confirmed Phishing Address, Potential Phishing Address, Confirmed Impersonated Account, Potential Impersonated Account |
| **Dark Web** | Dark Web Intelligence, Suspected Dark Web Exposure of Organization Asset, Suspected Dark Web Exposure of Supply Chain Asset, Data Sale Detection of Brand Accounts |
| **Vulnerability Management** | Vulnerable Technology Assessment, Vulnerability Detection, Externally Exploitable Vulnerability Detection, SSL/TLS Vulnerability Detection, SSL/TLS Weak Cipher & Algorithm Detection, SSL/TLS Certificate Missing Domain Inclusion, Expired SSL/TLS Detection, SSL Expires in 30 Days, Vulnerable HTTP Security Headers Detection, Vulnerable SSH Protocol Detection |
| **Attack Surface** | Attack Surface, Management Port Detection, Unidentified Management Port Detection, Filtered Statused Management Port Exposure, Insecure Redirect Protocol (HTTP) Detection, Unsecure Login Page Detection, Private IP Address Exposure, Hacker Search Engine Monitoring Detection |
| **Infrastructure** | Exposed Redis Server, Exposed Memcached System, Open DNS Resolver Detection, DNS Server Allows Cache Snooping, DNS Zone Transfer Detection, DNSSEC Not Found, Shared Hosting Detection, LDAP Server Allows Anonymous Bindings, Anonymous FTP Detection, SSH Supports Weak MAC Algorithms, SSH Supports Weak Ciphers, Blacklisted IP Address Detection, Blacklisted Domain Address Detection, Subdomain Takeover Detection |
| **Email Security** | SPF Misconfiguration, DMARC Not Found, DMARC Policy Not Configured, SMTP Open Relay Detection, SMTP Open Relay Detection for Supplier Systems |
| **Domain & SSL** | Domain Registrar Transfer Protection Not Enabled, Domain Expires in 30 Days, Expired Domain Detection, Expired Supply Chain Domain Detection |
| **Cloud Storage Misconfigurations** | Misconfigured AWS S3 Bucket, Misconfigured Azure Blob Storage, Misconfigured Google Cloud Storage, Misconfigured IBM Cloud Object Storage, Misconfigured Alibaba Cloud OSS, Misconfigured Backblaze B2 Bucket, Misconfigured DigitalOcean Space, Misconfigured Oracle Cloud Object Storage |
| **Code & Data Exposure** | Sensitive File Disclosure, Sensitive File Disclosure on GitHub Repositories, Sensitive File Disclosure on Postman Collections, Disclosure of Important Technology Information |
| **Fraud & Financial** | Stolen Credit/Debit Card Detection, Credit Card, Fraud Protection |
| **Ransomware & Malware** | Your Company Attacked by a Ransomware Group, Ransomware Attack Detected for Related Supply Chain Asset, Malicious File Detection, Malware Analysis |
| **Other** | Custom Investigation, Security Scan, Detection of Torrent Download Activity, Potentially Exposed SCADA Services, Potentially Vulnerable Exposed Technology, Entity Found in Threat Intelligence Feeds, Daily Discovered Entity Updates, Executive's Cyber Risk Assessment, Third Party Risk Management |

</details>

---

## 9. Rate Limiting & Throttling

The integration includes built-in request throttling to prevent hitting Brandefense API rate limits:

| Setting | Value |
|---------|-------|
| Delay between API calls | **300ms** |
| Pagination page size | **100** items per page |
| Max incidents per fetch | **200** (hard limit) |

The throttle is automatically applied to all API requests. No configuration is needed.

---

## 10. Troubleshooting

| Issue | Solution |
|-------|----------|
| **"Authorization Error: make sure API Key is correctly set"** | Verify the API key is correct and has the required scopes. Regenerate the token if needed. |
| **"Authorization Error: invalid API key"** | The API key has been revoked or expired. Generate a new one from the Brandefense portal. |
| **No incidents being fetched** | Ensure **Fetch incidents** is enabled. Check that **Fetching Issue Types** includes the desired types. Verify filter parameters are not too restrictive. |
| **Duplicate incidents appearing** | This should not happen due to built-in deduplication. If it does, reset the integration cache and last run from **Settings > Integrations > Instances**. |
| **Slow enrichment commands** | IoC results are cached for 6 hours. First lookups require an API call; subsequent lookups for the same indicator are instant. |
| **Missing fields on incidents** | Verify the **Brandefense - Incoming Mapper** is selected as the mapper for the integration instance. |
| **Wrong incident type routing** | Verify the **Brandefense - Classifier** is selected as the classifier for the integration instance. |
| **Rate limit errors** | The integration includes 300ms throttling between requests. If you still hit limits, increase the fetch interval or reduce Max Results. |
| **Connection timeout** | Check network connectivity to `https://api.brandefense.io`. Verify proxy settings if applicable. |

---

## Additional Information

- **Support**: support@brandefense.io
- **Website**: [https://www.brandefense.io](https://www.brandefense.io)
- **Portal**: [https://app.brandefense.io](https://app.brandefense.io)
- **Pack Version**: 1.0.0
- **Docker Image**: `demisto/python3:3.11.10.111039`
