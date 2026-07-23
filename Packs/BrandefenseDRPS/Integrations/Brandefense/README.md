# Brandefense Digital Risk Protection Services

Brandefense is a SaaS platform offering Digital Risk Protection Services (DRPS), External Attack Surface Management (EASM), and Actionable Threat Intelligence. This integration connects Cortex XSOAR with the Brandefense platform to automate threat intelligence, brand monitoring, and phishing response operations.

## What does this pack do?

- Fetches incidents and intelligence reports from Brandefense as Cortex XSOAR incidents (with deduplication).
- Investigates IP addresses, domains, URLs, and file hashes against Brandefense IoC data.
- Manages incidents: view details, indicators, related incidents, and change status.
- Retrieves intelligence reports with indicators and rules.
- Runs CTI-powered threat searches.
- Lists and searches monitored assets.
- Detects and investigates compromised devices.
- Reviews the Brandefense platform audit trail.
- Retrieves domain risk assessments for third-party risk management.
- Creates confirmed phishing incidents and requests takedowns.
- Retrieves consolidated indicators by type (leak, phishing, credit card, CVE, and similar categories).

## Fetch Incidents

The integration supports automatic incident fetching without duplicates.

- Fetches both **Incidents** and **Intelligence** reports (configurable via **Fetching Issue Types**).
- Tracks previously seen incident codes across fetch cycles to prevent duplicates.
- Uses timestamp and code-based deduplication.
- Auto-classifies items into the `Brandefense Incident` and `Brandefense Intelligence` types via the built-in classifier and incoming mapper.

## Configure Brandefense Digital Risk Protection Services on Cortex XSOAR

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. <https://api.brandefense.io>) |  | True |
| API Key | You can reach out your access token: <https://brandefense.io/> | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval | Start fetching incidents from the specified time. | False |
| First time fetching |  | False |
| Incident type |  | False |
| Max Results |  | False |
| Incident Category | This parameter will request and show the incident's related module category. | False |
| Incident Module | This parameter will request and show the incident's related module. | False |
| Incident Status | This parameter will request incident's by status. | False |
| Intelligence Category | This parameter allows you to filter intelligence values by categories. | False |
| Intelligence Search | This parameter allows you to filter intelligence values with keyword search. | False |
| Fetching Issue Types | This parameter allows you to filter fetching by issue type. | True |
| Incident Rules | This parameter will request and show the incident's related template. Don't select any to get all alerts. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Investigate an IP address against Brandefense threat intelligence.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to investigate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. |
| IP.Malicious.Vendor | String | Vendor reporting the IP as malicious. |
| IP.Malicious.Description | String | Description of the malicious IP. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Brandefense.IP.data | String | The IP address value. |
| Brandefense.IP.severity | String | Severity level. |
| Brandefense.IP.category | String | Category of the threat. |
| Brandefense.IP.first_seen | Date | First seen date. |
| Brandefense.IP.last_seen | Date | Last seen date. |

### domain

***
Investigate a domain against Brandefense threat intelligence.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to investigate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. |
| Domain.Malicious.Vendor | String | Vendor reporting the domain as malicious. |
| Domain.Malicious.Description | String | Description of the malicious domain. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Brandefense.Domain.data | String | The domain value. |
| Brandefense.Domain.severity | String | Severity level. |
| Brandefense.Domain.category | String | Category of the threat. |
| Brandefense.Domain.first_seen | Date | First seen date. |
| Brandefense.Domain.last_seen | Date | Last seen date. |

### url

***
Investigate a URL against Brandefense threat intelligence.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL address to investigate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. |
| URL.Malicious.Vendor | String | Vendor reporting the URL as malicious. |
| URL.Malicious.Description | String | Description of the malicious URL. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Brandefense.URL.data | String | The URL value. |
| Brandefense.URL.severity | String | Severity level. |
| Brandefense.URL.category | String | Category of the threat. |
| Brandefense.URL.first_seen | Date | First seen date. |
| Brandefense.URL.last_seen | Date | Last seen date. |

### file

***
Investigate a file hash against Brandefense threat intelligence.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash to investigate (MD5, SHA1, or SHA256). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.Malicious.Vendor | String | Vendor reporting the file as malicious. |
| File.Malicious.Description | String | Description of the malicious file. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source. |
| Brandefense.File.data | String | The hash value. |
| Brandefense.File.severity | String | Severity level. |
| Brandefense.File.category | String | Category of the threat. |
| Brandefense.File.first_seen | Date | First seen date. |
| Brandefense.File.last_seen | Date | Last seen date. |

### brandefense_get_incidents

***
Get Brandefense incidents with optional filtering by status, module, category, and time period.

#### Base Command

`brandefense_get_incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Filter incidents by status. Possible values are: OPEN, IN_PROGRESS, CLOSED, RISK_ACCEPTED, REJECTED. Default is OPEN. | Optional |
| time_range | Predefined time range. Overrides 'period' when set. Select 'Custom' to use created_at_range. Possible values are: Last 24 Hours, Last 7 Days, Last 30 Days, Last 90 Days, Last 6 Months, Last 1 Year, Custom. | Optional |
| created_at_range | Custom date range (start,end). Example: 2020-10-10,2023-10-10. Used when time_range is 'Custom' or not set. | Optional |
| period | Fetch period in hours. Used as fallback when time_range is not set. Default is 1. | Optional |
| module | Filter by incident module. Possible values are: SENSITIVE_FILE_DISCLOSURE, BREACH_MONITORING, PHISHING_MONITORING, DARKWEB_INTELLIGENCE, SOCIAL_MEDIA_MONITORING, MALICIOUS_FILES, EXECUTIVE_PROTECTION, SUPPLY_CHAIN_SECURITY, VULNERABILITY_MANAGEMENT, ATTACK_SURFACE, VULNERABILITY_INTELLIGENCE, INTELLIGENCE, THREAT_INTELLIGENCE, CREDIT_CARD, FRAUD_PROTECTION, CUSTOM_INVESTIGATION, MALWARE_ANALYZE, INVESTIGATION. | Optional |
| module_category | Filter by module category. Possible values are: BRAND_MONITORING, EXECUTIVE_PROTECTION, SUPPLY_CHAIN_SECURITY, EXPOSURE_MANAGEMENT, INTELLIGENCE, FRAUD_MONITORING, INTELLIGENCE_SUPPORT, INVESTIGATION. | Optional |
| MaxResults | Maximum number of incidents to return. Default is 100. | Optional |
| search | Search keywords within incident title or code. | Optional |
| severity | Filter by incident severity. Possible values are: INFO, LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| tags | Filter by tags (comma-separated). | Optional |
| network_type | Filter by network type. Possible values are: DARK_WEB, SURFACE_WEB. | Optional |
| mitre_tactics | Filter by MITRE ATT&amp;CK tactics. Possible values are: RECONNAISSANCE, RESOURCE_DEVELOPMENT, INITIAL_ACCESS, EXECUTION, PERSISTENCE, PRIVILEGE_ESCALATION, DEFENSE_EVASION, CREDENTIAL_ACCESS, DISCOVERY, LATERAL_MOVEMENT, COLLECTION, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT. | Optional |
| ordering | Order results. Possible values are: created_at, -created_at, severity, -severity. | Optional |
| has_indicator | Filter incidents that have indicators. Possible values are: true, false. | Optional |
| has_attachment | Filter incidents that have attachments. Possible values are: true, false. | Optional |
| type | Filter by incident type. Possible values are: COMPROMISED_EMPLOYEE_ACCOUNT, COMPROMISED_CLIENT_ACCOUNT, EXECUTIVE_PERSON_EMAIL_LEAK, COMPROMISED_DEVICE, CONFIRMED_PHISHING_ADDRESS, POTENTIAL_PHISHING_ADDRESS, DARKWEB_INTELLIGENCE, SENSITIVE_FILE_DISCLOSURE, CONFIRMED_IMPERSONATED_ACCOUNT, POTENTIAL_IMPERSONATED_ACCOUNT, VULNERABLE_TECHNOLOGY_ASSESSMENT, CREDIT_CARD, ATTACK_SURFACE, CUSTOM_INVESTIGATION, MALWARE_ANALYZE, FRAUD_PROTECTION, VULNERABILITY_DETECTION, OTHER. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Incident.id | Number | Incident ID. |
| Brandefense.Incident.code | String | Incident code. |
| Brandefense.Incident.title | String | Incident title. |
| Brandefense.Incident.created_at | Date | Incident creation date. |
| Brandefense.Incident.status | String | Incident status. |
| Brandefense.Incident.severity | String | Incident severity. |
| Brandefense.Incident.reference_url | String | URL to view the incident in Brandefense. |
| Brandefense.Incident.indicators | Unknown | List of indicators associated with the incident. |

### brandefense_get_incident_detail

***
Get detailed information for a specific Brandefense incident.

#### Base Command

`brandefense_get_incident_detail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Incident code identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.IncidentDetail.code | String | Incident code. |
| Brandefense.IncidentDetail.title | String | Incident title. |
| Brandefense.IncidentDetail.description | String | Incident description. |
| Brandefense.IncidentDetail.severity | String | Incident severity. |
| Brandefense.IncidentDetail.status | String | Incident status. |
| Brandefense.IncidentDetail.created_at | Date | Creation date. |
| Brandefense.IncidentDetail.reference_url | String | URL to view in Brandefense. |

### brandefense_change_incident_status

***
Change the status of a Brandefense incident.

#### Base Command

`brandefense_change_incident_status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Incident code identifier. | Required |
| status | New incident status. Possible values are: OPEN, IN_PROGRESS, CLOSED, RISK_ACCEPTED, REJECTED. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.ChangingStatus.code | String | Incident code. |
| Brandefense.ChangingStatus.status | String | Updated incident status. |

### brandefense_incident_indicators

***
Get indicators associated with a Brandefense incident.

#### Base Command

`brandefense_incident_indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Incident code identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Incident.Indicators | Unknown | List of indicators for the incident. |

### brandefense_get_incident_relatives

***
Get related incidents for a specific Brandefense incident.

#### Base Command

`brandefense_get_incident_relatives`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Incident code identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Incident.Relatives | Unknown | List of related incidents. |

### threat_search

***
Perform a CTI threat search and poll for results using ScheduledCommand.

#### Base Command

`threat_search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Value to search for (domain, IP, hash, etc.). | Required |
| interval_in_seconds | Polling interval in seconds between checks. Default is 20. | Optional |
| timeout_in_seconds | Maximum time in seconds to wait for results before timing out. Default is 600. | Optional |
| uuid | Threat search UUID for continuing an in-progress search (internal). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.ThreatSearch.uuid | String | Threat search UUID. |
| Brandefense.ThreatSearch.result | Unknown | Threat search result data. |

### brandefense_get_intelligences

***
Get Brandefense intelligence reports with optional filtering.

#### Base Command

`brandefense_get_intelligences`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Filter by intelligence category. Possible values are: STRATEGIC_INTELLIGENCE, FRAUD_INTELLIGENCE, TACTICAL_INTELLIGENCE, OPERATIONAL_INTELLIGENCE, SECURITY_NEWS, THREAT_REPORTS. | Optional |
| time_range | Predefined time range. Overrides 'period' when set. Select 'Custom' to use created_at_range. Possible values are: Last 24 Hours, Last 7 Days, Last 30 Days, Last 90 Days, Last 6 Months, Last 1 Year, Custom. | Optional |
| created_at_range | Custom date range (start,end). Example: 2020-10-10,2023-10-10. Used when time_range is 'Custom' or not set. | Optional |
| period | Fetch period in hours. Used as fallback when time_range is not set. Default is 24. | Optional |
| search | Keyword to filter intelligence by tag search. | Optional |
| MaxResults | Maximum number of intelligence reports to return. Default is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Intelligence.code | String | Intelligence code. |
| Brandefense.Intelligence.title | String | Intelligence title. |
| Brandefense.Intelligence.severity | String | Intelligence severity. |
| Brandefense.Intelligence.created_at | Date | Creation date. |
| Brandefense.Intelligence.reference_url | String | URL to view in Brandefense. |

### brandefense_get_intelligence_detail

***
Get detailed information for a specific intelligence report.

#### Base Command

`brandefense_get_intelligence_detail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Intelligence code identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.IntelligenceDetail.code | String | Intelligence code. |
| Brandefense.IntelligenceDetail.title | String | Intelligence title. |
| Brandefense.IntelligenceDetail.description | String | Intelligence description. |
| Brandefense.IntelligenceDetail.severity | String | Intelligence severity. |
| Brandefense.IntelligenceDetail.created_at | Date | Creation date. |
| Brandefense.IntelligenceDetail.reference_url | String | URL to view in Brandefense. |

### brandefense_intelligence_indicators

***
Get indicators associated with a Brandefense intelligence report.

#### Base Command

`brandefense_intelligence_indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Intelligence code identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Intelligence.Indicators | Unknown | List of indicators for the intelligence report. |

### brandefense_get_intelligence_rules

***
Get rules associated with a Brandefense intelligence report.

#### Base Command

`brandefense_get_intelligence_rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | Intelligence code identifier. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Intelligence.Rules | Unknown | Rules associated with the intelligence report. |

### brandefense_get_assets

***
Get list of monitored assets from Brandefense.

#### Base Command

`brandefense_get_assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Filter by asset type. Possible values are: DOMAIN, KEYWORD, URL, IP_ADDRESS, CIDR, EXECUTIVE_NAME, EXECUTIVE_EMAIL, EXECUTIVE_ACCOUNT, EXECUTIVE_NICKNAME, BIN_NUMBER, PRODUCT, GIT_REPO, GIT_ACCOUNT, PHISHING_RULE, LOGIN_PAGES, OFFICIAL_SOCIAL_MEDIA_ACCOUNTS, OFFICIAL_MOBILE_APPS, ADMIN_PAGES. | Optional |
| severity | Filter by severity. Possible values are: HIGH, MEDIUM, LOW. | Optional |
| status | Filter by status. Possible values are: ACTIVE, SUGGESTED, REJECTED, PASSIVE. | Optional |
| search | Keyword search. | Optional |
| module | Filter by module code. | Optional |
| max_results | Maximum number of assets to return. Default is 50. | Optional |
| ordering | Order results (e.g. -severity, -type, severity, type). | Optional |
| time_range | Predefined time range. Select 'Custom' to use created_at_range. Possible values are: Last 24 Hours, Last 7 Days, Last 30 Days, Last 90 Days, Last 6 Months, Last 1 Year, Custom. | Optional |
| created_at_range | Custom date range (start,end). Example: 2020-10-10,2023-10-10. Used when time_range is 'Custom' or not set. | Optional |
| threat_type | Filter by threat type. | Optional |
| asset_ilike | Filter assets containing the given keyword. | Optional |
| organization | Filter by organization code (comma-separated for multiple). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Asset.id | Number | Asset ID. |
| Brandefense.Asset.asset | String | Asset value. |
| Brandefense.Asset.type | String | Asset type. |
| Brandefense.Asset.severity | String | Asset severity. |
| Brandefense.Asset.status | String | Asset status. |

### brandefense_get_iocs

***
Get Indicators of Compromise from Brandefense threat intelligence feeds.

#### Base Command

`brandefense_get_iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | Type of IoC to retrieve. Possible values are: ip_address, domain, url, hash. | Required |
| period | Time period for IoCs (e.g., 24h, 7d). Default is 24h. | Optional |
| exclude_country | Exclude IoCs from specific countries (comma-separated country codes). | Optional |
| include_country | Include IoCs only from specific countries (comma-separated country codes). | Optional |
| module | Filter IoCs by module. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.IOC.data | String | IoC value. |
| Brandefense.IOC.type | String | IoC type. |
| Brandefense.IOC.severity | String | IoC severity. |
| Brandefense.IOC.first_seen | Date | First seen date. |
| Brandefense.IOC.last_seen | Date | Last seen date. |

### brandefense_get_ioc_list

***
Fetch and consolidate all IoCs from the last N days (default 30). Pulls all IoC types and merges into a single list.

#### Base Command

`brandefense_get_ioc_list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| days | Number of days to look back (default 30, max 90). Default is 30. | Optional |
| ioc_type | Comma-separated list of IoC types to fetch. Leave empty for all types. | Optional |
| limit | Maximum total number of IoCs to return. Default is 5000. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.IOCList.data | String | IoC value. |
| Brandefense.IOCList.ioc_type | String | IoC type. |
| Brandefense.IOCList.ioc_type_display | String | Human-readable IoC type. |
| Brandefense.IOCList.severity | String | IoC severity. |
| Brandefense.IOCList.first_seen | Date | First seen date. |
| Brandefense.IOCList.last_seen | Date | Last seen date. |

### brandefense_get_compromised_devices

***
Get compromised devices detected by Brandefense.

#### Base Command

`brandefense_get_compromised_devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| botnet_id | Specific botnet/device ID to retrieve details for. Leave empty to list all. | Optional |
| username | Filter by username (contains match). | Optional |
| time_range | Predefined time range for detection date. Select 'Custom' to use detection_date_range. Possible values are: Last 24 Hours, Last 7 Days, Last 30 Days, Last 90 Days, Last 6 Months, Last 1 Year, Custom. | Optional |
| detection_date_range | Custom date range (start,end). Example: 2020-10-10,2023-10-11. Used when time_range is 'Custom' or not set. | Optional |
| search | Search keyword to filter results. | Optional |
| ordering | Order results. Valid values are detection_date, -detection_date. | Optional |
| max_results | Maximum number of devices to return. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.CompromisedDevice.id | Number | Device ID. |
| Brandefense.CompromisedDevice | Unknown | Compromised device data. |

### brandefense_get_audit_logs

***
Get audit log entries from Brandefense.

#### Base Command

`brandefense_get_audit_logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Filter by audit log type. | Optional |
| search | Search keyword. | Optional |
| time_range | Predefined time range. Select 'Custom' to use created_at_range. Possible values are: Last 24 Hours, Last 7 Days, Last 30 Days, Last 90 Days, Last 6 Months, Last 1 Year, Custom. | Optional |
| created_at_range | Custom date range (start,end). Example: 2020-10-10,2023-10-10. Used when time_range is 'Custom' or not set. | Optional |
| max_results | Maximum number of logs to return. Default is 50. | Optional |
| actor_object_id | Filter by user/actor ID (comma-separated for multiple). | Optional |
| ip_address | Filter by user IP address. | Optional |
| ordering | Order results. Possible values are: id, -id. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.AuditLog.id | Number | Audit log ID. |
| Brandefense.AuditLog | Unknown | Audit log entry data. |

### brandefense_get_domain_risk_assessment

***
Get third-party domain risk assessments from Brandefense.

#### Base Command

`brandefense_get_domain_risk_assessment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Specific assessment UUID. Leave empty to list all. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.DomainRiskAssessment.uuid | String | Assessment UUID. |
| Brandefense.DomainRiskAssessment | Unknown | Domain risk assessment data. |

### brandefense_create_confirmed_phishing

***
Create a confirmed phishing address incident in Brandefense.

#### Base Command

`brandefense_create_confirmed_phishing`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The phishing URL to report. | Required |
| title | Title for the phishing incident. | Optional |
| network_type | Network type where phishing was found. Possible values are: DARK_WEB, SURFACE_WEB. | Optional |
| severity | Severity of the phishing incident. Possible values are: LOW, MEDIUM, HIGH, CRITICAL. | Optional |
| tags | Tags for the incident (comma-separated). | Optional |
| status | Initial status of the incident. Possible values are: OPEN, IN_PROGRESS, CLOSED. | Optional |
| asset_ids | Associated asset IDs (comma-separated). | Optional |
| data_source | Source of the phishing data. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.ConfirmedPhishing | Unknown | Created confirmed phishing incident data. |

### brandefense_takedown_request

***
Request takedown for a confirmed phishing address.

#### Base Command

`brandefense_takedown_request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The phishing URL to request takedown for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.TakedownRequest | Unknown | Takedown request response data. |

### brandefense_get_indicators

***
Get indicators from Brandefense. Retrieves Consolidated Data and Incident indicators by type and organization with optional date range and status filters.

#### Base Command

`brandefense_get_indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Type of indicator to retrieve. Each type has a different response body. Possible values are: leak, phishing_site, credit_card, cve, social_media, sensitive_file_disclosure, malicious-file, malicious_ads. | Required |
| organization_code | Organization code(s), comma-separated. Example: brandefense,other. | Optional |
| time_range | Predefined time range for filtering indicators. Select 'Custom' to use created_at_range instead. Possible values are: Last 24 Hours, Last 7 Days, Last 30 Days, Last 90 Days, Last 6 Months, Last 1 Year, Custom. | Optional |
| created_at_range | Custom date range (comma-separated start,end). Example: 2020-10-10,2023-10-10. Only used when time_range is 'Custom' or not set. | Optional |
| incident_status | Filter by incident status(es), comma-separated. Possible values are: OPEN, IN_PROGRESS, CLOSED, RISK_ACCEPTED, REJECTED. | Optional |
| page | Page number within the paginated result set. | Optional |
| page_size | Number of results per page (default values: 10, 20, 50, 100). | Optional |
| limit | Maximum total number of results to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Brandefense.Indicator.id | Number | Indicator ID. |
| Brandefense.Indicator.created_at | Date | Indicator creation date. |
| Brandefense.Indicator.content_object | Unknown | Indicator content data \(varies by indicator type\). |
| Brandefense.Indicator.content_object.data | String | Primary indicator value \(URL, email, hash, etc.\). |
| Brandefense.Indicator.content_object.username | String | Username associated with the indicator \(leak type\). |
| Brandefense.Indicator.content_object.password | String | Password associated with the indicator \(leak type\). |
| Brandefense.Indicator.content_object.source_platform | String | Source platform of the indicator. |
| Brandefense.Indicator.content_object.threat_actor | String | Threat actor associated with the indicator. |
| Brandefense.Indicator.content_object.breached_date | Date | Date when the breach occurred. |
| Brandefense.Indicator.threats | Unknown | Associated threats. |
| Brandefense.Indicator.threats.title | String | Threat title. |
| Brandefense.Indicator.threats.incidents.code | String | Incident code associated with the threat. |
| Brandefense.Indicator.threats.incidents.organization.name | String | Organization name associated with the incident. |
