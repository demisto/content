Fetches and manages incidents from iZOOlogic, enabling automated ingestion, incident creation, and advanced filtering for brand protection and threat management.

## Configure iZOOlogic in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The iZOOlogic API server URL. | True |
| API Key | The API key provided by iZOOlogic for authentication. | True |
| Secret Key | The secret key corresponding to the API key. | True |
| Trust any certificate (not secure) | Whether to trust any certificate \(not secure\). | False |
| Use system proxy settings | Whether to use the system proxy settings. | False |
| Fetch incidents | Whether to fetch incidents from iZOOlogic. | False |
| Fetch incident types | A comma-separated list of incident types to fetch from iZOOlogic. | True |
| Maximum incidents per fetch per type | The maximum number of incidents to fetch per type per fetch cycle. | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### izoologic-get-events

***
Gets events from iZOOlogic. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`izoologic-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to return per type. Default is 50. | Optional |
| start_time | The time to filter events detected at or after. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | The time to filter events detected at or before. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| event_type | The event types to filter by, as a comma-separated list. If not specified, the command uses the types configured in the integration parameters. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email. | Optional |
| should_push_events | The flag that indicates whether to push events to Cortex XSIAM. Pushing events is supported on Cortex XSIAM only. When set to false, or on non-Cortex XSIAM platforms, events are displayed without being pushed. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iZOOlogic.Incident.incidentID | String | The unique identifier of the incident. |
| iZOOlogic.Incident.incidentType | String | The type and subtype of the incident. |
| iZOOlogic.Incident.subIncidentType | String | The subtype of the incident. |
| iZOOlogic.Incident.detectionDate | String | The detection date of the incident as a Unix timestamp. |
| iZOOlogic.Incident.url | String | The URL associated with the incident. |
| iZOOlogic.Incident.status | String | The current status of the incident. |
| iZOOlogic.Incident.statusCode | Number | The numeric status code of the incident. |
| iZOOlogic.Incident.brand | String | The brand associated with the incident. |
| iZOOlogic.Incident.threatType | String | The threat level of the incident. |
| iZOOlogic.Incident.createdOn | String | The creation date of the incident as a Unix timestamp. |
| iZOOlogic.Incident.closedOn | String | The closing date of the incident as a Unix timestamp. |
| iZOOlogic.Incident.detectedBy | String | The entity that detected the incident. |

#### Command example

```!izoologic-get-events limit=3```

#### Human Readable Output

>### iZOOlogic Events
>
>|Incident ID|Incident Type|Sub Incident Type|Brand|Url|Status|Status Code|Threat Type|Detection Date|Created On|Closed On|Detected By|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| uVJxla1s1 | Brand Abuse - Fake Website | Fake Website | TVS Motor | https://tvsmotor.com.mt | Waiting | 17 | Substantial Threat | 1760941801 | 1769509374 |  | Reported By iZOOLogic |
>| 1JrJzZBip | Phishing |  | TVS Credit | https://tvs-credit.dev.veefin.in | Closed | 16 | High Threat | 1769792260 | 1769792260 | 1770180062 | Reported By iZOOLogic |
>| KIks8sE3U | Social Media - Facebook | Facebook | TVS King | https://www.facebook.com/ads/library/?id=917334661007536 | Waiting | 17 | Substantial Threat | 1769626014 | 1769626014 |  | Reported By iZOOLogic |

### izoologic-incident-create

***
Creates a new security incident in iZOOlogic.

#### Base Command

`izoologic-incident-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_url | The URL, email, or target of the security incident (max 1000 characters). | Required |
| incident_type | The type of incident. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email, executive. | Required |
| brand_code | The brand identifier associated with the incident. | Required |
| threat_type | The threat level. Possible values are: low threat, moderate threat, substantial threat, high threat, critical threat, redirect to whitelist. Default is moderate threat. | Optional |
| case_type | The preferred case type for processing. All new incidents are initially created as "Reported Incident" and may be reclassified during review. Possible values are: incident, brand abuse monitoring, domain monitoring, social media monitoring, mobile app monitoring, executive monitoring. Default is incident. | Optional |
| comment | The comments about the incident (max 2500 characters). | Optional |
| executive_name | The executive name. Required for executive-related incidents (max 2500 characters). | Optional |
| client_code | The client identifier for validation and access control. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iZOOlogic.Incident.reportedIncidentId | String | The unique identifier for the created incident case. |
| iZOOlogic.Incident.statusCode | Number | The numeric status code (1 = under review). |
| iZOOlogic.Incident.statusDescription | String | The human-readable status description. |
| iZOOlogic.Incident.caseType | Number | The case type code (9 = reported incident). |
| iZOOlogic.Incident.caseTypeDescription | String | The human-readable case type description. |

#### Command example

```!izoologic-incident-create incident_url="https://test-malicious-site.example.com" incident_type="phishing" brand_code="QnjggfvwlW"```

#### Human Readable Output

>### iZOOlogic - New Incident Created
>
>|Reported Incident Id|Status Code|Status Description|Case Type|Case Type Description|
>|---|---|---|---|---|
>| ycB2E7gPQ | 1 | Under Review | 9 | Reported Incident |

### izoologic-incident-fetch

***
Fetches incidents from iZOOlogic based on specified filters including date range, brand, incident type, and other criteria.

#### Base Command

`izoologic-incident-fetch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | The start date for filtering incidents. Supports ISO 8601 format or relative time expressions (e.g., "1 day ago", "2024-01-01T00:00:00Z"). Maximum date range is 31 days. Default is 1 day ago. | Optional |
| to_date | The end date for filtering incidents. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). Maximum date range is 31 days. Default is now. | Optional |
| incident_type | The type of incident to filter by. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email, executive. | Optional |
| threat_type | The threat level to filter by. Possible values are: low threat, moderate threat, substantial threat, high threat, critical threat, redirect to whitelist. | Optional |
| brand_code | The brand identifier to filter incidents by. | Optional |
| executive_name | The executive name for filtering executive-related incidents (max 100 characters). | Optional |
| client_ref_id | The client reference ID for specific incident lookup. | Optional |
| client_code | The client identifier for filtering incidents. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iZOOlogic.Incident.incidentID | String | The unique identifier of the incident. |
| iZOOlogic.Incident.incidentType | String | The type and subtype of the incident. |
| iZOOlogic.Incident.subIncidentType | String | The subtype of the incident. |
| iZOOlogic.Incident.detectionDate | String | The detection date of the incident as a Unix timestamp (e.g., 1704067200). |
| iZOOlogic.Incident.url | String | The URL associated with the incident. |
| iZOOlogic.Incident.status | String | The current status of the incident. |
| iZOOlogic.Incident.statusCode | Number | The numeric status code of the incident. |
| iZOOlogic.Incident.brand | String | The brand associated with the incident. |
| iZOOlogic.Incident.threatType | String | The threat level of the incident. |
| iZOOlogic.Incident.createdOn | String | The creation date of the incident as a Unix timestamp (e.g., 1704067200). |
| iZOOlogic.Incident.closedOn | String | The closing date of the incident as a Unix timestamp (e.g., 1704067200). |
| iZOOlogic.Incident.detectedBy | String | The entity that detected the incident. |

#### Command example

```!izoologic-incident-fetch from_date="1 day ago" incident_type="phishing"```

#### Human Readable Output

>### iZOOlogic Incidents
>
>|Incident ID|Incident Type|Brand|Url|Status|Status Code|Threat Type|Detection Date|Created On|Detected By|
>|---|---|---|---|---|---|---|---|---|---|
>| abc123 | Phishing | ExampleBrand | https://example.com | Active | 1 | High Threat | 1700000000 | 1700000200 | Reported By iZOOLogic |
