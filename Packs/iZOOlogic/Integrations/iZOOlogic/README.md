Fetches threat incidents from iZOOlogic for automated ingestion into Cortex.

## Configure iZOOlogic in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The iZOOlogic API server URL. | True |
| API Key | The API key provided by iZOOlogic for authentication. | True |
| Secret Key | The secret key corresponding to the API key. | True |
| Trust any certificate (not secure) | Whether to trust any certificate \(not secure\). | False |
| Use system proxy settings | Whether to use the system proxy settings. | False |
| Fetch incidents | Whether to fetch incidents from iZOOlogic. | False |
| First fetch timestamp | The time range for the initial fetch \(e.g., "1 day", "3 days"\). Subsequent fetches use the last run timestamp. | False |
| Fetch incident types | A comma-separated list of incident types to fetch from iZOOlogic. | True |
| Maximum Incidents Per Fetch Per Type | The maximum number of incidents to fetch per type per fetch cycle. | True |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### izoologic-get-incidents

***
Gets incidents from iZOOlogic. Use this command for development and debugging only, as it may exceed API rate limits.

#### Base Command

`izoologic-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of incidents to return per type. Default is 50. | Optional |
| start_time | The time to filter incidents detected at or after. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | The time to filter incidents detected at or before. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| incident_type | Filter by incident type(s). If not specified, uses the types configured in the integration parameters. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email. | Optional |

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

```!izoologic-get-incidents limit=3```

#### Human Readable Output

>### iZOOlogic Incidents
>
>|incidentID|incidentType|subIncidentType|brand|url|status|statusCode|threatType|detectionDate|createdOn|closedOn|detectedBy|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| uVJxla1s1 | Brand Abuse - Fake Website | Fake Website | TVS Motor | https://tvsmotor.com.mt | Waiting | 17 | Substantial Threat | 1760941801 | 1769509374 |  | Reported By iZOOLogic |
>| 1JrJzZBip | Phishing |  | TVS Credit | https://tvs-credit.dev.veefin.in | Closed | 16 | High Threat | 1769792260 | 1769792260 | 1770180062 | Reported By iZOOLogic |
>| KIks8sE3U | Social Media - Facebook | Facebook | TVS King | https://www.facebook.com/ads/library/?id=917334661007536 | Waiting | 17 | Substantial Threat | 1769626014 | 1769626014 |  | Reported By iZOOLogic |

### izoolabs-incident-create

***
Creates a new security incident in iZOOlogic.

#### Base Command

`izoolabs-incident-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_url | URL, email, or target of the security incident (max 1000 characters). | Required |
| incident_type | Type of incident. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email, executive. | Required |
| brand_code | Brand identifier associated with the incident. | Required |
| threat_type | Threat level. Defaults to moderate threat if not specified. Possible values are: low threat, critical threat, redirect to whitelist. | Optional |
| case_type | Desired case type for processing. Defaults to incident if not specified. Possible values are: incident, brand abuse monitoring, domain monitoring, social media monitoring, mobile app monitoring, executive monitoring. | Optional |
| comment | Comments about the incident (max 2500 characters). | Optional |
| executive_name | Executive name. Required for executive-related incidents (max 2500 characters). | Optional |
| client_code | Client identifier for validation and access control. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iZOOlabs.Incident.reportedincidentid | String | Unique identifier for the created incident case. |
| iZOOlabs.Incident.statuscode | Number | Numeric status code \(1 = under review\). |
| iZOOlabs.Incident.statusdescription | String | Human-readable status description. |
| iZOOlabs.Incident.casetype | Number | Case type code \(6 = incident\). |
| iZOOlabs.Incident.casetypedescription | String | Human-readable case type description. |
| iZOOlabs.Incident.success | Boolean | Whether the incident was successfully created. |

#### Command example

```!izoolabs-incident-create incident_url="https://malicious-site.example.com" incident_type="phishing" brand_code="BRAND001"```

#### Human Readable Output

>### iZOOlogic - New Incident Created
>
>|reportedincidentid|statuscode|statusdescription|casetype|casetypedescription|success|
>|---|---|---|---|---|---|
>| RPT-12345 | 1 | Under Review | 6 | Incident | true |

### izoolabs-incident-fetch

***
Fetches incidents from iZOOlogic based on specified filters including date range, brand, incident type, and other criteria.

#### Base Command

`izoolabs-incident-fetch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Start date for filtering incidents. Supports ISO 8601 format or relative time expressions (e.g., "1 day ago", "2024-01-01T00:00:00Z"). Maximum date range is 31 days. Default is 1 day ago. | Optional |
| to_date | End date for filtering incidents. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). Maximum date range is 31 days. Default is now. | Optional |
| incident_type | Type of incident to filter by. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email, executive. | Optional |
| threat_type | Threat level to filter by. Possible values are: low threat, moderate threat, substantial threat, high threat, critical threat, redirect to whitelist. | Optional |
| brand_code | Brand identifier to filter incidents by. | Optional |
| executive_name | Executive name for filtering executive-related incidents (max 100 characters). | Optional |
| client_ref_id | Client reference ID for specific incident lookup. | Optional |
| client_code | Client identifier for filtering incidents. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| iZOOlabs.Incident.incidentID | String | The unique identifier of the incident. |
| iZOOlabs.Incident.incidentType | String | The type and subtype of the incident. |
| iZOOlabs.Incident.subIncidentType | String | The subtype of the incident. |
| iZOOlabs.Incident.detectionDate | String | The detection date of the incident as a Unix timestamp. |
| iZOOlabs.Incident.url | String | The URL associated with the incident. |
| iZOOlabs.Incident.status | String | The current status of the incident. |
| iZOOlabs.Incident.statusCode | Number | The numeric status code of the incident. |
| iZOOlabs.Incident.brand | String | The brand associated with the incident. |
| iZOOlabs.Incident.threatType | String | The threat level of the incident. |
| iZOOlabs.Incident.createdOn | String | The creation date of the incident as a Unix timestamp. |
| iZOOlabs.Incident.closedOn | String | The closing date of the incident as a Unix timestamp. |
| iZOOlabs.Incident.detectedBy | String | The entity that detected the incident. |

#### Command example

```!izoolabs-incident-fetch from_date="1 day ago" incident_type="phishing"```

#### Human Readable Output

>### iZOOlogic Incidents
>
>|incidentID|incidentType|brand|url|status|statusCode|threatType|detectionDate|createdOn|detectedBy|
>|---|---|---|---|---|---|---|---|---|---|
>| abc123 | Phishing | ExampleBrand | https://example.com | Active | 1 | High Threat | 1700000000 | 1700000200 | Reported By iZOOLogic |
