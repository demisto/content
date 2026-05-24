Fetches threat incidents from iZOOlogic for automated ingestion into Cortex.

## Configure iZOOlogic in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The iZOOlogic API server URL. | True |
| API Key | The API key provided by iZOOlogic for authentication. | True |
| Secret Key | The secret key corresponding to the API key. | True |
| Trust any certificate (not secure) | When selected, certificates are not checked. | False |
| Use system proxy settings | When selected, uses the system proxy settings. | False |
| Fetch incidents | Whether to fetch incidents from iZOOlogic. | False |
| Fetch Incident types | Select which incident types to fetch from iZOOlogic. By default, all types are selected. | True |
| The maximum number of incidents per type per fetch | Maximum number of incidents to fetch per type per fetch cycle \(default: 5000\). | True |

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
| start_time | Filter incidents detected at or after this time. Supports ISO 8601 format or relative time expressions (e.g., "3 days ago", "2024-01-01T00:00:00Z"). | Optional |
| end_time | Filter incidents detected at or before this time. Supports ISO 8601 format or relative time expressions (e.g., "now", "2024-01-01T00:00:00Z"). | Optional |
| incident_type | Filter by incident type(s). If not specified, the command uses the types configured in the integration parameters. Possible values are: brand abuse, phishing, malware, pharming, smishing, vishing, mobile apps, social media, other, email. | Optional |

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
