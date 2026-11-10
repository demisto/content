## KELA Brand Control

Brand Control detects brand impersonation across the open web, social media and app ecosystems: phishing websites, look-alike domains, fake social media profiles, fake shops and more.

This integration fetches brand impersonation incidents from KELA Brand Control into Cortex.
This integration was integrated and tested with version 1.0 of the KELA Brand Control API.

## Configure KELA BrandControl in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for KELA BrandControl.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the KELA Brand Control API. | True |
| API Token | API token generated in the KELA platform (system menu). It is sent as the apiToken query parameter and is never logged. | True |
| Use system proxy settings | Route requests to the KELA Brand Control API through the system proxy configured on the Cortex server or engine. | False |
| Trust any certificate (not secure) | Skip TLS certificate validation when connecting to the KELA Brand Control API. | False |
| Workspace ID(s) | Workspace ID to connect to. Several workspaces can be given separated by commas; each one is fetched with its own state. Only workspaces owned by, or shared with, your group are accessible. | True |
| Fetch incidents |  | False |
| Incident type | The Cortex incident type to assign to incidents created by this integration. | False |
| Incidents Fetch Interval | How often, in minutes, Cortex runs a fetch cycle for this instance. | False |
| First fetch time | How far back to fetch the first time (e.g. "3 days", "12 hours", "2026-10-01T00:00:00Z"). Applied to the incident date. | False |
| Maximum number of incidents per fetch (per workspace) | Between 1 and 200. | False |
| Fetch only these severities | Optional. Leave empty to fetch every severity. Filtered-out incidents are skipped but the fetch position still advances past them. | False |

4. Click **Test** to validate the URL, token and workspace access.

Notes:

- Authentication uses the `apiToken` query parameter. The token is never written to logs or to command outputs.
- The API allows **1 request per second** (HTTP 429 above that). The integration spaces requests and retries on 429.
- Workspaces: you can only access workspaces owned by, or shared with, your group.

## Fetch incidents

The integration fetches Brand Control incidents by `incident_date` (new detections), excluding deleted and archived ones. For every workspace it keeps its own *watermark* (the latest incident date fetched) plus the IDs of the incidents sharing that exact timestamp, so an incident is never created twice. See the technical document for the design.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### kela-brandcontrol-incident-list

***
Retrieves the Brand Control incidents of a workspace, with filtering, sorting and pagination. Deleted and archived incidents are excluded by default.

#### Base Command

`kela-brandcontrol-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | Workspace ID to query. Optional when exactly one workspace is configured on the instance. | Optional |
| search_term | Free text search term. | Optional |
| types | A comma-separated list of incident types to return. Possible values are: phishing_website, look_alike_domain, phishing_email, fake_social_media_profile, fake_shop, malicious_application, brand_infringement. | Optional |
| statuses | A comma-separated list of incident statuses to return. Possible values are: new, in_review, resolved, requested_takedown, false_positive, irrelevant, whitelisted. | Optional |
| severities | A comma-separated list of severities to return. Possible values are: low, medium, high, critical. | Optional |
| is_deleted | When true, returns only deleted incidents. When false, returns only incidents that are not deleted. Possible values are: true, false. Default is false. | Optional |
| is_archived | When true, returns only archived incidents. When false, returns only incidents that are not archived. Possible values are: true, false. Default is false. | Optional |
| new_updates_only | When true, returns only incidents with updates available since they were last visited in the UI. Possible values are: true, false. Default is false. | Optional |
| time_range_field | Date field the start/end dates apply to. Possible values are: incident_date, incident_update_date. Default is incident_date. | Optional |
| start_date | Return incidents on or after this date. Accepts ISO dates, relative dates (e.g. "3 days") or a 13 digit epoch in milliseconds. | Optional |
| end_date | Return incidents up to this date. Same formats as start_date. | Optional |
| sort_by | Field to sort by. If omitted, the API sorts by lastUpdated descending. Possible values are: incidentDate, severity, status, lastUpdated. | Optional |
| sort_order | Sort order. Used together with sort_by. Possible values are: asc, desc. | Optional |
| limit | Number of incidents to return (1-1000). Ignored when page or page_size is given. Default is 50. | Optional |
| page | Page number, starting at 1. Used together with page_size. | Optional |
| page_size | Number of incidents per page (1-1000). Used together with page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KELA.BrandControl.Incident.incidentId | String | Unique identifier of the incident. |
| KELA.BrandControl.Incident.incidentDate | Number | The timestamp in Unix milliseconds when the incident was first detected (e.g., 1700000000000). |
| KELA.BrandControl.Incident.incidentUpdateDate | Number | The timestamp in Unix milliseconds of the last update to the incident (e.g., 1700000000000). |
| KELA.BrandControl.Incident.type | String | Type of detection, as classified by KELA. |
| KELA.BrandControl.Incident.severity | String | Aggregated priority for treatment (low, medium, high, critical). |
| KELA.BrandControl.Incident.status | String | Current status of the incident. |
| KELA.BrandControl.Incident.title | String | Short descriptive title of the incident. |
| KELA.BrandControl.Incident.description | String | Detailed explanation of the incident. |
| KELA.BrandControl.Incident.isTakedownRequested | Boolean | Whether a takedown has been requested for the incident. |
| KELA.BrandControl.Incident.takedowns.takedownId | String | Takedown request ID. |
| KELA.BrandControl.Incident.takedowns.takedownRequestDate | Number | The timestamp in Unix milliseconds of the takedown request (e.g., 1700000000000). |
| KELA.BrandControl.Incident.takedowns.requestedBy | String | KELA username that submitted the takedown request. |
| KELA.BrandControl.Incident.takedowns.status | String | Current status of the takedown request. |
| KELA.BrandControl.Incident.takedowns.statusUpdateDate | Number | The timestamp in Unix milliseconds of the last takedown status update (e.g., 1700000000000). |
| KELA.BrandControl.Incident.detectedEntity | Unknown | Entity at the core of the incident. The shape varies by incident type. |
| KELA.BrandControl.Incident.detectedEntity.urls | Unknown | URLs linked to the detected entity. |
| KELA.BrandControl.Incident.analysis | Unknown | Assessment of the detected entity. The shape varies by incident type. |
| KELA.BrandControl.Incident.analysis.impersonatedAsset | String | The legitimate asset being impersonated. |
| KELA.BrandControl.Incident.analysis.similarityScore | Number | Similarity score between the detected entity and the impersonated asset (0-1). |
| KELA.BrandControl.Incident.analysis.domainStatus | String | Status of the domain (e.g. active, inactive). |
| KELA.BrandControl.Incident.analysis.firstSeen | Number | The timestamp in Unix milliseconds when the entity was first detected (e.g., 1700000000000). |
| KELA.BrandControl.Incident.analysis.lastSeen | Number | The timestamp in Unix milliseconds when the entity was last detected (e.g., 1700000000000). |
| KELA.BrandControl.Incident.screenshots.url | String | Temporary signed download link of the screenshot. |
| KELA.BrandControl.Incident.screenshots.screenshotDate | Number | The timestamp in Unix milliseconds of the screenshot (e.g., 1700000000000). |
| KELA.BrandControl.Incident.screenshots.fileName | String | Screenshot file name. |
| KELA.BrandControl.Incident.reasons | Unknown | Assets that triggered the detection. |
| KELA.BrandControl.Incident.indicators.hasScreenshots | Boolean | Whether the incident has screenshots. |
| KELA.BrandControl.Incident.indicators.hasNotes | Boolean | Whether the incident has notes. |
| KELA.BrandControl.Incident.indicators.hasTags | Boolean | Whether the incident has tags. |
| KELA.BrandControl.Incident.indicators.hasRelatedEntities | Boolean | Whether the incident has related entities. |
| KELA.BrandControl.Incident.isDeleted | Boolean | Whether the incident is deleted. |
| KELA.BrandControl.Incident.isArchived | Boolean | Whether the incident is archived. |
| KELA.BrandControl.Incident.lastVisited | Number | The timestamp in Unix milliseconds of the last time the incident was visited in the UI (e.g., 1700000000000). |

#### Command example

```!kela-brandcontrol-incident-list workspace_id=<WORKSPACE_ID> types=look_alike_domain,phishing_website severities=high,critical start_date="7 days" sort_by=incidentDate sort_order=desc limit=10```

#### Context Example

```json
{
    "KELA": {
        "BrandControl": {
            "Incident": {
                "incidentId": "<incident-id>",
                "incidentDate": 1759500067000,
                "incidentUpdateDate": 1759500067000,
                "type": "look_alike_domain",
                "severity": "high",
                "status": "new",
                "title": "<title>",
                "description": "<description>",
                "isTakedownRequested": false,
                "detectedEntity": {
                    "urls": [
                        "http://examp1e.com"
                    ]
                },
                "analysis": {
                    "impersonatedAsset": "example.com",
                    "similarityScore": 0.92,
                    "domainStatus": "active"
                },
                "isDeleted": false,
                "isArchived": false
            }
        }
    }
}
```

#### Human Readable Output

>### KELA Brand Control incidents (showing 1 of 1 matching, 42 total in the workspace)
>
>|Incident ID|Incident Date|Type|Severity|Status|Title|Impersonated Asset|Detected URLs|
>|---|---|---|---|---|---|---|---|
>| `<incident-id>` | 2026-10-03T14:21:07.000Z | look_alike_domain | high | new | `<title>` | example.com | <http://examp1e.com> |

*(Illustrative output: values are placeholders, not real data. It has not been run against the live API yet.)*
