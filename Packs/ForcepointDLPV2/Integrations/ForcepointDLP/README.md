Forcepoint DLP REST integration (auth + incidents) aligned to Forcepoint REST API.
Features:
  • Auto token refresh (15m access TTL)
  • Incremental fetch with client-side dedup (watermark + seen event_ids)
  • Update incidents using Forcepoint-compliant payloads (type/action_type/value + event_ids or incident_id+partition_index)
  • Admin helpers to view/reset fetch state

## Configure Forcepoint DLP in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://&lt;DLP_Manager_IP&gt;:&lt;port&gt;) | True |
| User Name | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Enable incident fetching | False |
| First fetch window (e.g., 24h, 7d, 60m) | False |
| Fetch status filter (default IN_PROGRESS) | False |
| Fetch from_date (DD/MM/YYYY HH:MM:SS) | False |
| Fetch to_date (DD/MM/YYYY HH:MM:SS) | False |
| Maximum incidents per fetch | False |
| Ignore static from/to dates; use incremental watermark (recommended) | False |
| Watermark field name (default INSERT_DATE) | False |
| Dedup key field name (default eventId) | False |
| Dedup cache size | False |
| Incident type | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### forcepoint-dlp-get-incidents

***

#### Base Command

`forcepoint-dlp-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of incidents to retrieve (default INCIDENTS). | Optional | 
| from_date | From date (DD/MM/YYYY HH:MM:SS). | Optional | 
| to_date | To date (DD/MM/YYYY HH:MM:SS). | Optional | 
| status | Status filter (e.g., NEW, IN_PROGRESS, CLOSED). | Optional | 
| severity | Severity filter (LOW, MEDIUM, HIGH). | Optional | 
| action | Action filter. | Optional | 
| policies | Policy names filter. | Optional | 
| sort_by | Sort by field (e.g., INSERT_DATE). | Optional | 

#### Context Output

There is no context output for this command.
### forcepoint-dlp-update-incident

***

#### Base Command

`forcepoint-dlp-update-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | Comma-separated list or array of event IDs (preferred). | Optional | 
| incident_id | Incident ID (use with partition_index if event_ids not provided). | Optional | 
| partition_index | Partition index paired with incident_id. | Optional | 
| status | Set status (NEW, IN_PROGRESS, CLOSED). | Optional | 
| severity | Set severity (LOW, MEDIUM, HIGH). | Optional | 
| tag | Add a tag (string). | Optional | 
| action_type | Explicit action type (STATUS\|SEVERITY\|TAG). | Optional | 
| value | Explicit value for action_type. | Optional | 
| comments | Optional comment/remark (omit if server rejects). | Optional | 

#### Context Output

There is no context output for this command.
### forcepoint-dlp-reset-state

***
Reset fetch watermark and seen IDs (use with caution)

#### Base Command

`forcepoint-dlp-reset-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### forcepoint-dlp-show-state

***
Show current fetch watermark and seen IDs

#### Base Command

`forcepoint-dlp-show-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
