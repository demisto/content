Use the Panorays integration to retrieve and monitor internal security findings for your organization.

This integration was integrated and tested with the Panorays Findings API.

## Configure Panorays Findings API in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Panorays PAPI base URL | True |
| API Key | True |
| Maximum number of incidents to fetch per run | False |
| First fetch timestamp (e.g., 7 days) | False |
| Fetch incidents | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### panorays-finding-list
***
Lists the internal company findings as detected by Panorays.

#### Base Command

`panorays-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of findings to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Default is 1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorays.Finding.id | String | The unique ID of the finding. |
| Panorays.Finding.asset_name | String | The name of the affected asset. |
| Panorays.Finding.severity | String | The severity level (e.g., LOW, MEDIUM, HIGH). |
| Panorays.Finding.status | String | The current status of the finding. |

## Command Examples
### panorays-finding-list
Lists the company findings as detected by Panorays.

**Command**
`!panorays-finding-list limit=1`

**Context Output**
| Path | Type | Description |
| --- | --- | --- |
| Panorays.Finding.id | String | The unique ID of the finding. |
| Panorays.Finding.asset_name | String | The name of the affected asset. |
| Panorays.Finding.severity | String | The severity level (e.g., LOW, MEDIUM, HIGH). |
| Panorays.Finding.status | String | The current status of the finding. |

**Human Readable Output**
### Panorays Findings (Page 1)
| Finding ID | Category | Affected Asset | Risk Level | State |
| --- | --- | --- | --- | --- |
| 694b44b52752390e1447a56f | Human | shaytest | LOW | OPEN |