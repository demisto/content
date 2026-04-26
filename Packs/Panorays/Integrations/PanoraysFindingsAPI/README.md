Retrieve and monitor internal security findings for your organization from the Panorays platform to streamline self-assessment posture and automate internal incident response within Cortex XSOAR.
This integration was integrated and tested with version v2 of PanoraysFindingsAPI.

## Configure Panorays Findings API in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Panorays PAPI base URL | True |
| apikey | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Maximum number of incidents to fetch per run | False |
| First fetch timestamp (e.g., 7 days) | False |
| Incident type | False |
| Fetch incidents | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### panorays-finding-list

***
Lists the company findings as detected by Panorays.

#### Base Command

`panorays-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of findings to return. Default is 50. | Optional | 
| page | The page number of results to retrieve. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.
