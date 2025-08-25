Fetches dark web credentials, threats, assets, and other threat intelligence from the SpiderSilk API.
## Configure SpiderSilk in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | Base URL of the SpiderSilk API. | True |
| API Key | Your SpiderSilk API key \(will be used as a Bearer token\). | True |
| Hours Since Reports Created (for reported_since parameter) | Fetch credentials reported in the last X hours \(e.g., 0.5 to 168\). Used for manual fetch and as default for first fetch. | True |
| First Fetch Lookback (Hours) | When fetching incidents for the first time, look back this many hours \(e.g., 0.5 to 168\). Uses 'Hours Since Reports Created' if empty. | False |
| Maximum Incidents to Fetch per Run | The maximum number of credential incidents to fetch in a single fetch-incidents run. | False |
| Trust any certificate (not secure) | Skip certificate validation. | False |
| Use system proxy settings | Use XSOAR system proxy settings. | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### test-module

***
Tests API connectivity and authentication using the /stats endpoint.

#### Base Command

`test-module`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### fetch-incidents

***
Fetches dark web credential exposures as incidents from the /darkweb_credentials endpoint.

#### Base Command

`fetch-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### spidersilk-get-darkweb-credentials

***
Retrieve the information of the Darkweb credentials associated to the Company profile.

#### Base Command

`spidersilk-get-darkweb-credentials`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reported_since_hours | Number of hours since reports have been created (e.g., 0.5 to 168). | Optional | 
| limit | Maximum number of credentials to return per page. Default is 50. | Optional | 
| page | Page number for pagination. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.
### spidersilk-get-darkweb-reports

***
Retrieve the information of the Darkweb reports associated to the Company profile.

#### Base Command

`spidersilk-get-darkweb-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | No description provided. Default is 50. | Optional | 
| page | No description provided. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.
### spidersilk-get-darkweb-report-details

***
Retrieve the information of the darkweb by its uuid.

#### Base Command

`spidersilk-get-darkweb-report-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the darkweb report. | Required | 

#### Context Output

There is no context output for this command.
### spidersilk-update-darkweb-report-status

***
Change status of the darkweb.

#### Base Command

`spidersilk-update-darkweb-report-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the darkweb report to update. | Required | 
| status_id | The integer ID of the new status. | Required | 
| comment | An optional comment for the status change. | Optional | 

#### Context Output

There is no context output for this command.
### spidersilk-get-threats

***
Retrieve the information of the threats associated to the Company profile.

#### Base Command

`spidersilk-get-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | No description provided. Default is 50. | Optional | 
| page | No description provided. Default is 1. | Optional | 
| updated_since | Number of hours since threats were updated. | Optional | 

#### Context Output

There is no context output for this command.
### spidersilk-get-threat-details

***
Retrieve the information of the threat by its uuid.

#### Base Command

`spidersilk-get-threat-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the threat. | Required | 

#### Context Output

There is no context output for this command.
### spidersilk-update-threat-status

***
Change status of the threat.

#### Base Command

`spidersilk-update-threat-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the threat to update. | Required | 
| status_id | The integer ID of the new status. | Required | 
| comment | An optional comment for the status change. | Optional | 

#### Context Output

There is no context output for this command.
### spidersilk-get-assets

***
Retrieve the information of the assets associated to the Company profile.

#### Base Command

`spidersilk-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | No description provided. Default is 50. | Optional | 
| page | No description provided. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.
### spidersilk-get-asset-details

***
Retrieve the information of the asset by its Id.

#### Base Command

`spidersilk-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the asset (e.g., 10b95cb930bf4bc79bfdf21173e7781f). | Required | 

#### Context Output

There is no context output for this command.
