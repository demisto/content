InsightVM is a Vulnerability Management Tool which Scan your Network, Eliminate Vulnerabilities, Track and Communicate progress.
## Configure Rapid7 InsightVM Cloud in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Username | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Server URL (e.g., https://example.net) | True |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### insightvm-cloud-get-asset
***
Returns the assessment and details of an asset (specified by id). Only assets which the caller has access to can be returned.


#### Base Command

`insightvm-cloud-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The identifier of the asset to retrieve the details for. | Required | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-get-scan
***
Retrieves the scan with the specified identifier.


#### Base Command

`insightvm-cloud-get-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The identifier of the scan. | Required | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-get-scan-engines
***
Retrieves a page of scan engines.


#### Base Command

`insightvm-cloud-get-scan-engines`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The index of the page to retrieve. Default is 0. | Optional | 
| size | The number of records per page to retrieve. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-get-health-check
***
Returns an indicator of the health of the API.


#### Base Command

`insightvm-cloud-get-health-check`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### insightvm-cloud-search-assets
***
Returns the inventory, assessment, and summary details for a page of assets.


#### Base Command

`insightvm-cloud-search-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Search criteria for filtering assets returned. | Required | 
| page | The index of the page (zero-based) to retrieve. Default is 0. | Optional | 
| size | The number of records per page to retrieve. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-last-sites
***
Returns the details for sites


#### Base Command

`insightvm-cloud-last-sites`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The index of the page (zero-based) to retrieve. Default is 0. | Optional | 
| size |  The number of records per page to retrieve. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-search-vulnerabilities
***
Returns all vulnerabilities that can be assessed.


#### Base Command

`insightvm-cloud-search-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The index of the page to retrieve. Default is 0. | Optional | 
| size | The number of records per page to retrieve. Default is 10. | Optional | 
| query |  query to search vulnerabilities. | Required | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-start-scan
***
Starts a scan.


#### Base Command

`insightvm-cloud-start-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The identifiers of the assets to scan. | Required | 
| name | The name of the scan. | Optional | 


#### Context Output

There is no context output for this command.
### insightvm-cloud-stop-scan
***
Stops the scan with the specified identifier.


#### Base Command

`insightvm-cloud-stop-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The identifiers of the assets to stop scan. | Required | 


#### Context Output

There is no context output for this command.