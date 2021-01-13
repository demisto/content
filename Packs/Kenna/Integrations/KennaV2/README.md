Use the Kenna v2 integration to search and update vulnerabilities, schedule a run connector, and manage tags and attributes.
This integration was integrated and tested with version xx of Kennav2_Custom.
## Configure Kennav2_Custom on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Kennav2_Custom.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(e.g.  https://api.kennasecurity.com\) | False |
    | key | Kenna API key | True |
    | proxy | Use system proxy settings | False |
    | insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### kenna-search-vulnerabilities
***
Searches for vulnerabilities in Kenna.


#### Base Command

`kenna-search-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| top-priority | Whether to return vulnerabilities that Kenna deems a top priority to fix. Can be "true" or "false". Possible values are: true, false. | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| status | The status of the vulnerability. Can be "open", "closed", "risk_accepted", or "false_positive". Possible values are: open, closed, risk_accepted, false_positive. | Optional | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. Default is 500. | Optional | 
| to_context | Whether to flush to context. Can be "True" or "False". The default value is "True". Possible values are: True, False. Default is True. | Optional | 
| id | The vulnerability ID for which to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.Vulnerabilities.AssetID | Number | The asset ID related to the vulnerability. | 
| Kenna.Vulnerabilities.Connectors.DefinitionName | String | The connector definition name related to the vulnerability. | 
| Kenna.Vulnerabilities.Connectors.ID | Number | The connector ID related to the vulnerability. | 
| Kenna.Vulnerabilities.Connectors.Name | String | The connector name related to the vulnerability. | 
| Kenna.Vulnerabilities.Connectors.Vendor | String | The connector vendor related to the vulnerability. | 
| Kenna.Vulnerabilities.CveID | String | The CVE ID related to the vulnerability. | 
| Kenna.Vulnerabilities.FixID | String | The fix ID related to the vulnerability. | 
| Kenna.Vulnerabilities.Patch | Boolean | Whether there is a patch related to the vulnerability. | 
| Kenna.Vulnerabilities.ScannerVulnerabilities.ExternalID | String | The vulnerability scanner external ID. | 
| Kenna.Vulnerabilities.ScannerVulnerabilities.Open | Boolean | Whether the vulnerability scanner is open. | 
| Kenna.Vulnerabilities.ScannerVulnerabilities.Port | Number | The vulnerability scanner port. | 
| Kenna.Vulnerabilities.Score | Number | The vulnerability score. | 
| Kenna.Vulnerabilities.ServiceTicket.DueDate | Date | The service ticket due date. | 
| Kenna.Vulnerabilities.ServiceTicket.ExternalIdentifier | String | The service ticket external identifier. | 
| Kenna.Vulnerabilities.ServiceTicket.Status | String | The service ticket status. | 
| Kenna.Vulnerabilities.ServiceTicket.TicketType | String | The service ticket type. | 
| Kenna.Vulnerabilities.Severity | Number | The vulnerability severity. | 
| Kenna.Vulnerabilities.Status | String | The vulnerability status. | 
| Kenna.Vulnerabilities.Threat | Number | The vulnerability threat. | 
| Kenna.Vulnerabilities.TopPriority | Number | The vulnerability priority. | 
| Kenna.Vulnerabilities.ID | Number | The vulnerability ID. | 


#### Command Example
``` ```

#### Human Readable Output



### kenna-run-connector
***
Executes a run of the specified connector. If file based, it will use the most recently uploaded data file.


#### Base Command

`kenna-run-connector`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The connector ID to run. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### kenna-search-fixes
***
Filters fixes by a given set of vulnerability and asset parameters and returns the filtered fixes.


#### Base Command

`kenna-search-fixes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability ID for which to search. | Optional | 
| top-priority | Whether to return vulnerabilities that Kenna deems a top priority to fix. Can be "true" or "false". Possible values are: true, false. | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| status | The status of the vulnerability. Can be "open", "closed", "risk_accepted", or "false_positive". Possible values are: open, closed, risk_accepted, false_positive. | Optional | 
| vulnerabilities | vulnerabilities for search. | Optional | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. Default is 500. | Optional | 
| to_context | Whether to flush to context. Can be "True" or "False". The default value is "True". Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.Fixes.ID | Number | The fix ID. | 
| Kenna.Fixes.Title | String | The fix title. | 
| Kenna.Fixes.Assets.ID | Number | The asset ID related to the current fix. | 
| Kenna.Fixes.Assets.Locator | String | The asset locator related to the current fix. | 
| Kenna.Fixes.Assets.PrimaryLocator | String | The asset primary locator related to the current fix. | 
| Kenna.Fixes.Assets.DisplayLocator | String | The asset display locator related to the current fix. | 
| Kenna.Fixes.Vulnerabilities.ID | Number | The vulnerability ID related to the current fix. | 
| Kenna.Fixes.Vulnerabilities.ServiceTicketStatus | String | The vulnerability service ticket status related to the current fix. | 
| Kenna.Fixes.Vulnerabilities.ScannerIDs | Number | The vulnerability scanner IDs related to the current fix. | 
| Kenna.Fixes.CveID | String | The CVE-ID list related to the current fix. | 
| Kenna.Fixes.LastUpdatedAt | String | The timestamp when the current fix was last updated. | 
| Kenna.Fixes.Category | String | The category of fix. | 
| Kenna.Fixes.VulnerabilityCount | Number | The vulnerability count of the fix. | 
| Kenna.Fixes.MaxScore | Number | The maximum score of the fix. | 


#### Command Example
``` ```

#### Human Readable Output



### kenna-update-asset
***
Updates the attributes of a single asset.


#### Base Command

`kenna-update-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the asset to update. | Required | 
| notes | Notes about the asset. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### kenna-update-vulnerability
***
Updates the attributes of a single vulnerability.


#### Base Command

`kenna-update-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the vulnerability to update. | Required | 
| status | The status of the vulnerability. Can be "open", "closed", "risk_accepted", or "false_positive". Possible values are: open, closed, risk_accepted, false_positive. | Optional | 
| notes | Notes about the vulnerability. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### kenna-get-connectors
***
Returns all connectors.


#### Base Command

`kenna-get-connectors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.ConnectorsList.ID | Number | The connector ID. | 
| Kenna.ConnectorsList.Name | String | The connector name. | 
| Kenna.ConnectorsList.Running | Boolean | The running connector. | 
| Kenna.ConnectorsList.Host | String | The connector host. | 


#### Command Example
``` ```

#### Human Readable Output



### kenna-search-assets
***
Searches for assets.


#### Base Command

`kenna-search-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID to search for. | Optional | 
| hostname | The hostname of the asset to search for. | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| tags | The tags by which to search. | Optional | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. Default is 500. | Optional | 
| to_context | Whether to print output to context. Can be "True" or "False". The default value is "True". Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.Assets.ID | Number | The asset ID. | 
| Kenna.Assets.Hostname | String | The hostname of the asset. | 
| Kenna.Assets.IpAddress | String | The asset IP address. | 
| Kenna.Assets.Score | Number | The asset risk score. | 
| Kenna.Assets.VulnerabilitiesCount | Number | The number of vulnerabilities associated with the asset. | 
| Kenna.Assets.OperatingSystem | String | The asset operating system. | 
| Kenna.Assets.Tags | String | A list of the asset's tags. | 
| Kenna.Assets.Fqdn | String | The asset FQDN. | 
| Kenna.Assets.Status | String | The asset status. | 
| Kenna.Assets.Owner | String | The asset owner. | 
| Kenna.Assets.Priority | Number | The asset priority. | 
| Kenna.Assets.Notes | String | Notes of current asset. | 
| Kenna.Assets.OperatingSystem | String | Operating system of asset | 


#### Command Example
``` ```

#### Human Readable Output



### kenna-get-asset-vulnerabilities
***
Gets vulnerabilities of the specified asset.


#### Base Command

`kenna-get-asset-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID for which to get vulnerabilities. | Required | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. Default is 500. | Optional | 
| to_context | Whether to print output to context. Can be "True" or "False". The default value is "True". Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.VulnerabilitiesOfAsset.AssetID | Number | The ID of the asset that this vulnerability is associated with. | 
| Kenna.VulnerabilitiesOfAsset.CveID | String | The CVE ID of the vulnerability associated with the asset.  | 
| Kenna.VulnerabilitiesOfAsset.ID | Number | The ID of the vulnerability associated withe the asset  | 
| Kenna.VulnerabilitiesOfAsset.Patch | Boolean | Whether there is a patch for the vulnerability associated with the asset.  | 
| Kenna.VulnerabilitiesOfAsset.Status | String | The status of the vulnerability associated with the asset.  | 
| Kenna.VulnerabilitiesOfAsset.TopPriority | Boolean | Whether the vulnerability associated with the asset is a top priority.  | 
| Kenna.VulnerabilitiesOfAsset.Score | Number | The score of the vulnerability associated with the asset.  | 


#### Command Example
``` ```

#### Human Readable Output



### kenna-add-tag
***
Adds a tag to the specified asset.


#### Base Command

`kenna-add-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | A comma-separated list of tags to add to the asset. | Required | 
| id | The asset ID to which to add the tag. . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### kenna-delete-tag
***
Deletes tags from the specified asset.


#### Base Command

`kenna-delete-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID from which to delete the tag. Possible values are: . | Required | 
| tag | The tag to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### kenna-get-connector-runs
***
Returns JSON data on all the runs of a given connector


#### Base Command

`kenna-get-connector-runs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_id | Unique numerical ID of the connector. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.ConnectorRunsList.id | unknown | Connector Run ID | 
| Kenna.ConnectorRunsList.start_time | unknown | Connector Run Start Time | 
| Kenna.ConnectorRunsList.end_time | unknown | Connector Run End Time | 
| Kenna.ConnectorRunsList.success | boolean | Boolean value showing connector success | 
| Kenna.ConnectorRunsList.total_payload_count | unknown | Total connector payloads | 
| Kenna.ConnectorRunsList.processed_payload_count | unknown | total payloads processed by connector | 
| Kenna.ConnectorRunsList.failed_payload_count | unknown | Total failed payloads | 
| Kenna.ConnectorRunsList.processed_assets_count | unknown | Count of processed assets | 
| Kenna.ConnectorRunsList.assets_with_tags_reset_count | unknown | Count of assets with reset tags | 
| Kenna.ConnectorRunsList.processed_scanner_vuln_count | unknown | Count of processed scanners with vulnerabilities | 
| Kenna.ConnectorRunsList.updated_scanner_vlun_count | unknown | Count of updated scanners with vulnerabilities | 
| Kenna.ConnectorRunsList.created_scanner_vuln_count | unknown | Count of created scanners with vulnerabilities  | 
| Kenna.ConnectorRunsList.closed_scanner_vuln_count | unknown | Count of closed scanners with vulnerabilities  | 
| Kenna.ConnectorRunsList.autoclosed_scanner_vuln_count | unknown | Count of auto-closed scanners with vulnerabilities | 
| Kenna.ConnectorRunsList.reopened_scanner_vuln_count | unknown | Count of reopened scanners with vulnerabilities  | 
| Kenna.ConnectorRunsList.closed_vuln_count | unknown | Count of closed vulnerabilities | 
| Kenna.ConnectorRunsList.autoclosed_vuln_count | unknown | Count of auto-closed vulnerabilities | 
| Kenna.ConnectorRunsList.reopened_vuln_count | unknown | Count of re-opened vulnerabilities | 


#### Command Example
``` ```

#### Human Readable Output


