Use the Kenna v2 integration to search and update vulnerabilities, schedule a run connector, and manage tags and attributes.
This integration was integrated and tested with version 1.0 of Kenna.


## Configure Kenna v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for Kenna v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g.  <https://api.kennasecurity.com>) | False |
    | Kenna API key | False |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

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
| id | The vulnerability ID for which to search. | Optional | 
| top-priority | Whether to return vulnerabilities that Kenna deems a top priority to fix. Possible values are: true, false. | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| status | The status of the vulnerability. Possible values are: open, closed, risk_accepted, false_positive. | Optional | 
| limit | The maximum number of vulnerabilities to return. Default is 500. | Optional | 
| to_context | Whether to flush to context. Possible values are: True, False. Default is True. | Optional | 

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

#### Command example

```!kenna-search-vulnerabilities id=dummy limit=1 to_context=True```

#### Context Example

```json
{
    "Kenna": {
        "Vulnerabilities": {
            "AssetID": "dummy",
            "Connectors": [
                {
                    "DefinitionName": "Dummy XML",
                    "ID": 0,
                    "Name": "Dummy XML",
                    "Vendor": "Dummy"
                },
                {
                    "DefinitionName": "Kenna Data",
                    "ID": 1,
                    "Name": "Generic",
                    "Vendor": "Dummy"
                }
            ],
            "CveID": "CVE-2015-0000",
            "FixID": 00000,
            "ID": 00000,
            "Patch": true,
            "ScannerVulnerabilities": [
                {
                    "ExternalID": "generic scanner-id CVE-2015-0000",
                    "Open": true,
                    "Port": null
                },
                {
                    "ExternalID": "dummy-external-id CVE-2015-0000 0000-0000-0000-0000-0000",
                    "Open": true,
                    "Port": null
                }
            ],
            "Score": 100,
            "Severity": 10,
            "Status": "open",
            "Threat": 10,
            "TopPriority": true
        }
    }
}
```

#### Human Readable Output

>### Kenna Vulnerabilities

>|Name|Score|id|
>|---|---|---|
>| CVE-2015-0000 | 100 | 00000 |


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

#### Command example

```!kenna-run-connector id=dummy```

#### Human Readable Output

>Connector dummy ran successfully.

### kenna-search-fixes

***
Filters fixes by a given set of vulnerability and asset parameters and returns the filtered fixes.

#### Base Command

`kenna-search-fixes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability ID for which to search. | Optional | 
| top-priority | Whether to return vulnerabilities that Kenna deems a top priority to fix. Possible values are: true, false. | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| status | The status of the vulnerability. Possible values are: open, closed, risk_accepted, false_positive. | Optional | 
| limit | The maximum number of vulnerabilities to return. Default is 500. | Optional | 
| to_context | Whether to flush to context. Possible values are: True, False. Default is True. | Optional | 

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

#### Command example

```!kenna-search-fixes limit=2 id=dummy to_context=True```

#### Context Example

```json
{
    "Kenna": {
        "Fixes": {
            "Assets": [
                {
                    "DisplayLocator": "0.0.0",
                    "ID": 0,
                    "Locator": "0.0.0",
                    "PrimaryLocator": "ip_address"
                }
            ],
            "Category": null,
            "CveID": [
                "CVE-2015-0000"
            ],
            "ID": 0,
            "LastUpdatedAt": "2019-10-24T19:13:29.000Z",
            "MaxScore": 100,
            "Title": "CVE-2015-0000",
            "VulnerabilityCount": 1
        }
    }
}
```

#### Human Readable Output

>CVE-2015-0000

>#### ID: 0

>1 vulnerabilities affected

>#### Diagnosis:

>   Related CVE IDs:   CVE-2015-0000  
>&nbsp;


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
| inactive | Whether to deactivate the asset. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!kenna-update-asset id=dummy notes="New asset info"```

#### Human Readable Output

>Asset with ID dummy was successfully updated.

### kenna-update-vulnerability

***
Updates the attributes of a single vulnerability.

#### Base Command

`kenna-update-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the vulnerability to update. | Required | 
| status | The status of the vulnerability. Possible values are: open, closed, risk_accepted, false_positive. | Optional | 
| notes | Notes about the vulnerability. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!kenna-update-vulnerability id=dummy status=open notes="Test"```

#### Human Readable Output

>Asset dummy was updated

### kenna-get-connectors

***
Returns all connectors.

#### Base Command

`kenna-get-connectors`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.ConnectorsList.ID | Number | The connector ID. | 
| Kenna.ConnectorsList.Name | String | The connector name. | 
| Kenna.ConnectorsList.Running | Boolean | The running connector. | 
| Kenna.ConnectorsList.Host | String | The connector host. | 

#### Command example

```!kenna-get-connectors```

#### Context Example

```json
{
    "Kenna": {
        "ConnectorsList": [
            {
                "Host": null,
                "ID": 0,
                "Name": "XML",
                "Running": false
            },
            {
                "Host": null,
                "ID": 1,
                "Name": "Generic",
                "Running": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Kenna Connectors

>|Host|ID|Name|Running|
>|---|---|---|---|
>|  | 0 | XML | false |
>|  | 1 | Generic | false |


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
| limit | The maximum number of vulnerabilities to return. Default is 500. | Optional | 
| to_context | Whether to print output to context. Possible values are: True, False. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.Assets.ID | Number | The asset ID. | 
| Kenna.Assets.ExternalID | String | The asset external ID. |
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
| Kenna.Assets.OperatingSystem | String | Operating system of the asset. | 

#### Command example

```!kenna-search-assets limit=2 to_context=True```

#### Context Example

```json
{
    "Kenna": {
        "Assets": [
            {
                "Fqdn": null,
                "Hostname": null,
                "ID": 0,
                "IpAddress": "0.0.0",
                "Notes": "New asset info",
                "OperatingSystem": "Windows",
                "Owner": null,
                "Priority": 10,
                "Score": 1000,
                "Status": "active",
                "Tags": [
                    "Dummy"
                ],
                "VulnerabilitiesCount": 10
            },
            {
                "Fqdn": null,
                "Hostname": null,
                "ID": 1,
                "IpAddress": "0.0.0",
                "Notes": null,
                "OperatingSystem": "Windows",
                "Owner": null,
                "Priority": 10,
                "Score": 1000,
                "Status": "active",
                "Tags": [
                    "Category"
                ],
                "VulnerabilitiesCount": 10
            }
        ]
    }
}
```

#### Human Readable Output

>### Kenna Assets

>|IP-address|Operating System|Score|id|
>|---|---|---|---|
>| 0.0.0 | Windows | 1000 | 0 |
>| 0.0.0 | Windows | 1000 | 1 |


### kenna-get-asset-vulnerabilities

***
Gets vulnerabilities of the specified asset.

#### Base Command

`kenna-get-asset-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID for which to get vulnerabilities. | Required | 
| limit | The maximum number of vulnerabilities to return. Default is 500. | Optional | 
| to_context | Whether to print output to context. Possible values are: True, False. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.VulnerabilitiesOfAsset.AssetID | Number | The ID of the asset that this vulnerability is associated with. | 
| Kenna.VulnerabilitiesOfAsset.CveID | String | The CVE ID of the vulnerability associated with the asset. | 
| Kenna.VulnerabilitiesOfAsset.ID | Number | The ID of the vulnerability associated withe the asset. | 
| Kenna.VulnerabilitiesOfAsset.Patch | Boolean | Whether there is a patch for the vulnerability associated with the asset. | 
| Kenna.VulnerabilitiesOfAsset.Status | String | The status of the vulnerability associated with the asset. | 
| Kenna.VulnerabilitiesOfAsset.TopPriority | Boolean | Whether the vulnerability associated with the asset is a top priority. | 
| Kenna.VulnerabilitiesOfAsset.Score | Number | The score of the vulnerability associated with the asset. | 

#### Command example

```!kenna-get-asset-vulnerabilities id=dummy limit=2 to_context=True```

#### Context Example

```json
{
    "Kenna": {
        "VulnerabilitiesOfAsset": [
            {
                "AssetID": "dummy",
                "CveID": "CVE-2015-0000",
                "ID": 0,
                "Patch": true,
                "Score": 100,
                "Status": "open",
                "TopPriority": true
            },
            {
                "AssetID": "dummy",
                "CveID": "CVE-2015-0001",
                "ID": 1,
                "Patch": true,
                "Score": 100,
                "Status": "open",
                "TopPriority": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Kenna Vulnerabilities

>|Name|Score|id|
>|---|---|---|
>| CVE-2015-0000 | 100 | 0 |
>| CVE-2015-0001 | 100 | 1 |


### kenna-add-tag

***
Adds a tag to the specified asset.

#### Base Command

`kenna-add-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | A comma-separated list of tags to add to the asset. | Required | 
| id | The asset ID to which to add the tag. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!kenna-add-tag tag="Test tag" id=dummy```

#### Human Readable Output

>Tag Test tag was added to asset dummy

### kenna-delete-tag

***
Deletes tags from the specified asset.

#### Base Command

`kenna-delete-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID from which to delete the tag. | Required | 
| tag | The tag to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!kenna-delete-tag id=dummy tag="Test tag"```

#### Human Readable Output

>Tag Test tag was successfully removed from asset.

### kenna-get-connector-runs

***
Returns JSON data on all the runs of a given connector.

#### Base Command

`kenna-get-connector-runs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_id | Unique numerical ID of the connector. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.ConnectorRunsList.ID | Number | Connector Run ID. | 
| Kenna.ConnectorRunsList.StartTime | Number | Connector Run Start Time. | 
| Kenna.ConnectorRunsList.EndTime | string | Connector Run End Time. | 
| Kenna.ConnectorRunsList.Success | boolean | Boolean value showing connector success. | 
| Kenna.ConnectorRunsList.TotalPayload | Number | Total connector payloads. | 
| Kenna.ConnectorRunsList.ProcessedPayload | Number | Total payloads processed the connector. | 
| Kenna.ConnectorRunsList.FailedPayload | Number | Total failed payloads. | 
| Kenna.ConnectorRunsList.ProcessedAssets | Number | Amount of processed assets. | 
| Kenna.ConnectorRunsList.AssetsWithTagsReset | Number | Amount of assets with reset tags. | 
| Kenna.ConnectorRunsList.ProcessedScannerVulnerabilities | Number | Amount of processed scanners with vulnerabilities. | 
| Kenna.ConnectorRunsList.UpdatedScannerVulnerabilities | Number | Amount of updated scanners with vulnerabilities. | 
| Kenna.ConnectorRunsList.CreatedScannerVulnerabilities | Number | Amount of created scanners with vulnerabilities. | 
| Kenna.ConnectorRunsList.ClosedScannerVulnerabilities | Number | Amount of closed scanners with vulnerabilities. | 
| Kenna.ConnectorRunsList.AutoclosedScannerVulnerabilities | Number | Amount of auto-closed scanners with vulnerabilities. | 
| Kenna.ConnectorRunsList.ReopenedScannerVulnerabilities | number | Amount of reopened scanners with vulnerabilities. | 
| Kenna.ConnectorRunsList.ClosedVulnerabilities | Number | Amount of closed vulnerabilities. | 
| Kenna.ConnectorRunsList.AutoclosedVulnerabilities | Number | Amount of auto-closed vulnerabilities. | 
| Kenna.ConnectorRunsList.ReopenedVulnerabilities | Number | Amount of re-opened vulnerabilities. | 

#### Command example

```!kenna-get-connector-runs connector_id=dummy```

#### Context Example

```json
{
    "Kenna": {
        "ConnectorRunsList": {
            "AssetsWithTagsReset": 0,
            "AutoclosedScannerVulnerabilities": 0,
            "AutoclosedVulnerabilities": 0,
            "ClosedScannerVulnerabilities": 0,
            "ClosedVulnerabilities": 0,
            "CreatedScannerVulnerabilities": 0,
            "EndTime": "2019-10-24T19:13:36.000Z",
            "FailedPayload": 0,
            "ID": 0,
            "ProcessedAssets": 0,
            "ProcessedPayload": null,
            "ProcessedScannerVulnerabilities": 0,
            "ReopenedScannerVulnerabilities": 0,
            "ReopenedVulnerabilities": 0,
            "StartTime": "2019-10-24T19:02:02.000Z",
            "Success": true,
            "TotalPayload": 0,
            "UpdatedScannerVulnerabilities": 0
        }
    }
}
```

#### Human Readable Output

>### Kenna Connector Runs

>|AssetsWithTagsReset|AutoclosedScannerVulnerabilities|AutoclosedVulnerabilities|ClosedScannerVulnerabilities|ClosedVulnerabilities|CreatedScannerVulnerabilities|EndTime|FailedPayload|ID|ProcessedAssets|ProcessedPayload|ProcessedScannerVulnerabilities|ReopenedScannerVulnerabilities|ReopenedVulnerabilities|StartTime|Success|TotalPayload|UpdatedScannerVulnerabilities|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 0 | 0 | 0 | 2019-10-24T19:13:36.000Z | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2019-10-24T19:02:02.000Z | true | 0 | 0 |


### kenna-search-assets-by-external-id

***
Search assets by external ID.

#### Base Command

`kenna-search-assets-by-external-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| external_id | The external ID of the asset. | Required | 
| to_context | Whether to put data in context. Possible values are: true, false.| Optional | 
| limit | The maximum number of assets to return. Default is 500. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.Assets.ID | Number | The asset ID. | 
| Kenna.Assets.Notes | String | Notes of current asset. | 
| Kenna.Assets.VulnerabilitiesCount | Number | Count of vulnerabilities of current asset. | 
| Kenna.Assets.Hostname | String | Hostname of current asset. | 
| Kenna.Assets.Score | Number | Score of current asset. | 
| Kenna.Assets.IpAddress | String | IP of current asset. | 
| Kenna.Assets.OperatingSystem | String | Operating system of current asset. | 

#### Command example

```!kenna-search-assets-by-external-id external_id=dummy limit=2 to_context=true```

#### Context Example

```json
{
    "Kenna": {
        "Assets": [
            {
                "Fqdn": null,
                "Hostname": null,
                "ID": 0,
                "IpAddress": "0.0.0",
                "Notes": "New asset info",
                "OperatingSystem": "Windows",
                "Owner": null,
                "Priority": 10,
                "Score": 1000,
                "Status": "active",
                "Tags": [
                    "Category10",
                    "Category9"
                ],
                "VulnerabilitiesCount": 10
            },
            {
                "Fqdn": null,
                "Hostname": null,
                "ID": 1,
                "IpAddress": "0.0.0",
                "Notes": null,
                "OperatingSystem": "Windows",
                "Owner": null,
                "Priority": 10,
                "Score": 1000,
                "Status": "active",
                "Tags": [
                    "Category5",
                    "Category7"
                ],
                "VulnerabilitiesCount": 10
            }
        ]
    }
}
```

#### Human Readable Output

>### Kenna Assets

>|IP-address|Operating System|Score|id|
>|---|---|---|---|
>| 0.0.0 | Windows | 1000 | 0 |
>| 0.0.0 | Windows | 1000 | 0 |

