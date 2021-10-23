Use the Kenna v2 integration to search and update vulnerabilities, schedule a run connector, and manage tags and attributes.

## Configure Kenna v2 on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Kenna v2.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g.  https://api.kennasecurity.com)__
    * __Kenna API key__
    * __Use system proxy settings__
    * __Trust any certificate (not secure)__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### 1. Search vulnerabilities
---
Searches for vulnerabilities in Kenna.

##### Base Command

`kenna-search-vulnerabilities`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Vulnerability ID to search. | Optional | 
| top-priority | Whether to return vulnerabilities that Kenna deems a top priority to fix. Can be "true" or "false". | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| status | The status of the vulnerability. Can be "open", "closed", "risk_accepted", or "false_positive". | Optional | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. | Optional | 
| to_context | Whether to flush to context. Can be "True" or "False". The default value is "True". | Optional | 


##### Context Output

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


##### Command Example
```!kenna-search-vulnerabilities limit=5```

##### Context Example
```
{
    "Kenna.Vulnerabilities": [
        {
            "Status": "open", 
            "CveID": "CVE-2018-1273", 
            "Severity": 8, 
            "AssetID": {asset_id}, 
            "Threat": 10, 
            "Patch": true, 
            "Connectors": [
                {
                    "DefinitionName": "Nessus XML", 
                    "Vendor": "Tenable", 
                    "ID": 152075, 
                    "Name": "Nessus XML"
                }, 
                {
                    "DefinitionName": "Kenna Data Importer", 
                    "Vendor": "Kenna", 
                    "ID": 152076, 
                    "Name": "Generic"
                }
            ], 
            "Score": 100, 
            "ScannerVulnerabilities": [
                {
                    "Open": true, 
                    "ExternalID": "generic scanner-id CVE-2018-1273", 
                    "Port": null
                }, 
                {
                    "Open": true, 
                    "ExternalID": "nessus-external-id CVE-2018-1273 f1ca5f10-907f-44a3-9dad-4250dff54cf6", 
                    "Port": null
                }
            ], 
            "FixID": 1460814, 
            "TopPriority": true, 
            "ID": 631199
        }, 
        {
            "Status": "open", 
            "CveID": "CVE-2018-2628", 
            "Severity": 8, 
            "AssetID": {asset_id}, 
            "Threat": 10, 
            "Patch": true, 
            "Connectors": [
                {
                    "DefinitionName": "Nessus XML", 
                    "Vendor": "Tenable", 
                    "ID": 152075, 
                    "Name": "Nessus XML"
                }, 
                {
                    "DefinitionName": "Kenna Data Importer", 
                    "Vendor": "Kenna", 
                    "ID": 152076, 
                    "Name": "Generic"
                }
            ], 
            "Score": 100, 
            "ScannerVulnerabilities": [
                {
                    "Open": true, 
                    "ExternalID": "generic scanner-id CVE-2018-2628", 
                    "Port": null
                }, 
                {
                    "Open": true, 
                    "ExternalID": "nessus-external-id CVE-2018-2628 bc839599-9e76-41f9-a79f-92120e346688", 
                    "Port": null
                }
            ], 
            "FixID": 1460809, 
            "TopPriority": true, 
            "ID": 631194
        }, 
        {
            "Status": "open", 
            "CveID": "CVE-2018-20250", 
            "Severity": 7, 
            "AssetID": {asset_id}, 
            "Threat": 9, 
            "Patch": true, 
            "Connectors": [
                {
                    "DefinitionName": "Nessus XML", 
                    "Vendor": "Tenable", 
                    "ID": 152075, 
                    "Name": "Nessus XML"
                }, 
                {
                    "DefinitionName": "Kenna Data Importer", 
                    "Vendor": "Kenna", 
                    "ID": 152076, 
                    "Name": "Generic"
                }
            ], 
            "Score": 100, 
            "ScannerVulnerabilities": [
                {
                    "Open": true, 
                    "ExternalID": "generic scanner-id CVE-2018-20250", 
                    "Port": null
                }, 
                {
                    "Open": true, 
                    "ExternalID": "nessus-external-id CVE-2018-20250 755a8761-828b-45a9-907f-d30f38bd18a9", 
                    "Port": null
                }
            ], 
            "FixID": 1460615, 
            "TopPriority": true, 
            "ID": 631026
        }, 
        {
            "Status": "open", 
            "CveID": "CVE-2018-16858", 
            "Severity": 8, 
            "AssetID": {asset_id}, 
            "Threat": 10, 
            "Patch": true, 
            "Connectors": [
                {
                    "DefinitionName": "Nessus XML", 
                    "Vendor": "Tenable", 
                    "ID": 152075, 
                    "Name": "Nessus XML"
                }, 
                {
                    "DefinitionName": "Kenna Data Importer", 
                    "Vendor": "Kenna", 
                    "ID": 152076, 
                    "Name": "Generic"
                }
            ], 
            "Score": 100, 
            "ScannerVulnerabilities": [
                {
                    "Open": true, 
                    "ExternalID": "generic scanner-id CVE-2018-16858", 
                    "Port": null
                }, 
                {
                    "Open": true, 
                    "ExternalID": "nessus-external-id CVE-2018-16858 19443e63-b916-4068-a174-0c4678416c14", 
                    "Port": null
                }
            ], 
            "FixID": 1460616, 
            "TopPriority": true, 
            "ID": 631027
        }, 
        {
            "Status": "open", 
            "CveID": "CVE-2017-8917", 
            "Severity": 8, 
            "AssetID": {asset_id}, 
            "Threat": 10, 
            "Patch": true, 
            "Connectors": [
                {
                    "DefinitionName": "Nessus XML", 
                    "Vendor": "Tenable", 
                    "ID": 152075, 
                    "Name": "Nessus XML"
                }, 
                {
                    "DefinitionName": "Kenna Data Importer", 
                    "Vendor": "Kenna", 
                    "ID": 152076, 
                    "Name": "Generic"
                }
            ], 
            "Score": 100, 
            "ScannerVulnerabilities": [
                {
                    "Open": true, 
                    "ExternalID": "generic scanner-id CVE-2017-8917", 
                    "Port": null
                }, 
                {
                    "Open": true, 
                    "ExternalID": "nessus-external-id CVE-2017-8917 bfe89aea-8ba7-411e-9f48-9fd6e821526e", 
                    "Port": null
                }
            ], 
            "FixID": 1461409, 
            "TopPriority": true, 
            "ID": 631927
        }
    ]
}
```

##### Human Readable Output
### Kenna Vulnerabilities
|Name|Score|id|
|---|---|---|
| CVE-2018-1273 | 100 | 631199 |
| CVE-2018-2628 | 100 | 631194 |
| CVE-2018-20250 | 100 | 631026 |
| CVE-2018-16858 | 100 | 631027 |
| CVE-2017-8917 | 100 | 631927 |


### 2. Run a connector
---
Executes a run of the specified connector. If file based, it will use the most recently uploaded data file.

##### Base Command

`kenna-run-connector`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The connector ID to run. | Required | 


### 3. Search fixes
---
Filters fixes by a given set of vulnerability and asset parameters and returns the filtered fixes.

##### Base Command

`kenna-search-fixes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability ID for which to search. | Optional | 
| top-priority | Whether to return vulnerabilities that Kenna deems a top priority to fix. Can be "true" or "false". | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| status | The status of the vulnerability. Can be "open", "closed", "risk_accepted", or "false_positive". | Optional | 
| vulnerabilities | vulnerabilities for search. | Optional | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. | Optional | 
| to_context | Whether to flush to context. Can be "True" or "False". The default value is "True". | Optional | 


##### Context Output

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


##### Command Example
```!kenna-search-fixes limit=3```

##### Context Example
```
{
    "Kenna.Fixes": [
        {
            "Category": null, 
            "VulnerabilityCount": 1, 
            "CveID": [
                "CVE-2019-18408"
            ], 
            "Assets": [
                {
                    "PrimaryLocator": "ip_address", 
                    "Locator": "{ip}", 
                    "DisplayLocator": "{ip}", 
                    "ID": {id}}
                }
            ], 
            "Title": "CVE-2019-18408", 
            "LastUpdatedAt": "2019-10-24T19:02:03.000Z", 
            "MaxScore": 27, 
            "ID": 1459069
        }, 
        {
            "Category": null, 
            "VulnerabilityCount": 1, 
            "CveID": [
                "CVE-2019-18409"
            ], 
            "Assets": [
                {
                    "PrimaryLocator": "ip_address", 
                    "Locator": "{ip}", 
                    "DisplayLocator": "{ip}", 
                    "ID": 10963
                }
            ], 
            "Title": "CVE-2019-18409", 
            "LastUpdatedAt": "2019-10-24T19:02:03.000Z", 
            "MaxScore": 16, 
            "ID": 1459070
        }, 
        {
            "Category": null, 
            "VulnerabilityCount": 1, 
            "CveID": [
                "CVE-2019-18393"
            ], 
            "Assets": [
                {
                    "PrimaryLocator": "ip_address", 
                    "Locator": "{ip}", 
                    "DisplayLocator": "{ip}", 
                    "ID": 10963
                }
            ], 
            "Title": "CVE-2019-18393", 
            "LastUpdatedAt": "2019-10-24T19:02:03.000Z", 
            "MaxScore": 27, 
            "ID": 1459071
        }
    ]
}
```

##### Human Readable Output
CVE-2019-18408
#### ID: 1459069
1 vulnerabilities affected
#### Diagnosis:
   Related CVE IDs:   CVE-2019-18408  
&nbsp;
CVE-2019-18409
#### ID: 1459070
1 vulnerabilities affected
#### Diagnosis:
   Related CVE IDs:   CVE-2019-18409  
&nbsp;
CVE-2019-18393
#### ID: 1459071
1 vulnerabilities affected
#### Diagnosis:
   Related CVE IDs:   CVE-2019-18393  
&nbsp;


### 4. Update an asset
---
Updates the attributes of a single asset.

##### Base Command

`kenna-update-asset`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the asset to update. | Required | 
| notes | Notes about the asset. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kenna-update-asset id={asset_id} notes="My personal asset."```


##### Human Readable Output
Asset {asset_id} was updated

### 5. Update a vulnerability
---
Updates the attributes of a single vulnerability.

##### Base Command

`kenna-update-vulnerability`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the vulnerability to update. | Required | 
| status | The status of the vulnerability. Can be "open", "closed", "risk_accepted", or "false_positive". | Optional | 
| notes | Notes about the vulnerability. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kenna-update-vulnerability id=631199 status=risk_accepted```


##### Human Readable Output
Asset 631199 was updated

### 6. Get a list of all connectors
---
Returns all connectors.

##### Base Command

`kenna-get-connectors`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.ConnectorsList.ID | Number | The connector ID. | 
| Kenna.ConnectorsList.Name | String | The connector name. | 
| Kenna.ConnectorsList.Running | Boolean | The running connector. | 
| Kenna.ConnectorsList.Host | String | The connector host. | 


##### Command Example
```!kenna-get-connectors```

##### Context Example
```
{
    "Kenna.ConnectorsList": [
        {
            "Host": null, 
            "Running": false, 
            "ID": 152075, 
            "Name": "Nessus XML"
        }, 
        {
            "Host": null, 
            "Running": false, 
            "ID": 152076, 
            "Name": "Generic"
        }, 
        {
            "Host": null, 
            "Running": false, 
            "ID": 152077, 
            "Name": "Checkmarx XML"
        }, 
        {
            "Host": "ven01347.service-now.com:443", 
            "Running": false, 
            "ID": 152078, 
            "Name": "ServiceNow"
        }, 
        {
            "Host": "8080", 
            "Running": false, 
            "ID": 152929, 
            "Name": "AppScan Enterprise"
        }
    ]
}
```

##### Human Readable Output
### Kenna Connectors
|Host|ID|Name|Running|
|---|---|---|---|
|  | 152075 | Nessus XML | false |
|  | 152076 | Generic | false |
|  | 152077 | Checkmarx XML | false |
| ven01347.service-now.com:443 | 152078 | ServiceNow | false |
| 8080 | 152929 | AppScan Enterprise | false |


### 7. Search assets
---
Searches for assets.

##### Base Command

`kenna-search-assets`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID to search for. | Optional | 
| hostname | The hostname of the asset to search for. | Optional | 
| min-score | The minimum vulnerability score for which to return vulnerabilities. | Optional | 
| tags | The tags by which to search. | Optional | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. | Optional | 
| to_context | Whether to print output to context. Can be "True" or "False". The default value is "True". | Optional | 


##### Context Output

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


##### Command Example
```!kenna-search-assets limit=4```

##### Context Example
```
{
    "Kenna.Assets": [
        {
            "Status": "active", 
            "Tags": [
                "DMZ"
            ], 
            "Notes": "Test Update Notes Kenna", 
            "Hostname": null, 
            "Fqdn": null, 
            "ID": {asset_id}, 
            "Priority": 10, 
            "Score": 1000, 
            "Owner": null, 
            "IpAddress": "{ip}", 
            "OperatingSystem": "Ubuntu", 
            "VulnerabilitiesCount": 55
        }, 
        {
            "Status": "active", 
            "Tags": [
                "Category4"
            ], 
            "Notes": null, 
            "Hostname": null, 
            "Fqdn": null, 
            "ID": {asset_id}, 
            "Priority": 10, 
            "Score": 1000, 
            "Owner": null, 
            "IpAddress": "{ip}", 
            "OperatingSystem": "Windows", 
            "VulnerabilitiesCount": 19
        }, 
        {
            "Status": "active", 
            "Tags": [
                "Category4", 
                "Category5"
            ], 
            "Notes": null, 
            "Hostname": null, 
            "Fqdn": null, 
            "ID": {asset_id}, 
            "Priority": 10, 
            "Score": 1000, 
            "Owner": null, 
            "IpAddress": "{ip}", 
            "OperatingSystem": "Windows", 
            "VulnerabilitiesCount": 10
        }, 
        {
            "Status": "active", 
            "Tags": [
                "Category3", 
                "Category5"
            ], 
            "Notes": null, 
            "Hostname": null, 
            "Fqdn": null, 
            "ID": {asset_id}, 
            "Priority": 10, 
            "Score": 1000, 
            "Owner": null, 
            "IpAddress": "{ip}", 
            "OperatingSystem": "Windows", 
            "VulnerabilitiesCount": 10
        }
    ]
}
```

##### Human Readable Output
### Kenna Assets
|IP-address|Operating System|Score|id|
|---|---|---|---|
| {ip} | Ubuntu | 1000 | {asset_id} |
| {ip} | Windows | 1000 | {asset_id} |
| {ip} | Windows | 1000 | {asset_id} |
| {ip} | Windows | 1000 | {asset_id} |


### 8. Get an asset's vulnerabilities
---
Gets vulnerabilities of the specified asset.

##### Base Command

`kenna-get-asset-vulnerabilities`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID for which to get vulnerabilities. | Required | 
| limit | The maximum number of vulnerabilities to return. The default value is 500. | Optional | 
| to_context | Whether to print output to context. Can be "True" or "False". The default value is "True". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kenna.VulnerabilitiesOfAsset.AssetID | Number | The ID of the asset that this vulnerability is associated with. | 
| Kenna.VulnerabilitiesOfAsset.CveID | String | The CVE ID of the vulnerability associated with the asset.  | 
| Kenna.VulnerabilitiesOfAsset.ID | Number | The ID of the vulnerability associated withe the asset  | 
| Kenna.VulnerabilitiesOfAsset.Patch | Boolean | Whether there is a patch for the vulnerability associated with the asset.  | 
| Kenna.VulnerabilitiesOfAsset.Status | String | The status of the vulnerability associated with the asset.  | 
| Kenna.VulnerabilitiesOfAsset.TopPriority | Boolean | Whether the vulnerability associated with the asset is a top priority.  | 
| Kenna.VulnerabilitiesOfAsset.Score | Number | The score of the vulnerability associated with the asset.  | 


##### Command Example
```!kenna-get-asset-vulnerabilities id={asset_id} limit=2```

##### Context Example
```
{
    "Kenna.VulnerabilitiesOfAsset": [
        {
            "Status": "open", 
            "CveID": "CVE-2017-5817", 
            "AssetID": {asset_id}, 
            "Patch": true, 
            "Score": 91, 
            "TopPriority": true, 
            "ID": 631229
        }, 
        {
            "Status": "open", 
            "CveID": "CVE-2018-0866", 
            "AssetID": {asset_id}, 
            "Patch": true, 
            "Score": 85, 
            "TopPriority": true, 
            "ID": 631231
        }
    ]
}
```

##### Human Readable Output
### Kenna Vulnerabilities
|Name|Score|id|
|---|---|---|
| CVE-2017-5817 | 91 | 631229 |
| CVE-2018-0866 | 85 | 631231 |


### 9. Add a tag to an asset
---
Adds a tag to the specified asset.

##### Base Command

`kenna-add-tag`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | A comma-separated list of tags to add to the asset. | Required | 
| id | The asset ID to which to add the tag.  | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kenna-add-tag id={asset_id} tag="My test tag"```



##### Human Readable Output
Tag My test tag was added to asset {asset_id}

### 10. Delete a tag from an asset
---
Deletes tags from the specified asset.

##### Base Command

`kenna-delete-tag`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID from which to delete the tag. | Required | 
| tag | The tag to delete. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!kenna-delete-tag id={asset_id} tag="My test tag"```



##### Human Readable Output
Tag My test tag was deleted to asset {asset_id}


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


#### Command Example
```!kenna-get-connector-runs connector_id={connector_id}```

#### Context Example
```
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
            "ID": 111111,
            "ProcessedAssets": 10,
            "ProcessedPayload": null,
            "ProcessedScannerVulnerabilities": 10,
            "ReopenedScannerVulnerabilities": 0,
            "StartTime": "2019-10-24T19:02:02.000Z",
            "Success": true,
            "TotalPayload": 10,
            "UpdatedScannerVulnerabilities": 10
        }
    }
}
```

#### Human Readable Output

>### Kenna Connector Runs
>|AssetsWithTagsReset|AutoclosedScannerVulnerabilities|AutoclosedVulnerabilities|ClosedScannerVulnerabilities|ClosedVulnerabilities|CreatedScannerVulnerabilities|EndTime|FailedPayload|ID|ProcessedAssets|ProcessedPayload|ProcessedScannerVulnerabilities|ReopenedScannerVulnerabilities|ReopenedVulnerabilities|StartTime|Success|TotalPayload|UpdatedScannerVulnerabilities|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 0 | 0 | 10 | 2019-10-24T19:13:36.000Z | 0 | 111111 | 10 | 10 | 10 | 0 | 0 | 2019-10-24T19:02:02.000Z | true | 10 | 0 |

