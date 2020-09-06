The SentinelOne REST API sends requests to your Management Server and responds with data that the management pulled from Agents or from the management database.

This integration was integrated and tested with version 2.1 of SentinelOne
## Configure SentinelOne V3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SentinelOne V3.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g., https://usea1.sentinelone.net\) | True |
| token | API Token | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetch_time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| fetch_limit | Fetch limit: the maximum number of incidents to fetch | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sentinelone-list-agents
***
Returns all agents that match the specified criteria.


#### Base Command

`sentinelone-list-agents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_name | Filter by computer name. | Optional | 
| scan_status | CSV list of scan statuses by which to filter the results, for example: "started,aborted". | Optional | 
| os_type | Included OS types, for example: "windows". | Optional | 
| created_at | Endpoint created at timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| min_active_threats | Minimum number of threats for an agent. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agents.NetworkStatus | string | The agent network status. | 
| SentinelOne.Agents.ID | string | The agent ID. | 
| SentinelOne.Agents.AgentVersion | string | The agent software version. | 
| SentinelOne.Agents.IsDecomissioned | boolean | Whether the agent is decommissioned. | 
| SentinelOne.Agents.IsActive | boolean | Whether the agent is active. | 
| SentinelOne.Agents.LastActiveDate | date | The last active date of the agent | 
| SentinelOne.Agents.RegisteredAt | date | The registration date of the agent. | 
| SentinelOne.Agents.ExternalIP | string | The agent IP address. | 
| SentinelOne.Agents.ThreatCount | number | Number of active threats. | 
| SentinelOne.Agents.EncryptedApplications | boolean | Whether disk encryption is enabled. | 
| SentinelOne.Agents.OSName | string | Name of operating system. | 
| SentinelOne.Agents.ComputerName | string | Name of agent computer. | 
| SentinelOne.Agents.Domain | string | Domain name of the agent. | 
| SentinelOne.Agents.CreatedAt | date | Creation time of the agent. | 
| SentinelOne.Agents.SiteName | string | Site name associated with the agent. | 


#### Command Example
```!sentinelone-list-agents```

#### Context Example
```
{
    "SentinelOne.Agents": [
        {
            "ExternalIP": "77.125.26.100", 
            "Domain": "local", 
            "LastActiveDate": "2019-08-18T10:31:18.675994Z", 
            "NetworkStatus": "connected", 
            "EncryptedApplications": true, 
            "ThreatCount": 0, 
            "ComputerName": "Bills-MacBook-Pro", 
            "IsActive": false, 
            "OSName": "OS X", 
            "SiteName": "demisto", 
            "AgentVersion": "2.6.3.2538", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2018-12-02T08:48:37.785644Z", 
            "ID": "507609079972381234", 
            "CreatedAt": "2018-12-02T08:48:37.792682Z"
        }, 
        {
            "ExternalIP": "77.125.26.100", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-08-18T13:56:50.620408Z", 
            "NetworkStatus": "connected", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-AJ0KANC", 
            "IsActive": true, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.3.38", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-06-27T08:01:05.567249Z", 
            "ID": "657613730168121234", 
            "CreatedAt": "2019-06-27T08:01:05.571895Z"
        }, 
        {
            "ExternalIP": "34.100.71.242", 
            "Domain": "PALOALTONETWORK", 
            "LastActiveDate": "2019-08-16T06:32:48.683437Z", 
            "NetworkStatus": "connecting", 
            "EncryptedApplications": true, 
            "ThreatCount": 0, 
            "ComputerName": "TLVWIN9131Q1V", 
            "IsActive": false, 
            "OSName": "Windows 10", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.3.38", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-06-27T12:09:43.590587Z", 
            "ID": "657738871640371234", 
            "CreatedAt": "2019-06-27T12:09:43.598071Z"
        }, 
        {
            "ExternalIP": "52.49.120.63", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-08-06T07:38:35.677266Z", 
            "NetworkStatus": "connected", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-55LV527", 
            "IsActive": false, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.5.63", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-08-05T11:42:38.644242Z", 
            "ID": "685991494097051234", 
            "CreatedAt": "2019-08-05T11:42:38.648232Z"
        }, 
        {
            "ExternalIP": "77.125.26.100", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-08-06T07:37:05.677281Z", 
            "NetworkStatus": "connecting", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-TR9AE9E", 
            "IsActive": false, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.5.63", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-08-05T11:46:49.681346Z", 
            "ID": "685993599961234", 
            "CreatedAt": "2019-08-05T11:46:49.687519Z"
        }
    ]
}
```

#### Human Readable Output

### Sentinel One - List of Agents 
Provides summary information and details for all the agents that matched your search criteria

| **Agent Version** | **Computer Name** | **Created At** | **Domain** | **Encrypted Applications** | **External IP** | **ID** | **Is Active** | **Is Decomissioned** | **Last Active Date** | **Network Status** | **OS Name** | **Registered At** | **Site Name** | **Threat Count** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.6.3.2538 | Bills-MacBook-Pro | 2018-12-02T08:48:37.792682Z | local | true | 77.125.26.100 | 507609079972381234 | false | false | 2019-08-18T10:31:18.675994Z | connected | OS X | 2018-12-02T08:48:37.785644Z | demisto | 0 |
| 3.1.3.38 |  |  | WORKGROUP | false | 77.125.26.100 | 657613730168121234 | true | false |  | connected |  | 2019-06-27T08:01:05.567249Z |  | 0 |
| 3.1.3.38 | TLVWIN9131Q1V | 2019-06-27T12:09:43.598071Z | PALOALTONETWORK | true | 34.100.71.242 | 657738871640371234 | false | false | 2019-08-16T06:32:48.683437Z | connecting |  | 2019-06-27T12:09:43.590587Z |  | 0 |
| 3.1.5.63 | EC2AMAZ-55LV527 |  | WORKGROUP | false |  | 685991494097051234 |  | false | 2019-08-06T07:38:35.677266Z |  |  | 2019-08-05T11:42:38.644242Z | demisto |  |
| 3.1.5.63 | EC2AMAZ-TR9AE9E | 2019-08-05T11:46:49.687519Z | WORKGROUP | false | 77.125.26.100 | 685993599961234 |  | false | 2019-08-06T07:37:05.677281Z |  | Windows Server 2016 | 2019-08-05T11:46:49.681346Z |  | 0 |


### sentinelone-create-white-list-item
***
Creates an exclusion item that matches the specified input filter.


#### Base Command

`sentinelone-create-white-list-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_type | Exclusion item type. Can be "file_type", "path", "white_hash", "certificate", or "browser". | Required | 
| exclusion_value | Value of the exclusion item for the exclusion list. | Required | 
| os_type | OS type. Can be "windows", "windows_legacy", "macos", or "linux". OS type is required for hash exclusions. | Required | 
| description | Description for adding the item. | Optional | 
| exclusion_mode | Exclusion mode (path exclusion only). Can be "suppress", "disable_in_process_monitor_deep", "disable_in_process_monitor", "disable_all_monitors", or "disable_all_monitors_deep". | Optional | 
| path_exclusion_type | Excluded path for a path exclusion list. | Optional | 
| group_ids | CSV list of group IDs by which to filter. Can be "site_ids" or "group_ids". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Exclusions.ID | string | The whitelisted entity ID. | 
| SentinelOne.Exclusions.Type | string | The whitelisted item type. | 
| SentinelOne.Exclusions.CreatedAt | date | Time when the whitelist item was created. | 


#### Command Example
```!sentinelone-get-white-list exclusion_type=file_type ```

#### Context Example
```
{
    "SentinelOne.Exclusions": [
        {
            "UserName": "John Roe", 
            "UserID": "433273625970231234", 
            "Value": "MDF", 
            "Source": "user", 
            "Mode": null, 
            "UpdatedAt": "2018-11-05T18:48:49.070978Z", 
            "OsType": "windows", 
            "Type": "file_type", 
            "ID": "488342219732991235", 
            "CreatedAt": "2018-11-05T18:48:49.072116Z"
        }
    ]
}
```
#### Human Readable Output

| **CreatedAt** | **ID** | **OsType** | **Source** | **Type** | **UpdatedAt** | **UserID** | **UserName** | **Value** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2018-11-05T18:48:49.072116Z | 488342219732991235 | windows | user | file_type | 2018-11-05T18:48:49.070978Z | 433273625970231234 | John Ro | MDF |


### sentinelone-get-white-list
***
Lists all exclusion items that match the specified input filter.


#### Base Command

`sentinelone-get-white-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_ids | List of IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| os_types | CSV list of OS types by which to filter, for example: "windows, linux". | Optional | 
| exclusion_type | Exclusion type. Can be "file_type", "path", "white_hash", "certificate", "browser". | Optional | 
| limit | The maximum number of items to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Exclusions.ID | string | The item ID. | 
| SentinelOne.Exclusions.Type | string | The exclusion item type. | 
| SentinelOne.Exclusions.CreatedAt | date | Timestamp when the item was added. | 
| SentinelOne.Exclusions.Value | string | Value of the added item. | 
| SentinelOne.Exclusions.Source | string | Source of the added item. | 
| SentinelOne.Exclusions.UserID | string | User ID of the user that added the item. | 
| SentinelOne.Exclusions.UpdatedAt | date | Timestamp when the item was updated | 
| SentinelOne.Exclusions.OsType | string | OS type. | 
| SentinelOne.Exclusions.UserName | string | User name of the user that added the item. | 
| SentinelOne.Exclusions.Mode | string | CSV list of modes by which to filter \(ath exclusions only\), for example: "suppress". | 


#### Command Example
```!sentinelone-get-white-list exclusion_type=file_type ```

#### Context Example
```
{
    "SentinelOne.Exclusions": [
        {
            "UserName": "John Roe", 
            "UserID": "433273625970231234", 
            "Value": "MDF", 
            "Source": "user", 
            "Mode": null, 
            "UpdatedAt": "2018-11-05T18:48:49.070978Z", 
            "OsType": "windows", 
            "Type": "file_type", 
            "ID": "488342219732991235", 
            "CreatedAt": "2018-11-05T18:48:49.072116Z"
        }
    ]
}
```
#### Human Readable Output

| **CreatedAt** | **ID** | **OsType** | **Source** | **Type** | **UpdatedAt** | **UserID** | **UserName** | **Value** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2018-11-05T18:48:49.072116Z | 488342219732991235 | windows | user | file_type | 2018-11-05T18:48:49.070978Z | 433273625970231234 | John Ro | MDF |


### sentinelone-get-hash
***
Gets the reputation of a hash.


#### Base Command

`sentinelone-get-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The content hash. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Hash.Rank | Number | The hash reputation \(1-10\). | 
| SentinelOne.Hash.Hash | String | The content hash. | 


#### Command Example
```!sentinelone-get-hash hash=3395856ce81f2b7382dee72602f798b642f14140```

#### Context Example
```
{
    "SentinelOne": {
        "Hash": {
            "Hash": "3395856ce81f2b7382dee72602f798b642f14140",
            "Rank": "7"
        }
    }
}
```

#### Human Readable Output

>### Sentinel One - Hash Reputation 
>Provides hash reputation (rank from 0 to 10):
>
>| Hash | Rank |
>| --- | --- |
>| 3395856ce81f2b7382dee72602f798b642f14140 | 7 |


### sentinelone-get-threats
***
Returns threats according to specified filters.


#### Base Command

`sentinelone-get-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_status | CSV list of mitigation statuses. Can be "mitigated", "active", "blocked", "suspicious", "pending", or "suspicious_resolved". | Optional | 
| created_before | Searches for threats created before this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_after | Searches for threats created after this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_until | Searches for threats created on or before this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_from | Search for threats created on or after this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| resolved | Whether to only return resolved threats. | Optional | 
| display_name | Threat display name. Can be a partial display name, not an exact match. | Optional | 
| limit | The maximum number of threats to return. Default is 20. | Optional | 
| query | Full free-text search for fields. Can be "content_hash", "file_display_name", "file_path", "computer_name", or "uuid". | Optional | 
| threat_ids | CSV list of threat IDs, for example: "225494730938493804,225494730938493915". | Optional | 
| classifications |  CSV list of threat classifications to search, for example: "Malware", "Network", "Benign". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.AgentComputerName | String | The agent computer name. | 
| SentinelOne.Threat.CreatedDate | Date | File created date. | 
| SentinelOne.Threat.SiteID | String | The site ID. | 
| SentinelOne.Threat.Classification | string | Classification name. | 
| SentinelOne.Threat.ClassificationSource | string | Source of the threat Classification. | 
| SentinelOne.Threat.MitigationStatus | String | The agent status. | 
| SentinelOne.Threat.AgentID | String | The agent ID. | 
| SentinelOne.Threat.FileContentHash | String | SHA1 hash of file content. | 
| SentinelOne.Threat.ConfidenceLevel | String | SentinelOne threat confidence level. | 
| SentinelOne.Threat.ThreatName | String | Threat name. | 
| SentinelOne.Threat.FileSha256 | String | SHA256 hash of file content. | 
| SentinelOne.Threat.AgentOsType | String | OS type. | 
| SentinelOne.Threat.FilePath | String | File path. | 
| SentinelOne.Threat.Username | String | Username. | 


#### Command Example
```!sentinelone-get-threats resolved=true```

#### Context Example
```
{
    "SentinelOne": {
        "Threat": [
            {
                "AgentComputerName": "MacBook-Pro",
                "AgentID": "507609079972381234",
                "AgentOsType": "macos",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2018-12-04T15:28:16.044265Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "/Users/doc_test/.Trash/eicar.com.txt",
                "FileSha256": null,
                "ID": "509259775582961234",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "eicar.com.txt",
                "Username": "root"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T12:05:49.095889Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                "FileSha256": null,
                "ID": "715718962991148224",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Unconfirmed 123490.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T12:14:42.440985Z",
                "FileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "FileSha256": null,
                "ID": "715723437013282014",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Ncat Netcat Portable - CHIP-Installer.exe",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T12:14:43.349807Z",
                "FileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "FileSha256": null,
                "ID": "715723444638526700",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Ncat Netcat Portable - CHIP-Installer.exe",
                "Username": ""
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T12:14:44.069617Z",
                "FileContentHash": "ccce727e39cb8d955a323bf2c0419f31fb917e5a",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                "FileSha256": null,
                "ID": "715723450678324472",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Ncat Netcat Portable - CHIP-Installer (1).exe",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T14:25:49.421016Z",
                "FileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "FileSha256": null,
                "ID": "715789430024646184",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Ncat Netcat Portable - CHIP-Installer.exe",
                "Username": ""
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T14:25:49.944443Z",
                "FileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "FileSha256": null,
                "ID": "715789434420276790",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Ncat Netcat Portable - CHIP-Installer.exe",
                "Username": ""
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T14:35:38.133381Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                "FileSha256": null,
                "ID": "715794368498839113",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Unconfirmed 117897.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T14:35:44.189243Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                "FileSha256": null,
                "ID": "715794419300249176",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Unconfirmed 537649.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-16T09:23:27.669569Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                "FileSha256": null,
                "ID": "716362021709886102",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Unconfirmed 136405.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-16T09:28:54.846665Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                "FileSha256": null,
                "ID": "716364766277874352",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Unconfirmed 95652.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168121234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-16T09:36:02.411027Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 742374.crdownload",
                "FileSha256": null,
                "ID": "716368352944665294",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "Unconfirmed 742374.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "TLVWIN9131Q1V",
                "AgentID": "657738871640371234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-10-14T19:46:14.666494Z",
                "FileContentHash": "",
                "FilePath": "\\Device\\HarddiskVolume4\\Users\\doc_test\\AppData\\Local\\Microsoft\\OneDrive\\19.152.0801.0008",
                "FileSha256": null,
                "ID": "736969199273531914",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "19.152.0801.0008",
                "Username": "PALOALTONETWORK\\doc_test"
            },
            {
                "AgentComputerName": "TLVWIN9131Q1V",
                "AgentID": "657738871640371234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-11-06T08:39:27.239867Z",
                "FileContentHash": "",
                "FilePath": "\\Device\\HarddiskVolume4\\Users\\doc_test\\AppData\\Local\\Microsoft\\OneDrive\\19.152.0801.0009",
                "FileSha256": null,
                "ID": "753303434477386151",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "19.152.0801.0009",
                "Username": "PALOALTONETWORK\\doc_test"
            },
            {
                "AgentComputerName": "TLVWIN9131Q1V",
                "AgentID": "657738871640371234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2020-02-17T10:11:27.879999Z",
                "FileContentHash": "",
                "FilePath": "\\Device\\HarddiskVolume4\\Users\\doc_test\\AppData\\Local\\Microsoft\\OneDrive\\19.222.1110.0006\\amd64",
                "FileSha256": null,
                "ID": "828001645276245587",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "amd64",
                "Username": "PALOALTONETWORK\\doc_test"
            },
            {
                "AgentComputerName": "TLVWIN9131Q1V",
                "AgentID": "657738871640371234",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2020-02-17T10:11:28.377994Z",
                "FileContentHash": "",
                "FilePath": "\\Device\\HarddiskVolume4\\Users\\doc_test\\AppData\\Local\\Microsoft\\OneDrive\\19.222.1110.0006",
                "FileSha256": null,
                "ID": "828001649453772382",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366721234",
                "ThreatName": "19.222.1110.0006",
                "Username": "PALOALTONETWORK\\doc_test"
            }
        ]
    }
}
```

#### Human Readable Output

>### Sentinel One - Getting Threat List 
>Provides summary information and details for all the threatsthat matched your search criteria.
>|Agent Computer Name|Agent ID|Classification|Created Date|File Content Hash|ID|Mitigation Status|Site ID|Site Name|
>|---|---|---|---|---|---|---|---|---|
>| MacBook-Pro | 507609079972381234 | Malware | 2018-12-04T15:28:16.044265Z | 3395856ce81f2b7382dee72602f798b642f14140 | 509259775582961234 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T12:05:49.095889Z | 3395856ce81f2b7382dee72602f798b642f14140 | 715718962991148224 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T12:14:42.440985Z | d8757a0396d05a1d532422827a70a7966c361366 | 715723437013282014 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T12:14:43.349807Z | d8757a0396d05a1d532422827a70a7966c361366 | 715723444638526700 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T12:14:44.069617Z | ccce727e39cb8d955a323bf2c0419f31fb917e5a | 715723450678324472 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T14:25:49.421016Z | 3e7704f5668bc4330c686ccce2dd6f9969686a2c | 715789430024646184 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T14:25:49.944443Z | 3e7704f5668bc4330c686ccce2dd6f9969686a2c | 715789434420276790 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T14:35:38.133381Z | 3395856ce81f2b7382dee72602f798b642f14140 | 715794368498839113 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-15T14:35:44.189243Z | 3395856ce81f2b7382dee72602f798b642f14140 | 715794419300249176 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-16T09:23:27.669569Z | 3395856ce81f2b7382dee72602f798b642f14140 | 716362021709886102 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-16T09:28:54.846665Z | 3395856ce81f2b7382dee72602f798b642f14140 | 716364766277874352 | mitigated | 475482421366721234 | demisto |
>| EC2AMAZ-AJ0KANC | 657613730168121234 | Malware | 2019-09-16T09:36:02.411027Z | 3395856ce81f2b7382dee72602f798b642f14140 | 716368352944665294 | mitigated | 475482421366721234 | demisto |
>| TLVWIN9131Q1V | 657738871640371234 | Malware | 2019-10-14T19:46:14.666494Z |  | 736969199273531914 | mitigated | 475482421366721234 | demisto |
>| TLVWIN9131Q1V | 657738871640371234 | Malware | 2019-11-06T08:39:27.239867Z |  | 753303434477386151 | mitigated | 475482421366721234 | demisto |
>| TLVWIN9131Q1V | 657738871640371234 | Malware | 2020-02-17T10:11:27.879999Z |  | 828001645276245587 | mitigated | 475482421366721234 | demisto |
>| TLVWIN9131Q1V | 657738871640371234 | Malware | 2020-02-17T10:11:28.377994Z |  | 828001649453772382 | mitigated | 475482421366721234 | demisto |


### sentinelone-threat-summary
***
Returns a dashboard threat summary.


#### Base Command

`sentinelone-threat-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_ids | CSV list of group IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.NotResolved | Number | Number of unresolved threats in the system. | 
| SentinelOne.Threat.SuspiciousNotMitigatedNotResolved | Number | Number of unmitigated suspicious threats in the system. | 
| SentinelOne.Threat.SuspiciousNotResolved | Number | Number of unresolved suspicious threats in the system. | 
| SentinelOne.Threat.Resolved | Number | Number of resolved threats in the system. | 
| SentinelOne.Threat.InProgress | Number | Number of active threats in the system. | 
| SentinelOne.Threat.Total | Number | Total number of threats in the system. | 
| SentinelOne.Threat.NotMitigated | Number | Number of unmitigated threats in the system. | 
| SentinelOne.Threat.MaliciousNotResolved | Number | Number of unresolved malicious threats in the system. | 
| SentinelOne.Threat.NotMitigatedNotResolved | Number | Number of unmitigated and unresolved threats in the system. | 


#### Command Example
```!sentinelone-threat-summary group_ids="475482421375111234,764073410272411234"```

#### Context Example
```
{
    "SentinelOne": {
        "Threat": {
            "InProgress": 0,
            "MaliciousNotResolved": 0,
            "NotMitigated": 0,
            "NotMitigatedNotResolved": 0,
            "NotResolved": 0,
            "Resolved": 16,
            "SuspiciousNotMitigatedNotResolved": 0,
            "SuspiciousNotResolved": 0,
            "Total": 16
        }
    }
}
```

#### Human Readable Output

>### Sentinel One - Dashboard Threat Summary
>|In Progress|Malicious Not Resolved|Not Mitigated|Not Mitigated Not Resolved|Not Resolved|Resolved|Suspicious - Not Mitigated Not Resolved|Suspicious Not Resolved|Total|
>|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 0 | 0 | 16 | 0 | 0 | 16 |


### sentinelone-mitigate-threat
***
Applies a mitigation action to a group of threats that match the specified input filter. Valid values for mitigation- "kill", "quarantine", "remediate", "rollback", "disconnectFromNetwork". Rollback is applied only on Windows. Remediate is applied only on macOS and Windows.


#### Base Command

`sentinelone-mitigate-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Mitigation action. Can be "kill", "quarantine", "un-quarantine", "remediate", or "rollback-remediation". | Required | 
| threat_ids | CSV list of threat IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Mitigated | Boolean | Whether the threat was successfully mitigated. | 
| SentinelOne.Threat.Mitigation.Action | Number | Number of threats affected. | 


#### Command Example
``` ```

#### Human Readable Output



### sentinelone-get-agent
***
Returns details of an agent, by agent ID.


#### Base Command

`sentinelone-get-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The agent ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.NetworkStatus | string | The agent network status. | 
| SentinelOne.Agent.ID | string | The agent ID. | 
| SentinelOne.Agent.AgentVersion | string | The agent software version. | 
| SentinelOne.Agent.IsDecomissioned | boolean | Whether the agent is decommissioned. | 
| SentinelOne.Agent.IsActive | boolean | Whether the agent is active. | 
| SentinelOne.Agent.LastActiveDate | date | The last active date of the agent. | 
| SentinelOne.Agent.RegisteredAt | date | The registration date of the agent. | 
| SentinelOne.Agent.ExternalIP | string | The agent IP address. | 
| SentinelOne.Agent.ThreatCount | number | Number of active threats. | 
| SentinelOne.Agent.EncryptedApplications | boolean | Whether disk encryption is enabled. | 
| SentinelOne.Agent.OSName | string | Name of the operating system. | 
| SentinelOne.Agent.ComputerName | string | Name of the agent computer. | 
| SentinelOne.Agent.Domain | string | Domain name of the agent. | 
| SentinelOne.Agent.CreatedAt | date | Agent creation time. | 
| SentinelOne.Agent.SiteName | string | Site name associated with the agent. | 


#### Command Example
```!sentinelone-get-agent agent_id=657613730168121234```

#### Context Example
```
{
    "SentinelOne": {
        "Agent": {
            "AgentVersion": "3.1.3.38",
            "ComputerName": "EC2AMAZ-AJ0KANC",
            "CreatedAt": "2019-06-27T08:01:05.571895Z",
            "Domain": "WORKGROUP",
            "EncryptedApplications": false,
            "ExternalIP": "77.125.26.100",
            "ID": "657613730168121234",
            "IsActive": false,
            "IsDecomissioned": true,
            "LastActiveDate": "2020-02-20T00:26:33.955830Z",
            "NetworkStatus": "connecting",
            "OSName": "Windows Server 2016",
            "RegisteredAt": "2019-06-27T08:01:05.567249Z",
            "SiteName": "demisto",
            "ThreatCount": 0
        }
    }
}
```

#### Human Readable Output

>### Sentinel One - Get Agent Details 
>Provides details for the following agent ID : 657613730168121234
>|Agent Version|Computer Name|Created At|Domain|Encrypted Applications|External IP|ID|Is Active|Is Decomissioned|Last ActiveDate|Network Status|OS Name|Registered At|Site Name|Threat Count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3.1.3.38 | EC2AMAZ-AJ0KANC | 2019-06-27T08:01:05.571895Z | WORKGROUP | false | 77.125.26.100 | 657613730168121234 | false | true | 2020-02-20T00:26:33.955830Z | connecting | Windows Server 2016 | 2019-06-27T08:01:05.567249Z | demisto | 0 |


### sentinelone-get-sites
***
Returns all sites that match the specified criteria.


#### Base Command

`sentinelone-get-sites`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| updated_at | Timestamp of last update, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| query | Full-text search for fields: name, account_name. | Optional | 
| site_type | Site type. Can be "Trial", "Paid", "POC", "DEV", or "NFR". | Optional | 
| features | Returns sites that support the specified features. Can be "firewall-control", "device-control", or "ioc". | Optional | 
| state | Site state. Can be "active", "deleted", or "expired". | Optional | 
| suite | The suite of product features active for this site. Can be "Core" or "Complete". | Optional | 
| admin_only | Sites to which the user has Admin privileges. | Optional | 
| account_id | Account ID, for example: "225494730938493804". | Optional | 
| site_name | Site name, for example: "My Site". | Optional | 
| created_at | Timestamp of site creation, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| limit | Maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.Creator | string | The creator name. | 
| SentinelOne.Site.Name | string | The site name. | 
| SentinelOne.Site.Type | string | The site type. | 
| SentinelOne.Site.AccountName | string | The account name. | 
| SentinelOne.Site.State | string | The site state. | 
| SentinelOne.Site.HealthStatus | boolean | The health status of the site. | 
| SentinelOne.Site.Sku | string | The sku of product features active for this site. | 
| SentinelOne.Site.ActiveLicenses | number | Number of active licenses on the site. | 
| SentinelOne.Site.ID | string | ID of the site. | 
| SentinelOne.Site.TotalLicenses | number | Number of total licenses on the site. | 
| SentinelOne.Site.CreatedAt | date | Timestamp when the site was created. | 
| SentinelOne.Site.Expiration | string | Timestamp when the site will expire. | 
| SentinelOne.Site.UnlimitedLicenses | boolean | Whether the site has unlimited licenses. | 


#### Command Example
``` ```

#### Human Readable Output



### sentinelone-get-site
***
Returns a site, by site ID.


#### Base Command

`sentinelone-get-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.Creator | string | The creator name. | 
| SentinelOne.Site.Name | string | The site name. | 
| SentinelOne.Site.Type | string | The site type. | 
| SentinelOne.Site.AccountName | string | The account name. | 
| SentinelOne.Site.State | string | The site state. | 
| SentinelOne.Site.HealthStatus | boolean | The health status of the site. | 
| SentinelOne.Site.Suite | string | The suite to which the site belongs. | 
| SentinelOne.Site.ActiveLicenses | number | Number of active licenses on the site. | 
| SentinelOne.Site.ID | string | ID of the site. | 
| SentinelOne.Site.TotalLicenses | number | Number of total licenses on the site. | 
| SentinelOne.Site.CreatedAt | date | Timestamp when the site was created. | 
| SentinelOne.Site.Expiration | string | Timestamp when the site will expire. | 
| SentinelOne.Site.UnlimitedLicenses | boolean | Unlimited licenses boolean. | 
| SentinelOne.Site.AccountID | string | Account ID. | 
| SentinelOne.Site.IsDefault | boolean | Whether the site is the default site. | 


#### Command Example
```!sentinelone-get-site site_id=475482421366721234```

#### Context Example
```
{
    "SentinelOne": {
        "Site": {
            "AccountID": "433241117337583618",
            "AccountName": "SentinelOne",
            "ActiveLicenses": 0,
            "CreatedAt": "2018-10-19T00:58:41.644879Z",
            "Creator": "John Roh",
            "Expiration": null,
            "HealthStatus": true,
            "ID": "475482421366721234",
            "IsDefault": false,
            "Name": "demisto",
            "State": "active",
            "Suite": "Complete",
            "TotalLicenses": 0,
            "Type": "Paid",
            "UnlimitedLicenses": true
        }
    }
}
```

#### Human Readable Output

>### Sentinel One - Summary About Site: 475482421366721234
>Provides summary information and details for specific site ID
>|Account Name|AccountID|Active Licenses|Created At|Creator|Health Status|ID|IsDefault|Name|Sku|State|Total Licenses|Type|Unlimited Licenses|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| SentinelOne | 433241117337583618 | 0 | 2018-10-19T00:58:41.644879Z | John Roh | true | 475482421366721234 | false | demisto | Complete | active | 0 | Paid | true |


### sentinelone-reactivate-site
***
Reactivates an expired site.


#### Base Command

`sentinelone-reactivate-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Site ID. Example: "225494730938493804". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.ID | string | Site ID. | 
| SentinelOne.Site.Reactivated | boolean | Whether the site was reactivated. | 


#### Command Example
``` ```

#### Human Readable Output



### sentinelone-expire-site
***
Expires a site.


#### Base Command

`sentinelone-expire-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Site ID of the site to expire, for example: "225494730938493804". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.ID | String | ID of the site. | 
| SentinelOne.Site.Expired | Boolean | A boolean to check if the site was expired or not. | 


#### Command Example
``` ```

#### Human Readable Output



### sentinelone-get-activities
***
Returns a list of activities.


#### Base Command

`sentinelone-get-activities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_after | Return activities created after this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| user_emails | Email address of the user who invoked the activity (if applicable). | Optional | 
| group_ids | List of Group IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| created_until | Return activities created on or before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| include_hidden | Include internal activities hidden from display, for example: "False". | Optional | 
| activities_ids | CSV list of activity IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| created_before | Return activities created before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| threats_ids | CSV list of threat IDs for which to return activities, for example: "225494730938493804,225494730938493915". | Optional | 
| activity_types | CSV of activity codes to return, for example: "52,53,71,72". | Optional | 
| user_ids | CSV list of user IDs for users that invoked the activity (if applicable), for example: "225494730938493804,225494730938493915". | Optional | 
| created_from | Return activities created on or after this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_between | Return activities created within this range (inclusive), for example: "1514978764288-1514978999999". | Optional | 
| agent_ids | Return activities related to specified agents. Example: "225494730938493804,225494730938493915". | Optional | 
| limit | Maximum number of items to return (1-100). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Activity.AgentID | String | Related agent \(if applicable\). | 
| SentinelOne.Activity.AgentUpdatedVersion | String | Agent's new version \(if applicable\). | 
| SentinelOne.Activity.SiteID | String | Related site \(if applicable\). | 
| SentinelOne.Activity.UserID | String | The user who invoked the activity \(if applicable\). | 
| SentinelOne.Activity.SecondaryDescription | String | Secondary description. | 
| SentinelOne.Activity.OsFamily | String | Agent's OS type \(if applicable\). Can be "linux", "macos", "windows", or "windows_legacy". | 
| SentinelOne.Activity.ActivityType | Number | Activity type. | 
| SentinelOne.Activity.data.SiteID | String | The site ID. | 
| SentinelOne.Activity.data.SiteName | String | The site name. | 
| SentinelOne.Activity.data.username | String | The name of the site creator. | 
| SentinelOne.Activity.Hash | String | Threat file hash \(if applicable\). | 
| SentinelOne.Activity.UpdatedAt | Date | Activity last updated time \(UTC\). | 
| SentinelOne.Activity.Comments | String | Comments for the activity. | 
| SentinelOne.Activity.ThreatID | String | Related threat \(if applicable\). | 
| SentinelOne.Activity.PrimaryDescription | String | Primary description for the activity. | 
| SentinelOne.Activity.GroupID | String | Related group \(if applicable\). | 
| SentinelOne.Activity.ID | String | Activity ID. | 
| SentinelOne.Activity.CreatedAt | Date | Activity creation time \(UTC\). | 
| SentinelOne.Activity.Description | String | Extra activity information. | 


#### Command Example
```!sentinelone-get-activities```

#### Context Example
```
{
    "SentinelOne": {
        "Activity": [
            {
                "ActivityType": 27,
                "AgentID": null,
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-09T15:18:22.012957Z",
                "Data": {
                    "role": "admin",
                    "source": "mgmt",
                    "userScope": "site",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": null,
                "Hash": null,
                "ID": "711467221495908564",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe logged into the management console.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-09T15:18:22.012964Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 27,
                "AgentID": null,
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-10T06:23:53.061460Z",
                "Data": {
                    "role": "admin",
                    "source": "mgmt",
                    "userScope": "site",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": null,
                "Hash": null,
                "ID": "711922983359810824",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe logged into the management console.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-10T06:23:53.061467Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 61,
                "AgentID": "657738871640371234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-10T06:43:50.243220Z",
                "Data": {
                    "computerName": "TLVWIN9131Q1V",
                    "username": "John Doe",
                    "uuid": "e71ee1c39e4d457997d3f11a3588735c"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "711933026050313492",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a disconnect from network command to the machine TLVWIN9131Q1V.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-10T06:43:50.243226Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 62,
                "AgentID": "657738871640371234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-10T06:46:53.458594Z",
                "Data": {
                    "computerName": "TLVWIN9131Q1V",
                    "username": "John Doe",
                    "uuid": "e71ee1c39e4d457997d3f11a3588735c"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "711934562969128219",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a reconnect to network command to the machine TLVWIN9131Q1V.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-10T06:46:53.458600Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 1001,
                "AgentID": "657738871640371234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-10T07:58:45.399831Z",
                "Data": {
                    "computerName": "TLVWIN9131Q1V"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "711970734160284982",
                "OsFamily": null,
                "PrimaryDescription": "Agent TLVWIN9131Q1V was disconnected from network.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-10T07:58:45.399836Z",
                "UserID": null
            },
            {
                "ActivityType": 1002,
                "AgentID": "657738871640371234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-10T07:58:45.642140Z",
                "Data": {
                    "computerName": "TLVWIN9131Q1V"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "711970736190328121",
                "OsFamily": null,
                "PrimaryDescription": "Agent TLVWIN9131Q1V was connected to network.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-10T07:58:45.642146Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:05:49.119367Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 123490.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715718963184086211",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Unconfirmed 123490.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715718962991148224",
                "UpdatedAt": "2019-09-15T12:05:49.110179Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:05:49.236063Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 123490.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715718964165553351",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 123490.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715718962991148224",
                "UpdatedAt": "2019-09-15T12:05:49.233489Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:05:49.345311Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 123490.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715718965079911627",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 123490.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715718962991148224",
                "UpdatedAt": "2019-09-15T12:05:49.342471Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:42.465051Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": null,
                    "threatClassificationSource": null,
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723437214608611",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723437013282014",
                "UpdatedAt": "2019-09-15T12:14:42.455994Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:42.636463Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723438649060583",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723437013282014",
                "UpdatedAt": "2019-09-15T12:14:42.633622Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:42.987987Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723441601850603",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723437013282014",
                "UpdatedAt": "2019-09-15T12:14:42.982630Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:43.369411Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723444797910255",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723444638526700",
                "UpdatedAt": "2019-09-15T12:14:43.361119Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:43.513702Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723446005869811",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723444638526700",
                "UpdatedAt": "2019-09-15T12:14:43.510748Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:43.792279Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723448346291447",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723444638526700",
                "UpdatedAt": "2019-09-15T12:14:43.789224Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:44.079748Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "ccce727e39cb8d955a323bf2c0419f31fb917e5a",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": null,
                    "threatClassificationSource": null,
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723450753821949",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Ncat Netcat Portable - CHIP-Installer (1).exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723450678324472",
                "UpdatedAt": "2019-09-15T12:14:44.075466Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:44.342020Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "ccce727e39cb8d955a323bf2c0419f31fb917e5a",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723452960025857",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer (1).exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723450678324472",
                "UpdatedAt": "2019-09-15T12:14:44.339257Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T12:14:44.475805Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "ccce727e39cb8d955a323bf2c0419f31fb917e5a",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715723454084099333",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer (1).exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723450678324472",
                "UpdatedAt": "2019-09-15T12:14:44.472176Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:25:49.431050Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": null,
                    "threatClassificationSource": null,
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715789430108532268",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789430024646184",
                "UpdatedAt": "2019-09-15T14:25:49.427079Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:25:49.545617Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715789431064833585",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789430024646184",
                "UpdatedAt": "2019-09-15T14:25:49.542808Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:25:49.657886Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715789432012746293",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789430024646184",
                "UpdatedAt": "2019-09-15T14:25:49.654572Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:25:49.966563Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715789434604826169",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789434420276790",
                "UpdatedAt": "2019-09-15T14:25:49.957011Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:25:50.079828Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715789435552738877",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789434420276790",
                "UpdatedAt": "2019-09-15T14:25:50.077241Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:25:50.187499Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Static"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715789436450319937",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789434420276790",
                "UpdatedAt": "2019-09-15T14:25:50.184581Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:35:38.144114Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 117897.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715794368591113805",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Unconfirmed 117897.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794368498839113",
                "UpdatedAt": "2019-09-15T14:35:38.138786Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:35:38.257438Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 117897.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715794369539026512",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 117897.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794368498839113",
                "UpdatedAt": "2019-09-15T14:35:38.254506Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:35:38.363722Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 117897.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715794370428218964",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 117897.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794368498839113",
                "UpdatedAt": "2019-09-15T14:35:38.360685Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:35:44.201366Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 537649.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715794419400912476",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Unconfirmed 537649.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794419300249176",
                "UpdatedAt": "2019-09-15T14:35:44.195242Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:35:44.314248Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 537649.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715794420348825183",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 537649.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794419300249176",
                "UpdatedAt": "2019-09-15T14:35:44.309884Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:35:44.421959Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 537649.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715794421254794851",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 537649.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794419300249176",
                "UpdatedAt": "2019-09-15T14:35:44.418695Z",
                "UserID": null
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631011Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803272989453948",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789430024646184",
                "UpdatedAt": "2019-09-15T14:53:19.631015Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631019Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803272997842557",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723437013282014",
                "UpdatedAt": "2019-09-15T14:53:19.631022Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631025Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803273006231166",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723444638526700",
                "UpdatedAt": "2019-09-15T14:53:19.631027Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631030Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "ccce727e39cb8d955a323bf2c0419f31fb917e5a",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803273006231167",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer (1).exe on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer (1).exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715723450678324472",
                "UpdatedAt": "2019-09-15T14:53:19.631033Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631036Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 117897.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803273014619776",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Unconfirmed 117897.crdownload on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 117897.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794368498839113",
                "UpdatedAt": "2019-09-15T14:53:19.631038Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631041Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 123490.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803273023008385",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Unconfirmed 123490.crdownload on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715718962991148224",
                "UpdatedAt": "2019-09-15T14:53:19.631044Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631047Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3e7704f5668bc4330c686ccce2dd6f9969686a2c",
                    "fileDisplayName": "Ncat Netcat Portable - CHIP-Installer.exe",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803273023008386",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "SiteID": "475482421366721234",
                "ThreatID": "715789434420276790",
                "UpdatedAt": "2019-09-15T14:53:19.631049Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 2011,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-15T14:53:19.631052Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 537649.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                    "groupName": "Default Group",
                    "newStatus": null,
                    "originalStatus": "mitigated",
                    "siteName": "demisto",
                    "username": "John Doe"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "715803273031396995",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a kill command to threat Unconfirmed 537649.crdownload on agent EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 537649.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "715794419300249176",
                "UpdatedAt": "2019-09-15T14:53:19.631055Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 62,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:01:50.684456Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "username": "John Doe",
                    "uuid": "f431b0a1a8744d2a8a92fc88fa3c13bc"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716351141811139157",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a reconnect to network command to the machine EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-16T09:01:50.684463Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 62,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:01:52.315393Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "username": "John Doe",
                    "uuid": "f431b0a1a8744d2a8a92fc88fa3c13bc"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716351155492958810",
                "OsFamily": null,
                "PrimaryDescription": "The management user John Doe issued a reconnect to network command to the machine EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-16T09:01:52.315399Z",
                "UserID": "475412345872052394"
            },
            {
                "ActivityType": 1002,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:02:18.732856Z",
                "Data": {
                    "computerName": "EC2AMAZ-AJ0KANC"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716351377103204961",
                "OsFamily": null,
                "PrimaryDescription": "Agent EC2AMAZ-AJ0KANC was connected to network.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-16T09:02:18.730355Z",
                "UserID": null
            },
            {
                "ActivityType": 1002,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:02:18.834921Z",
                "Data": {
                    "computerName": "EC2AMAZ-AJ0KANC"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716351377958842980",
                "OsFamily": null,
                "PrimaryDescription": "Agent EC2AMAZ-AJ0KANC was connected to network.",
                "SecondaryDescription": null,
                "SiteID": "475482421366721234",
                "ThreatID": null,
                "UpdatedAt": "2019-09-16T09:02:18.832350Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:23:27.679230Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 136405.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716362021793772186",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Unconfirmed 136405.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716362021709886102",
                "UpdatedAt": "2019-09-16T09:23:27.674372Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:23:27.791264Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 136405.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716362022733296285",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 136405.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716362021709886102",
                "UpdatedAt": "2019-09-16T09:23:27.788471Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:23:27.897966Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 136405.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716362023630877345",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 136405.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 136405.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716362021709886102",
                "UpdatedAt": "2019-09-16T09:23:27.894651Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:28:54.858074Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 95652.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716364766370149044",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Unconfirmed 95652.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716364766277874352",
                "UpdatedAt": "2019-09-16T09:28:54.852367Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:28:54.966232Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 95652.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716364767276118711",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 95652.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716364766277874352",
                "UpdatedAt": "2019-09-16T09:28:54.963780Z",
                "UserID": null
            },
            {
                "ActivityType": 2004,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:28:55.073453Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 95652.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716364768173699771",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 95652.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 95652.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716364766277874352",
                "UpdatedAt": "2019-09-16T09:28:55.070459Z",
                "UserID": null
            },
            {
                "ActivityType": 19,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:36:02.420411Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 742374.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 742374.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine",
                    "username": null
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716368353020162770",
                "OsFamily": null,
                "PrimaryDescription": "Threat detected, name: Unconfirmed 742374.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 742374.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716368352944665294",
                "UpdatedAt": "2019-09-16T09:36:02.415821Z",
                "UserID": null
            },
            {
                "ActivityType": 2001,
                "AgentID": "657613730168121234",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2019-09-16T09:36:02.531386Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "fileDisplayName": "Unconfirmed 742374.crdownload",
                    "filePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 742374.crdownload",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "threatClassification": "Malware",
                    "threatClassificationSource": "Engine"
                },
                "Description": null,
                "GroupID": "475482421375111234",
                "Hash": null,
                "ID": "716368353951298261",
                "OsFamily": null,
                "PrimaryDescription": "The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 742374.crdownload.",
                "SecondaryDescription": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 742374.crdownload",
                "SiteID": "475482421366721234",
                "ThreatID": "716368352944665294",
                "UpdatedAt": "2019-09-16T09:36:02.528381Z",
                "UserID": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Sentinel One Activities
>|ID|Primary description|Data|User ID|Created at|Updated at|Threat ID|
>|---|---|---|---|---|---|---|
>| 711467221495908564 | The management user John Doe logged into the management console. | role: admin<br/>source: mgmt<br/>userScope: site<br/>username: John Doe | 475412345872052394 | 2019-09-09T15:18:22.012957Z | 2019-09-09T15:18:22.012964Z |  |
>| 711922983359810824 | The management user John Doe logged into the management console. | role: admin<br/>source: mgmt<br/>userScope: site<br/>username: John Doe | 475412345872052394 | 2019-09-10T06:23:53.061460Z | 2019-09-10T06:23:53.061467Z |  |
>| 711933026050313492 | The management user John Doe issued a disconnect from network command to the machine TLVWIN9131Q1V. | computerName: TLVWIN9131Q1V<br/>username: John Doe<br/>uuid: e71ee1c39e4d457997d3f11a3588735c | 475412345872052394 | 2019-09-10T06:43:50.243220Z | 2019-09-10T06:43:50.243226Z |  |
>| 711934562969128219 | The management user John Doe issued a reconnect to network command to the machine TLVWIN9131Q1V. | computerName: TLVWIN9131Q1V<br/>username: John Doe<br/>uuid: e71ee1c39e4d457997d3f11a3588735c | 475412345872052394 | 2019-09-10T06:46:53.458594Z | 2019-09-10T06:46:53.458600Z |  |
>| 711970734160284982 | Agent TLVWIN9131Q1V was disconnected from network. | computerName: TLVWIN9131Q1V |  | 2019-09-10T07:58:45.399831Z | 2019-09-10T07:58:45.399836Z |  |
>| 711970736190328121 | Agent TLVWIN9131Q1V was connected to network. | computerName: TLVWIN9131Q1V |  | 2019-09-10T07:58:45.642140Z | 2019-09-10T07:58:45.642146Z |  |
>| 715718963184086211 | Threat detected, name: Unconfirmed 123490.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 123490.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 123490.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine<br/>username: null |  | 2019-09-15T12:05:49.119367Z | 2019-09-15T12:05:49.110179Z | 715718962991148224 |
>| 715718964165553351 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 123490.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 123490.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 123490.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-15T12:05:49.236063Z | 2019-09-15T12:05:49.233489Z | 715718962991148224 |
>| 715718965079911627 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 123490.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 123490.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 123490.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-15T12:05:49.345311Z | 2019-09-15T12:05:49.342471Z | 715718962991148224 |
>| 715723437214608611 | Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: null<br/>threatClassificationSource: null<br/>username: null |  | 2019-09-15T12:14:42.465051Z | 2019-09-15T12:14:42.455994Z | 715723437013282014 |
>| 715723438649060583 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T12:14:42.636463Z | 2019-09-15T12:14:42.633622Z | 715723437013282014 |
>| 715723441601850603 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T12:14:42.987987Z | 2019-09-15T12:14:42.982630Z | 715723437013282014 |
>| 715723444797910255 | Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static<br/>username: null |  | 2019-09-15T12:14:43.369411Z | 2019-09-15T12:14:43.361119Z | 715723444638526700 |
>| 715723446005869811 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T12:14:43.513702Z | 2019-09-15T12:14:43.510748Z | 715723444638526700 |
>| 715723448346291447 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T12:14:43.792279Z | 2019-09-15T12:14:43.789224Z | 715723444638526700 |
>| 715723450753821949 | Threat detected, name: Ncat Netcat Portable - CHIP-Installer (1).exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: ccce727e39cb8d955a323bf2c0419f31fb917e5a<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer (1).exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer (1).exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: null<br/>threatClassificationSource: null<br/>username: null |  | 2019-09-15T12:14:44.079748Z | 2019-09-15T12:14:44.075466Z | 715723450678324472 |
>| 715723452960025857 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer (1).exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: ccce727e39cb8d955a323bf2c0419f31fb917e5a<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer (1).exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer (1).exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T12:14:44.342020Z | 2019-09-15T12:14:44.339257Z | 715723450678324472 |
>| 715723454084099333 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer (1).exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: ccce727e39cb8d955a323bf2c0419f31fb917e5a<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer (1).exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer (1).exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T12:14:44.475805Z | 2019-09-15T12:14:44.472176Z | 715723450678324472 |
>| 715789430108532268 | Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: null<br/>threatClassificationSource: null<br/>username: null |  | 2019-09-15T14:25:49.431050Z | 2019-09-15T14:25:49.427079Z | 715789430024646184 |
>| 715789431064833585 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T14:25:49.545617Z | 2019-09-15T14:25:49.542808Z | 715789430024646184 |
>| 715789432012746293 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T14:25:49.657886Z | 2019-09-15T14:25:49.654572Z | 715789430024646184 |
>| 715789434604826169 | Threat detected, name: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static<br/>username: null |  | 2019-09-15T14:25:49.966563Z | 2019-09-15T14:25:49.957011Z | 715789434420276790 |
>| 715789435552738877 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T14:25:50.079828Z | 2019-09-15T14:25:50.077241Z | 715789434420276790 |
>| 715789436450319937 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Ncat Netcat Portable - CHIP-Installer.exe. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Static |  | 2019-09-15T14:25:50.187499Z | 2019-09-15T14:25:50.184581Z | 715789434420276790 |
>| 715794368591113805 | Threat detected, name: Unconfirmed 117897.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 117897.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 117897.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine<br/>username: null |  | 2019-09-15T14:35:38.144114Z | 2019-09-15T14:35:38.138786Z | 715794368498839113 |
>| 715794369539026512 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 117897.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 117897.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 117897.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-15T14:35:38.257438Z | 2019-09-15T14:35:38.254506Z | 715794368498839113 |
>| 715794370428218964 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 117897.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 117897.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 117897.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-15T14:35:38.363722Z | 2019-09-15T14:35:38.360685Z | 715794368498839113 |
>| 715794419400912476 | Threat detected, name: Unconfirmed 537649.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 537649.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 537649.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine<br/>username: null |  | 2019-09-15T14:35:44.201366Z | 2019-09-15T14:35:44.195242Z | 715794419300249176 |
>| 715794420348825183 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 537649.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 537649.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 537649.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-15T14:35:44.314248Z | 2019-09-15T14:35:44.309884Z | 715794419300249176 |
>| 715794421254794851 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 537649.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 537649.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 537649.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-15T14:35:44.421959Z | 2019-09-15T14:35:44.418695Z | 715794419300249176 |
>| 715803272989453948 | The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631011Z | 2019-09-15T14:53:19.631015Z | 715789430024646184 |
>| 715803272997842557 | The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631019Z | 2019-09-15T14:53:19.631022Z | 715723437013282014 |
>| 715803273006231166 | The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: d8757a0396d05a1d532422827a70a7966c361366<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631025Z | 2019-09-15T14:53:19.631027Z | 715723444638526700 |
>| 715803273006231167 | The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer (1).exe on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: ccce727e39cb8d955a323bf2c0419f31fb917e5a<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer (1).exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer (1).exe<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631030Z | 2019-09-15T14:53:19.631033Z | 715723450678324472 |
>| 715803273014619776 | The management user John Doe issued a kill command to threat Unconfirmed 117897.crdownload on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 117897.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 117897.crdownload<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631036Z | 2019-09-15T14:53:19.631038Z | 715794368498839113 |
>| 715803273023008385 | The management user John Doe issued a kill command to threat Unconfirmed 123490.crdownload on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 123490.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 123490.crdownload<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631041Z | 2019-09-15T14:53:19.631044Z | 715718962991148224 |
>| 715803273023008386 | The management user John Doe issued a kill command to threat Ncat Netcat Portable - CHIP-Installer.exe on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3e7704f5668bc4330c686ccce2dd6f9969686a2c<br/>fileDisplayName: Ncat Netcat Portable - CHIP-Installer.exe<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Ncat Netcat Portable - CHIP-Installer.exe<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631047Z | 2019-09-15T14:53:19.631049Z | 715789434420276790 |
>| 715803273031396995 | The management user John Doe issued a kill command to threat Unconfirmed 537649.crdownload on agent EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 537649.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 537649.crdownload<br/>groupName: Default Group<br/>newStatus: null<br/>originalStatus: mitigated<br/>siteName: demisto<br/>username: John Doe | 475412345872052394 | 2019-09-15T14:53:19.631052Z | 2019-09-15T14:53:19.631055Z | 715794419300249176 |
>| 716351141811139157 | The management user John Doe issued a reconnect to network command to the machine EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>groupName: Default Group<br/>siteName: demisto<br/>username: John Doe<br/>uuid: f431b0a1a8744d2a8a92fc88fa3c13bc | 475412345872052394 | 2019-09-16T09:01:50.684456Z | 2019-09-16T09:01:50.684463Z |  |
>| 716351155492958810 | The management user John Doe issued a reconnect to network command to the machine EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>groupName: Default Group<br/>siteName: demisto<br/>username: John Doe<br/>uuid: f431b0a1a8744d2a8a92fc88fa3c13bc | 475412345872052394 | 2019-09-16T09:01:52.315393Z | 2019-09-16T09:01:52.315399Z |  |
>| 716351377103204961 | Agent EC2AMAZ-AJ0KANC was connected to network. | computerName: EC2AMAZ-AJ0KANC |  | 2019-09-16T09:02:18.732856Z | 2019-09-16T09:02:18.730355Z |  |
>| 716351377958842980 | Agent EC2AMAZ-AJ0KANC was connected to network. | computerName: EC2AMAZ-AJ0KANC |  | 2019-09-16T09:02:18.834921Z | 2019-09-16T09:02:18.832350Z |  |
>| 716362021793772186 | Threat detected, name: Unconfirmed 136405.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 136405.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 136405.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine<br/>username: null |  | 2019-09-16T09:23:27.679230Z | 2019-09-16T09:23:27.674372Z | 716362021709886102 |
>| 716362022733296285 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 136405.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 136405.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 136405.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-16T09:23:27.791264Z | 2019-09-16T09:23:27.788471Z | 716362021709886102 |
>| 716362023630877345 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 136405.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 136405.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 136405.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-16T09:23:27.897966Z | 2019-09-16T09:23:27.894651Z | 716362021709886102 |
>| 716364766370149044 | Threat detected, name: Unconfirmed 95652.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 95652.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 95652.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine<br/>username: null |  | 2019-09-16T09:28:54.858074Z | 2019-09-16T09:28:54.852367Z | 716364766277874352 |
>| 716364767276118711 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 95652.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 95652.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 95652.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-16T09:28:54.966232Z | 2019-09-16T09:28:54.963780Z | 716364766277874352 |
>| 716364768173699771 | The agent EC2AMAZ-AJ0KANC successfully quarantined the threat: Unconfirmed 95652.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 95652.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 95652.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-16T09:28:55.073453Z | 2019-09-16T09:28:55.070459Z | 716364766277874352 |
>| 716368353020162770 | Threat detected, name: Unconfirmed 742374.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 742374.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 742374.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine<br/>username: null |  | 2019-09-16T09:36:02.420411Z | 2019-09-16T09:36:02.415821Z | 716368352944665294 |
>| 716368353951298261 | The agent EC2AMAZ-AJ0KANC successfully killed the threat: Unconfirmed 742374.crdownload. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140<br/>fileDisplayName: Unconfirmed 742374.crdownload<br/>filePath: \Device\HarddiskVolume1\Users\Administrator\Downloads\Unconfirmed 742374.crdownload<br/>groupName: Default Group<br/>siteName: demisto<br/>threatClassification: Malware<br/>threatClassificationSource: Engine |  | 2019-09-16T09:36:02.531386Z | 2019-09-16T09:36:02.528381Z | 716368352944665294 |


### sentinelone-get-groups
***
Returns data for the specified group.


#### Base Command

`sentinelone-get-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | Group type, for example: "static". | Optional | 
| group_ids | CSV list of group IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| group_id | Group ID by which to filter, for example: "225494730938493804". | Optional | 
| is_default | Whether this is the default group. | Optional | 
| name | The name of the group. | Optional | 
| query | Free-text search on fields name. | Optional | 
| rank | The rank sets the priority of a dynamic group over others, for example, "1", which is the highest priority. | Optional | 
| limit | Maximum number of items to return (1-200). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Group.siteId | String | The ID of the site of which this group is a member. | 
| SentinelOne.Group.filterName | String | If the group is dynamic, the name of the filter which is used to associate agents. | 
| SentinelOne.Group.creatorId | String | The ID of the user that created the group. | 
| SentinelOne.Group.name | String | The name of the group. | 
| SentinelOne.Group.creator | String | The user that created the group. | 
| SentinelOne.Group.rank | Number | The rank, which sets the priority of a dynamic group over others. | 
| SentinelOne.Group.updatedAt | Date | Timestamp of the last update. | 
| SentinelOne.Group.totalAgents | Number | Number of agents in the group. | 
| SentinelOne.Group.filterId | String | If the group is dynamic, the group ID of the filter that is used to associate agents. | 
| SentinelOne.Group.isDefault | Boolean | Whether the groups is the default group of the site. | 
| SentinelOne.Group.inherits | Boolean | Whether the policy is inherited from a site. "False" if the group has its own edited policy. | 
| SentinelOne.Group.type | String | Group type. Can be static or dynamic | 
| SentinelOne.Group.id | String | The ID of the group. | 
| SentinelOne.Group.createdAt | Date | Timestamp of group creation. | 


#### Command Example
```!sentinelone-get-groups```

#### Context Example
```
{
    "SentinelOne": {
        "Group": [
            {
                "createdAt": "2018-10-19T00:58:41.646045Z",
                "creator": "John Roh",
                "creatorId": "433273625970231234",
                "filterId": null,
                "filterName": null,
                "id": "475482421375111234",
                "inherits": true,
                "isDefault": true,
                "name": "Default Group",
                "rank": null,
                "registrationToken": "eyJ1cmwiOiAiaHR0cHM6Ly91c2VhMS1wYXJCAic2l0ZV9rZXkiOiAiZ184NjJiYWQzNTIwN2ZmNTJmIn0=",
                "siteId": "475482421366721234",
                "totalAgents": 0,
                "type": "static",
                "updatedAt": "2019-11-21T05:19:48.201079Z"
            },
            {
                "createdAt": "2019-11-21T05:17:28.403556Z",
                "creator": "John Doe",
                "creatorId": "475412345872052394",
                "filterId": null,
                "filterName": null,
                "id": "764073410272411234",
                "inherits": false,
                "isDefault": false,
                "name": "Edward",
                "rank": null,
                "registrationToken": "eyJ1cmwiOiAiaHR0cHM6Ly91c2VhMS1wYXLCAic2l0ZV9rZXkiOiAiZ183OTY2NThlNzcyNGU4MjY3In0=",
                "siteId": "475482421366721234",
                "totalAgents": 0,
                "type": "static",
                "updatedAt": "2019-11-21T05:19:48.201079Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Sentinel One Groups
>|ID|Name|Type|Creator|Creator ID|Created at|
>|---|---|---|---|---|---|
>| 475482421375111234 | Default Group | static | John Roh | 433273625970231234 | 2018-10-19T00:58:41.646045Z |
>| 764073410272411234 | Edward | static | John Doe | 475412345872052394 | 2019-11-21T05:17:28.403556Z |


### sentinelone-move-agent
***
Moves agents to a new group.


#### Base Command

`sentinelone-move-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to move the agent to. | Required | 
| agents_ids | Agents IDs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.AgentsMoved | Number | The number of agents that were moved to another group. | 


### sentinelone-delete-group
***
Deletes a group, by the group ID.


#### Base Command

`sentinelone-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !sentinelone-delete-group group_id=661564034148420567```

#### Human Readable Output
>The group was deleted successfully


### sentinelone-agent-processes
***
Retrieves running processes for a specific agent.


#### Base Command

`sentinelone-agent-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agents_ids | The ID of the agent from which to retrieve the processes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.memoryUsage | Number | Memory usage \(MB\). | 
| SentinelOne.Agent.startTime | Date | The process start time. | 
| SentinelOne.Agent.pid | Number | The process ID. | 
| SentinelOne.Agent.processName | String | The name of the process. | 
| SentinelOne.Agent.cpuUsage | Number | CPU usage \(%\). | 
| SentinelOne.Agent.executablePath | String | Executable path. | 


#### Command Example
```!sentinelone-agent-processes agents_ids=657613730168121234```


### sentinelone-connect-agent
***
Connects agents to network.


#### Base Command

`sentinelone-connect-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | A CSV list of agent IDs to connect to the network. Run the list-agents command to get a list of agent IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.AgentsAffected | Number | The number of affected agents. | 
| SentinelOne.Agent.ID | String | The IDs of the affected agents. | 


#### Command Example
```!sentinelone-connect-agent agent_id=657613730168121234```

#### Context Example
```
{
    "SentinelOne": {
        "Agent": {
            "ID": "657613730168121234",
            "NetworkStatus": "connecting"
        }
    }
}
```

#### Human Readable Output

>1 agent(s) successfully connected to the network.

### sentinelone-disconnect-agent
***
Disconnects agents from network.


#### Base Command

`sentinelone-disconnect-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | A CSV list of agent IDs to disconnect from the network. Run the list-agents command to get a list of agent IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.NetworkStatus | String | Agent network status. | 
| SentinelOne.Agent.ID | String | The IDs of the affected agents. | 


#### Command Example
```!sentinelone-disconnect-agent agent_id=657613730168121234```

#### Context Example
```
{
    "SentinelOne": {
        "Agent": {
            "ID": "657613730168121234",
            "NetworkStatus": "disconnecting"
        }
    }
}
```

#### Human Readable Output

>1 agent(s) successfully disconnected from the network.

### sentinelone-broadcast-message
***
Broadcasts a message to all agents that match the input filters.


#### Base Command

`sentinelone-broadcast-message`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The Message to broadcast to agents. | Required | 
| active_agent | Whether to only include active agents. Default is "false". | Optional | 
| group_id | List of Group IDs by which to filter the results. | Optional | 
| agent_id | A list of Agent IDs by which to filter the results. | Optional | 
| domain | Included network domains. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sentinelone-broadcast-message message="Hey There, just checking" agent_id=657613730168121234```

#### Human Readable Output

>The message was successfully delivered to the agent(s)

### sentinelone-get-events
***
Returns all Deep Visibility events that match the query.


#### Base Command

`sentinelone-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of items to return (1-100). Default is "50". | Optional | 
| query_id | QueryId obtained when creating a query in the sentinelone-create-query command. Example: "q1xx2xx3". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Event.ProcessUID | String | Process unique identifier. | 
| SentinelOne.Event.SHA256 | String | SHA256 hash of the file. | 
| SentinelOne.Event.AgentOS | String | OS type. Can be "windows", "linux", "macos", or "windows_legac". | 
| SentinelOne.Event.ProcessID | Number | The process ID. | 
| SentinelOne.Event.User | String | User assigned to the event. | 
| SentinelOne.Event.Time | Date | Process start time. | 
| SentinelOne.Event.Endpoint | String | The agent name. | 
| SentinelOne.Event.SiteName | String | Site name. | 
| SentinelOne.Event.EventType | String | Event type. Can be "events", "file", "ip", "url", "dns", "process", "registry", "scheduled_task", or "logins". | 
| SentinelOne.Event.ProcessName | String | The name of the process. | 
| SentinelOne.Event.MD5 | String | MD5 hash of the file. | 
| Event.ID | String | Event process ID. | 
| Event.Name | String | Event name. | 
| Event.Type | String | Event type. | 


#### Command Example
```!sentinelone-get-events query_id=q6673e283b47a28083e2bc3e768e6f423```

#### Context Example
```
{
    "Event": [
        {
            "Type": "process", 
            "ID": "5556", 
            "Name": "svchost.exe"
        }, 
        {
            "Type": "process", 
            "ID": "5432", 
            "Name": "VSSVC.exe"
        }
    ], 
    "SentinelOne.Event": [
        {
            "ProcessID": "5556", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "process", 
            "ProcessUID": "10EEF25AF81502CD", 
            "ProcessName": "svchost.exe", 
            "User": null, 
            "Time": "2019-08-04T04:48:36.440Z", 
            "SHA256": "438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7", 
            "AgentOS": "windows", 
            "MD5": "36f670d89040709013f6a460176767ec"
        }, 
        {
            "ProcessID": "5432", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "process", 
            "ProcessUID": "DAB10F03FC995CCA", 
            "ProcessName": "VSSVC.exe", 
            "User": null, 
            "Time": "2019-08-04T04:48:26.439Z", 
            "SHA256": "29c18ccdb5077ee158ee591e2226f2c95d27a0f26f259c16c621ecc20b499bed", 
            "AgentOS": "windows", 
            "MD5": "adf381b23416fd54d5dbb582dbb7992d"
        }
    ]
}
```

#### Human Readable Output
| **EventType** | **SiteName** | **Time** | **AgentOS** | **ProcessID** | **ProcessUID** | **ProcessName** | **MD5** | **SHA256** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| process | demisto | 2019-08-04T04:48:36.440Z | windows | 5556 | 10EEF25AF81502CD | svchost.exe | 36f670d89040709013f6a460176767ec | 438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7 |
| process | demisto | 2019-08-04T04:48:26.439Z | windows | 5432 | DAB10F03FC995CCA | VSSVC.exe | adf381b23416fd54d5dbb582dbb7992d | 29c18ccdb5077ee158ee591e2226f2c95d27a0f26f259c16c621ecc20b499bed |

### sentinelone-create-query
***
Runs a Deep Visibility Query and returns the queryId. You can use the queryId for all other commands, such as the sentinelone-get-events command.


#### Base Command

`sentinelone-create-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string for which to return events. | Required | 
| from_date | Query start date, for example, "2019-08-03T04:49:26.257525Z". | Required | 
| to_date | Query end date, for example, "2019-08-03T04:49:26.257525Z". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Query.FromDate | Date | Query start date. | 
| SentinelOne.Query.Query | String | The search query string. | 
| SentinelOne.Query.QueryID | String | The query ID. | 
| SentinelOne.Query.ToDate | Date | Query end date. | 


#### Command Example
```!sentinelone-create-query query="AgentName Is Not Empty" from_date="2020-06-30T15:24:09.257Z" to_date="2020-08-05T04:49:26.257525Z"```

#### Context Example
```
{
    "SentinelOne": {
        "Query": {
            "FromDate": "2020-06-30T15:24:09.257Z",
            "Query": "AgentName Is Not Empty",
            "QueryID": "qe58d14b9f1ca297fc1ccbd09deacc4bc",
            "ToDate": "2020-08-05T04:49:26.257525Z"
        }
    }
}
```

#### Human Readable Output

>The query ID is qe58d14b9f1ca297fc1ccbd09deacc4bc

### sentinelone-get-processes
***
Returns a list of Deep Visibility events from query by event type - process.


#### Base Command

`sentinelone-get-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The queryId that is returned when creating a query under Create Query. Example: "q1xx2xx3". Get the query_id from the "get-query-id" command. | Required | 
| limit | Maximum number of items to return (1-100). Default is "50". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Event.ParentProcessID | Number | Parent process ID. | 
| SentinelOne.Event.ProcessUID | String | The process unique identifier. | 
| SentinelOne.Event.SHA1 | String | SHA1 hash of the process image. | 
| SentinelOne.Event.SubsystemType | String | Process sub-system. | 
| SentinelOne.Event.ParentProcessStartTime | Date | The parent process start time. | 
| SentinelOne.Event.ProcessID | Number | The process ID. | 
| SentinelOne.Event.ParentProcessUID | String | Parent process unique identifier. | 
| SentinelOne.Event.User | String | User assigned to the event. | 
| SentinelOne.Event.Time | Date | Start time of the process. | 
| SentinelOne.Event.ParentProcessName | String | Parent process name. | 
| SentinelOne.Event.SiteName | String | Site name. | 
| SentinelOne.Event.EventType | String | The event type. | 
| SentinelOne.Event.Endpoint | String | The agent name \(endpoint\). | 
| SentinelOne.Event.IntegrityLevel | String | Process integrity level. | 
| SentinelOne.Event.CMD | String | Process CMD. | 
| SentinelOne.Event.ProcessName | String | Process name. | 
| SentinelOne.Event.ProcessDisplayName | String | Process display name. | 


#### Command Example
```!sentinelone-get-processes query_id="q5b327f7c84162549eb1d568c968ff655" ```

#### Context Output
```
{
    "SentinelOne.Event": [
        {
            "ProcessID": "5556", 
            "Time": "2019-08-04T04:48:36.440Z", 
            "CMD": null, 
            "ParentProcessStartTime": "2019-06-27T08:01:30.957Z", 
            "SHA1": "0dac68816ae7c09efc24d11c27c3274dfd147dee", 
            "ParentProcessID": "560", 
            "ProcessDisplayName": "Host Process for Windows Services", 
            "EventType": "process", 
            "ParentProcessName": "Services and Controller app", 
            "SubsystemType": "SYS_WIN32", 
            "ProcessUID": "10EEF25AF81502CD", 
            "ProcessName": "svchost.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "CFEE347DA897CF4C", 
            "IntegrityLevel": "SYSTEM"
        }, 
        {
            "ProcessID": "5432", 
            "Time": "2019-08-04T04:48:26.439Z", 
            "CMD": null, 
            "ParentProcessStartTime": "2019-06-27T08:01:30.957Z", 
            "SHA1": "cd5e7c15e7688d40d51d32b8286c2e1804a97349", 
            "ParentProcessID": "560", 
            "ProcessDisplayName": "Microsoft\u00ae Volume Shadow Copy Service", 
            "EventType": "process", 
            "ParentProcessName": "Services and Controller app", 
            "SubsystemType": "SYS_WIN32", 
            "ProcessUID": "DAB10F03FC995CCA", 
            "ProcessName": "VSSVC.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "CFEE347DA897CF4C", 
            "IntegrityLevel": "SYSTEM"
        }
    ]
}
```
#### Human Readable Output
| **EventType** | **SiteName** | **Time** | **ParentProcessID** | **ParentProcessUID** | **ProcessName** | **ParentProcessName** | **ProcessDisplayName** | **ProcessID** | **ProcessUID** | **SHA1** | **SubsystemType** | **IntegrityLevel** | **ParentProcessStartTime** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| process | demisto | 2019-08-04T04:48:36.440Z | 560 | CFEE347DA897CF4C | svchost.exe | Services and Controller app | Host Process for Windows Services | 5556 | 10EEF25AF81502CD | 0dac68816ae7c09efc24d11c27c3274dfd147dee | SYS_WIN32 | SYSTEM | 2019-06-27T08:01:30.957Z |
| process | demisto | 2019-08-04T04:48:26.439Z | 560 | CFEE347DA897CF4C | VSSVC.exe | Services and Controller app | Microsoft® Volume Shadow Copy Service | 5432 | DAB10F03FC995CCA | cd5e7c15e7688d40d51d32b8286c2e1804a97349 | SYS_WIN32 | SYSTEM | 2019-06-27T08:01:30.957Z |



### sentinelone-shutdown-agent
***
Sends a shutdown command to all agents that match the input filter.


#### Base Command

`sentinelone-shutdown-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text search term, will match applicable attributes (sub-string match). Note: A device's physical addresses will only be matched if they start with the search term  (not if they contain the search term). | Optional | 
| agent_id | A CSV list of agents IDs to shutdown. | Optional | 
| group_id | The ID of the network group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.ID | String | The ID of the agent that was shutdown. | 


#### Command Example
```!sentinelone-shutdown-agent agent_id=685993599961234```

#### Human Readable Output
>Shutting down 1 agent(s).


### sentinelone-uninstall-agent
***
Sends an uninstall command to all agents that match the input filter.


#### Base Command

`sentinelone-uninstall-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text search term, will match applicable attributes (sub-string match). Note: A device's physical addresses will only be matched if they start with the search term  (not if they contain the search term). | Optional | 
| agent_id | A CSV list of agents IDs to shutdown. | Optional | 
| group_id | The ID of the network group. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sentinelone-uninstall-agent agent_id=685993599961234```

#### Human Readable Output
>Uninstall was sent to 1 agent(s).

