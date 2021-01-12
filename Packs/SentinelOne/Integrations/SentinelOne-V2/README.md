Use the SentinelOne integratation to send requests to your Management Server and responds with data pulled from Agents or from the management database.
This integration was integrated and tested with versions 2.0 and 2.1 of SentinelOne
## Configure SentinelOne V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SentinelOne V2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(e.g., https://usea1.sentinelone.net\) | True |
    | token | API Token | True |
    | api_version | API Version. | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | fetch_time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
    | fetch_threat_rank | Minimum risk score for importing incidents \(0-10\), where 0 is low risk and 10 is high risk. Relevant for API version 2.0. | False |
    | fetch_limit | Fetch limit: the maximum number of incidents to fetch | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| scan_status | A comma-separated list of scan statuses by which to filter the results, for example: "started,aborted". Possible values are: started, none, finished, aborted. | Optional | 
| os_type | Included OS types, for example: "windows". Possible values are: windows, windows_legacy, macos, linux. | Optional | 
| created_at | Endpoint created at timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| min_active_threats | Minimum number of threats for an agent. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agents.NetworkStatus | string | The agent network status. | 
| SentinelOne.Agents.ID | string | The agent ID. | 
| SentinelOne.Agents.AgentVersion | string | The agent software version. | 
| SentinelOne.Agents.IsDecommissioned | boolean | Whether the agent is decommissioned. | 
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
```json
{
    "SentinelOne": {
        "Agents": {
            "AgentVersion": "3.1.3.38",
            "ComputerName": "EC2AMAZ-AJ0KANC",
            "CreatedAt": "2019-06-27T08:01:05.571895Z",
            "Domain": "WORKGROUP",
            "EncryptedApplications": false,
            "ExternalIP": "8.88.8.8",
            "ID": "657613730168123595",
            "IsActive": false,
            "IsDecommissioned": true,
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

>### Sentinel One - List of Agents
>Provides summary information and details for all the agents that matched your search criteria
>|Agent Version|Computer Name|Created At|Domain|Encrypted Applications|External IP|ID|Is Active|Is Decommissioned|Last Active Date|Network Status|OS Name|Registered At|Site Name|Threat Count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3.1.3.38 | EC2AMAZ-AJ0KANC | 2019-06-27T08:01:05.571895Z | WORKGROUP | false | 8.88.8.8 | 657613730168123595 | false | true | 2020-02-20T00:26:33.955830Z | connecting | Windows Server 2016 | 2019-06-27T08:01:05.567249Z | demisto | 0 |


### sentinelone-create-white-list-item
***
Creates an exclusion item that matches the specified input filter.


#### Base Command

`sentinelone-create-white-list-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_type | Exclusion item type. Can be "file_type", "path", "white_hash", "certificate", or "browser". Possible values are: file_type, path, white_hash, certificate, browser. | Required | 
| exclusion_value | Value of the exclusion item for the exclusion list. | Required | 
| os_type | OS type. Can be "windows", "windows_legacy", "macos", or "linux". OS type is required for hash exclusions. Possible values are: windows, windows_legacy.macos, linux. | Required | 
| description | Description for adding the item. | Optional | 
| exclusion_mode | Exclusion mode (path exclusion only). Can be "suppress", "disable_in_process_monitor_deep", "disable_in_process_monitor", "disable_all_monitors", or "disable_all_monitors_deep". Possible values are: suppress, disable_in_process_monitor_deep, disable_in_process_monitor, disable_all_monitors, disable_all_monitors_deep. | Optional | 
| path_exclusion_type | Excluded path for a path exclusion list. | Optional | 
| group_ids | A comma-separated list of group IDs by which to filter. Can be "site_ids" or "group_ids". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Exclusions.ID | string | The whitelisted entity ID. | 
| SentinelOne.Exclusions.Type | string | The whitelisted item type. | 
| SentinelOne.Exclusions.CreatedAt | date | Time when the whitelist item was created. | 


### sentinelone-get-white-list
***
Lists all exclusion items that match the specified input filter.


#### Base Command

`sentinelone-get-white-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_ids | List of IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| os_types | A comma-separated list of OS types by which to filter, for example: "windows, linux". Possible values are: windows, windows_legacy, macos, linux. | Optional | 
| exclusion_type | Exclusion type. Can be "file_type", "path", "white_hash", "certificate", "browser". Possible values are: file_type, path, white_hash, certificate, browser. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


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
| SentinelOne.Exclusions.Mode | string | A comma-separated list of modes by which to filter \(ath exclusions only\), for example: "suppress". | 


#### Command Example
```!sentinelone-get-white-list os_types=windows exclusion_type=path```

#### Context Example
```json
{
    "SentinelOne": {
        "Exclusions": {
            "CreatedAt": "2020-10-25T14:09:58.928251Z",
            "ID": "1010040403583584993",
            "Mode": "suppress",
            "OsType": "windows",
            "Source": "user",
            "Type": "path",
            "UpdatedAt": "2020-10-25T14:09:58.921789Z",
            "UserID": "475482955872052394",
            "UserName": "XSOAR User",
            "Value": "*/test/"
        }
    }
}
```

#### Human Readable Output

>### Sentinel One - Listing exclusion items
>Provides summary information and details for all the exclusion items that matched your search criteria.
>|CreatedAt|ID|Mode|OsType|Source|Type|UpdatedAt|UserID|UserName|Value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-25T14:09:58.928251Z | 1010040403583584993 | suppress | windows | user | path | 2020-10-25T14:09:58.921789Z | 475482955872052394 | XSOAR User | */test/ |


### sentinelone-get-hash
***
Get file reputation by a SHA1 hash.


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
```json
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
>|Hash|Rank|
>|---|---|
>| 3395856ce81f2b7382dee72602f798b642f14140 | 7 |


### sentinelone-get-threats
***
Returns threats according to specified filters.


#### Base Command

`sentinelone-get-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_hash | The content hash of the threat. | Optional | 
| mitigation_status | A comma-separated list of mitigation statuses. Can be "mitigated", "active", "blocked", "suspicious", "pending", or "suspicious_resolved". Possible values are: mitigated, active, blocked, suspicious, pending, suspicious_resolved. | Optional | 
| created_before | Searches for threats created before this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_after | Searches for threats created after this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_until | Searches for threats created on or before this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_from | Search for threats created on or after this date, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| resolved | Whether to only return resolved threats. Possible values are: false, true. Default is false. | Optional | 
| display_name | Threat display name. For API version 2.0 can be a partial display name, not an exact match. | Optional | 
| limit | The maximum number of threats to return. Default is 20. Default is 20. | Optional | 
| query | Full free-text search for fields. Can be "content_hash", "file_display_name", "file_path", "computer_name", or "uuid". | Optional | 
| threat_ids | A comma-separated list of threat IDs, for example: "225494730938493804,225494730938493915". | Optional | 
| classifications |  CSV list of threat classifications to search, for example: "Malware", "Network", "Benign". Possible values are: Engine, Static, Cloud, Behavioral. | Optional | 
| rank | Risk level threshold to retrieve (1-10). Relevant for API version 2.0 only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.AgentComputerName | String | The agent computer name. | 
| SentinelOne.Threat.CreatedDate | Date | File created date. | 
| SentinelOne.Threat.SiteID | String | The site ID. | 
| SentinelOne.Threat.Classification | string | Classification name. | 
| SentinelOne.Threat.ClassificationSource | string | Source of the threat Classification. | 
| SentinelOne.Threat.ConfidenceLevel | string | SentinelOne threat confidence level. | 
| SentinelOne.Threat.FileSha256 | string | SHA256 hash of file content. | 
| SentinelOne.Threat.MitigationStatus | String | The agent status. | 
| SentinelOne.Threat.AgentID | String | The agent ID. | 
| SentinelOne.Threat.Rank | Number | Number representing cloud reputation \(1-10\). | 
| SentinelOne.Threat.MarkedAsBenign | Boolean | Whether the threat is marked as benign. Relevant for version 2.0 only. | 


#### Command Example
```!sentinelone-get-threats resolved=true```

#### Context Example
```json
{
    "SentinelOne": {
        "Threat": [
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168123595",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T12:05:49.095889Z",
                "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Unconfirmed 123490.crdownload",
                "ID": "715718962991148224",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366727779",
                "SiteName": "demisto",
                "ThreatName": "Unconfirmed 123490.crdownload",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            },
            {
                "AgentComputerName": "EC2AMAZ-AJ0KANC",
                "AgentID": "657613730168123595",
                "AgentOsType": "windows",
                "Classification": "Malware",
                "ClassificationSource": "Static",
                "ConfidenceLevel": "malicious",
                "CreatedDate": "2019-09-15T12:14:42.440985Z",
                "FileContentHash": "d8757a0396d05a1d532422827a70a7966c361366",
                "FilePath": "\\Device\\HarddiskVolume1\\Users\\Administrator\\Downloads\\Ncat Netcat Portable - CHIP-Installer.exe",
                "ID": "715723437013282014",
                "MitigationStatus": "mitigated",
                "SiteID": "475482421366727779",
                "SiteName": "demisto",
                "ThreatName": "Ncat Netcat Portable - CHIP-Installer.exe",
                "Username": "EC2AMAZ-AJ0KANC\\Administrator"
            }
        ]
    }
}
```

#### Human Readable Output

>### Sentinel One - Getting Threat List
>Provides summary information and details for all the threats that matched your search criteria.
>|ID|Agent Computer Name|Created Date|Site ID|Site Name|Classification|Mitigation Status|Confidence Level|Agent ID|File Content Hash|
>|---|---|---|---|---|---|---|---|---|---|
>| 715718962991148224 | EC2AMAZ-AJ0KANC | 2019-09-15T12:05:49.095889Z | 475482421366727779 | demisto | Malware | mitigated | malicious | 657613730168123595 | 3395856ce81f2b7382dee72602f798b642f14140 |
>| 715723437013282014 | EC2AMAZ-AJ0KANC | 2019-09-15T12:14:42.440985Z | 475482421366727779 | demisto | Malware | mitigated | malicious | 657613730168123595 | d8757a0396d05a1d532422827a70a7966c361366 |


### sentinelone-threat-summary
***
Returns a dashboard threat summary.


#### Base Command

`sentinelone-threat-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_ids | A comma-separated list of group IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 


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
```!sentinelone-threat-summary group_ids="475482421375116388,764073410272419896"```

#### Context Example
```json
{
    "SentinelOne": {
        "Threat": {
            "InProgress": 0,
            "MaliciousNotResolved": 0,
            "NotMitigated": 0,
            "NotMitigatedNotResolved": 0,
            "NotResolved": 0,
            "Resolved": 14,
            "SuspiciousNotMitigatedNotResolved": 0,
            "SuspiciousNotResolved": 0,
            "Total": 14
        }
    }
}
```

#### Human Readable Output

>### Sentinel One - Dashboard Threat Summary
>|In Progress|Malicious Not Resolved|Not Mitigated|Not Mitigated Not Resolved|Not Resolved|Resolved|Suspicious Not Mitigated Not Resolved|Suspicious Not Resolved|Total|
>|---|---|---|---|---|---|---|---|---|
>| 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 14 |


### sentinelone-mark-as-threat
***
Mark suspicious threats as threats


#### Base Command

`sentinelone-mark-as-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | A comma-separated list of threat IDs. | Optional | 
| target_scope | Scope to use for exclusions. Can be "site" or "tenant". Possible values are: site, tenant. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.MarkedAsThreat | Boolean | Whether the suspicious threat was successfully marked as a threat. | 


### sentinelone-mitigate-threat
***
Applies a mitigation action to a group of threats that match the specified input filter.


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


### sentinelone-resolve-threat
***
Resolves threat using the threat ID.


#### Base Command

`sentinelone-resolve-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | A comma-separated list of threat IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Resolved | Boolean | Whether the threat was successfully resolved. | 


### sentinelone-get-agent
***
Returns details of an agent, by agent ID.


#### Base Command

`sentinelone-get-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | A comma-separated list of Agent IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.NetworkStatus | string | The agent network status. | 
| SentinelOne.Agent.ID | string | The agent ID. | 
| SentinelOne.Agent.AgentVersion | string | The agent software version. | 
| SentinelOne.Agent.IsDecommissioned | boolean | Whether the agent is decommissioned. | 
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
```!sentinelone-get-agent agent_id=657613730168123595```

#### Context Example
```json
{
    "SentinelOne": {
        "Agent": {
            "AgentVersion": "3.1.3.38",
            "ComputerName": "EC2AMAZ-AJ0KANC",
            "CreatedAt": "2019-06-27T08:01:05.571895Z",
            "Domain": "WORKGROUP",
            "EncryptedApplications": false,
            "ExternalIP": "8.88.8.8",
            "ID": "657613730168123595",
            "IsActive": false,
            "IsDecommissioned": true,
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
>|Agent Version|Computer Name|Created At|Domain|Encrypted Applications|External IP|ID|Is Active|Is Decommissioned|Last Active Date|Network Status|OS Name|Registered At|Site Name|Threat Count|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3.1.3.38 | EC2AMAZ-AJ0KANC | 2019-06-27T08:01:05.571895Z | WORKGROUP | false | 8.88.8.8 | 657613730168123595 | false | true | 2020-02-20T00:26:33.955830Z | connecting | Windows Server 2016 | 2019-06-27T08:01:05.567249Z | demisto | 0 |


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
| site_type | Site type. Can be "Trial", "Paid", "POC", "DEV", or "NFR". Possible values are: Trial, Paid, POC, DEV, NFR. | Optional | 
| features | Returns sites that support the specified features. Can be "firewall-control", "device-control", or "ioc". Possible values are: firewall-control, device-control, ioc. | Optional | 
| state | Site state. Can be "active", "deleted", or "expired". Possible values are: active, deleted, expired. | Optional | 
| suite | The suite of product features active for this site. Can be "Core" or "Complete". Possible values are: Core, Complete. | Optional | 
| admin_only | Sites to which the user has Admin privileges. Possible values are: true, false. | Optional | 
| account_id | Account ID, for example: "225494730938493804". | Optional | 
| site_name | Site name, for example: "My Site". | Optional | 
| created_at | Timestamp of site creation, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 


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
| SentinelOne.Site.UnlimitedLicenses | boolean | Whether the site has unlimited licenses. | 


#### Command Example
```!sentinelone-get-sites```

#### Context Example
```json
{
    "SentinelOne": {
        "Site": {
            "AccountName": "SentinelOne",
            "ActiveLicenses": 0,
            "CreatedAt": "2018-10-19T00:58:41.644879Z",
            "Creator": "XSOAR User",
            "Expiration": null,
            "HealthStatus": true,
            "ID": "475482421366727779",
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

>### Sentinel One - Getting List of Sites
>Provides summary information and details for all sites that matched your search criteria.
>|Account Name|Active Licenses|Created At|Creator|Health Status|ID|Name|State|Suite|Total Licenses|Type|Unlimited Licenses|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| SentinelOne | 0 | 2018-10-19T00:58:41.644879Z | XSOAR User | true | 475482421366727779 | demisto | active | Complete | 0 | Paid | true |


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
```!sentinelone-get-site site_id=475482421366727779```

#### Context Example
```json
{
    "SentinelOne": {
        "Site": {
            "AccountID": "433241117337583618",
            "AccountName": "SentinelOne",
            "ActiveLicenses": 0,
            "CreatedAt": "2018-10-19T00:58:41.644879Z",
            "Creator": "XSOAR User",
            "Expiration": null,
            "HealthStatus": true,
            "ID": "475482421366727779",
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

>### Sentinel One - Summary About Site: 475482421366727779
>Provides summary information and details for specific site ID
>|Account ID|Account Name|Active Licenses|Created At|Creator|Health Status|ID|Is Default|Name|State|Suite|Total Licenses|Type|Unlimited Licenses|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 433241117337583618 | SentinelOne | 0 | 2018-10-19T00:58:41.644879Z | XSOAR User | true | 475482421366727779 | false | demisto | active | Complete | 0 | Paid | true |


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
| include_hidden | Include internal activities hidden from display, for example: "False". Possible values are: true, false. | Optional | 
| activities_ids | A comma-separated list of activity IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| created_before | Return activities created before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| threats_ids | A comma-separated list of threat IDs for which to return activities, for example: "225494730938493804,225494730938493915". | Optional | 
| activity_types | A comma-separated list of activity codes to return, for example: "52,53,71,72". | Optional | 
| user_ids | A comma-separated list of user IDs for users that invoked the activity (if applicable), for example: "225494730938493804,225494730938493915". | Optional | 
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
```json
{
    "SentinelOne": {
        "Activity": [
            {
                "ActivityType": 61,
                "AgentID": "657613730168123595",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2020-01-12T20:16:44.594737Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "username": "XSOAR User",
                    "uuid": "f431b0a1a8744d2a8a92fc88fa3c13bc"
                },
                "Description": null,
                "GroupID": "475482421375116388",
                "Hash": null,
                "ID": "802214365638826164",
                "OsFamily": null,
                "PrimaryDescription": "The management user XSOAR User issued a disconnect from network command to the machine EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": null,
                "SiteID": "475482421366727779",
                "ThreatID": null,
                "UpdatedAt": "2020-01-12T20:16:44.594743Z",
                "UserID": "475482955872052394"
            },
            {
                "ActivityType": 62,
                "AgentID": "657613730168123595",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2020-01-12T20:16:46.659017Z",
                "Data": {
                    "accountName": "SentinelOne",
                    "computerName": "EC2AMAZ-AJ0KANC",
                    "groupName": "Default Group",
                    "siteName": "demisto",
                    "username": "XSOAR User",
                    "uuid": "f431b0a1a8744d2a8a92fc88fa3c13bc"
                },
                "Description": null,
                "GroupID": "475482421375116388",
                "Hash": null,
                "ID": "802214382952913086",
                "OsFamily": null,
                "PrimaryDescription": "The management user XSOAR User issued a reconnect to network command to the machine EC2AMAZ-AJ0KANC.",
                "SecondaryDescription": null,
                "SiteID": "475482421366727779",
                "ThreatID": null,
                "UpdatedAt": "2020-01-12T20:16:46.659023Z",
                "UserID": "475482955872052394"
            },
            {
                "ActivityType": 1002,
                "AgentID": "657613730168123595",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2020-01-12T20:17:32.040670Z",
                "Data": {
                    "computerName": "EC2AMAZ-AJ0KANC"
                },
                "Description": null,
                "GroupID": "475482421375116388",
                "Hash": null,
                "ID": "802214763636332743",
                "OsFamily": null,
                "PrimaryDescription": "Agent EC2AMAZ-AJ0KANC was connected to network.",
                "SecondaryDescription": null,
                "SiteID": "475482421366727779",
                "ThreatID": null,
                "UpdatedAt": "2020-01-12T20:17:32.038143Z",
                "UserID": null
            },
            {
                "ActivityType": 1001,
                "AgentID": "657613730168123595",
                "AgentUpdatedVersion": null,
                "Comments": null,
                "CreatedAt": "2020-01-12T20:17:42.815619Z",
                "Data": {
                    "computerName": "EC2AMAZ-AJ0KANC"
                },
                "Description": null,
                "GroupID": "475482421375116388",
                "Hash": null,
                "ID": "802214854023583946",
                "OsFamily": null,
                "PrimaryDescription": "Agent EC2AMAZ-AJ0KANC was disconnected from network.",
                "SecondaryDescription": null,
                "SiteID": "475482421366727779",
                "ThreatID": null,
                "UpdatedAt": "2020-01-12T20:17:42.812834Z",
                "UserID": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Sentinel One Activities
>|ID|Primary Description|Data|User ID|Created At|Updated At|
>|---|---|---|---|---|---|
>| 802214365638826164 | The management user XSOAR User issued a disconnect from network command to the machine EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>groupName: Default Group<br/>siteName: demisto<br/>username: XSOAR User<br/>uuid: f431b0a1a8744d2a8a92fc88fa3c13bc | 475482955872052394 | 2020-01-12T20:16:44.594737Z | 2020-01-12T20:16:44.594743Z |
>| 802214382952913086 | The management user XSOAR User issued a reconnect to network command to the machine EC2AMAZ-AJ0KANC. | accountName: SentinelOne<br/>computerName: EC2AMAZ-AJ0KANC<br/>groupName: Default Group<br/>siteName: demisto<br/>username: XSOAR User<br/>uuid: f431b0a1a8744d2a8a92fc88fa3c13bc | 475482955872052394 | 2020-01-12T20:16:46.659017Z | 2020-01-12T20:16:46.659023Z |
>| 802214763636332743 | Agent EC2AMAZ-AJ0KANC was connected to network. | computerName: EC2AMAZ-AJ0KANC |  | 2020-01-12T20:17:32.040670Z | 2020-01-12T20:17:32.038143Z |
>| 802214854023583946 | Agent EC2AMAZ-AJ0KANC was disconnected from network. | computerName: EC2AMAZ-AJ0KANC |  | 2020-01-12T20:17:42.815619Z | 2020-01-12T20:17:42.812834Z |


### sentinelone-get-groups
***
Returns data for the specified group.


#### Base Command

`sentinelone-get-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | Group type, for example: "static". | Optional | 
| group_ids | A comma-separated list of group IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| group_id | Group ID by which to filter, for example: "225494730938493804". | Optional | 
| is_default | Whether this is the default group. Possible values are: true, false. | Optional | 
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
```json
{
    "SentinelOne": {
        "Group": {
            "createdAt": "2018-10-19T00:58:41.646045Z",
            "creator": "XSOAR User",
            "creatorId": "433273625970238486",
            "filterId": null,
            "filterName": null,
            "id": "475482421375116388",
            "inherits": true,
            "isDefault": true,
            "name": "Default Group",
            "rank": null,
            "registrationToken": "eyJiOiAiZ184NjJiYWQzNTIwN2ZmNTJmIn0=",
            "siteId": "475482421366727779",
            "totalAgents": 0,
            "type": "static",
            "updatedAt": "2021-01-02T13:34:58.753880Z"
        }
    }
}
```

#### Human Readable Output

>### Sentinel One Groups
>|Id|Name|Type|Creator|Creator Id|Created At|
>|---|---|---|---|---|---|
>| 475482421375116388 | Default Group | static | XSOAR User | 433273625970238486 | 2018-10-19T00:58:41.646045Z |


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


#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



### sentinelone-agent-processes
***
DEPRECATED - Retrieves running processes for a specific agent.


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


### sentinelone-connect-agent
***
Connects agents to network.


#### Base Command

`sentinelone-connect-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | A comma-separated list of agent IDs to connect to the network. Run the list-agents command to get a list of agent IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.AgentsAffected | Number | The number of affected agents. | 
| SentinelOne.Agent.ID | String | The IDs of the affected agents. | 


#### Command Example
```!sentinelone-connect-agent agent_id=657613730168123595```

#### Context Example
```json
{
    "SentinelOne": {
        "Agent": {
            "ID": "657613730168123595",
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
| agent_id | A comma-separated list of agent IDs to disconnect from the network. Run the list-agents command to get a list of agent IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.NetworkStatus | String | Agent network status. | 
| SentinelOne.Agent.ID | String | The IDs of the affected agents. | 


#### Command Example
```!sentinelone-disconnect-agent agent_id=657613730168123595```

#### Context Example
```json
{
    "SentinelOne": {
        "Agent": {
            "ID": "657613730168123595",
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
| active_agent | Whether to only include active agents. Default is "false". Possible values are: true, false. | Optional | 
| group_id | A comma-separated list of Group IDs by which to filter the results. | Optional | 
| agent_id | A comma-separated list of Agent IDs by which to filter the results. | Optional | 
| domain | A comma-separated of included network domains. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sentinelone-broadcast-message message="Hey There, just checking" agent_id=657613730168123595```

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
| limit | Maximum number of items to return (1-100). Default is "50". Default is 50. | Optional | 
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
```!sentinelone-get-events query_id=q034ae362a30eba5a187cbe601d19abaa```

#### Human Readable Output

>No events were found.

### sentinelone-create-query
***
Runs a Deep Visibility Query and returns the queryId. You can use the queryId for all other commands, such as the sentinelone-get-events command.


#### Base Command

`sentinelone-create-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string for which to return events. | Required | 
| from_date | Query start date, for example, "2019-08-03T04:49:26.257525Z". Limited to 93 ago. | Required | 
| to_date | Query end date, for example, "2019-08-03T04:49:26.257525Z". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Query.FromDate | Date | Query start date. | 
| SentinelOne.Query.Query | String | The search query string. | 
| SentinelOne.Query.QueryID | String | The query ID. | 
| SentinelOne.Query.ToDate | Date | Query end date. | 


#### Command Example
```!sentinelone-create-query query="AgentName Is Not Empty" from_date="2020-10-13T15:24:09.257Z" to_date="2021-01-10T04:49:26.257525Z"```

#### Context Example
```json
{
    "SentinelOne": {
        "Query": {
            "FromDate": "2020-10-13T15:24:09.257Z",
            "Query": "AgentName Is Not Empty",
            "QueryID": "q15a9c0b5a5f2081188e70c42897ef5f9",
            "ToDate": "2021-01-10T04:49:26.257525Z"
        }
    }
}
```

#### Human Readable Output

>The query ID is q15a9c0b5a5f2081188e70c42897ef5f9

### sentinelone-get-processes
***
Returns a list of Deep Visibility events from query by event type - process.


#### Base Command

`sentinelone-get-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The queryId that is returned when creating a query under Create Query. Example: "q1xx2xx3". Get the query_id from the "get-query-id" command. | Required | 
| limit | Maximum number of items to return (1-100). Default is "50". Default is 50. | Optional | 


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
```!sentinelone-get-processes query_id=q034ae362a30eba5a187cbe601d19abaa```


### sentinelone-shutdown-agent
***
Sends a shutdown command to all agents that match the input filter.


#### Base Command

`sentinelone-shutdown-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text search term, will match applicable attributes (sub-string match). Note: A device's physical addresses will only be matched if they start with the search term  (not if they contain the search term). | Optional | 
| agent_id | A comma-separated list of agents IDs to shutdown. | Optional | 
| group_id | The ID of the network group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.ID | String | The ID of the agent that was shutdown. | 


#### Command Example
``` ```

#### Human Readable Output



### sentinelone-uninstall-agent
***
Sends an uninstall command to all agents that match the input filter.


#### Base Command

`sentinelone-uninstall-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text search term, will match applicable attributes (sub-string match). Note: A device's physical addresses will only be matched if they start with the search term  (not if they contain the search term). | Optional | 
| agent_id | A comma-separated list of agents IDs to shutdown. | Optional | 
| group_id | The ID of the network group. | Optional | 


#### Context Output

There is no context output for this command.

