Use the SentinelOne integration to send requests to your management server and get responses with data pulled from agents or from the management database.
This integration was integrated and tested with versions 2.0 and 2.1 of SentinelOne V2
## Configure SentinelOne V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SentinelOne v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://usea1.sentinelone.net) |  | True |
    | API Token |  | False |
    | API Version |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Minimum risk score for importing incidents (0-10), where 0 is low risk and 10 is high risk. Relevant for API version 2.0. |  | False |
    | Fetch limit: The maximum number of incidents to fetch |  | False |
    | Site IDs | Comma-separated list of site IDs to fetch incidents for. Leave blank to fetch all sites. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | API Token (Deprecated) | Use the "API Token \(Recommended\)" parameter instead. | False |

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
| computer_name | The computer name by which to filter the results. | Optional | 
| scan_status | A comma-separated list of scan statuses by which to filter the results, for example: "started,aborted". Possible values are: started, none, finished, aborted. | Optional | 
| os_type | Included operating system types, for example: "windows". Possible values are: windows, windows_legacy, macos, linux. | Optional | 
| created_at | Endpoint creation timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| min_active_threats | Minimum number of threats per agent. | Optional | 
| limit | The maximum number of agents to return. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agents.NetworkStatus | string | The agent network status. | 
| SentinelOne.Agents.ID | string | The agent ID. | 
| SentinelOne.Agents.AgentVersion | string | The agent software version. | 
| SentinelOne.Agents.IsDecommissioned | boolean | Whether the agent is decommissioned. | 
| SentinelOne.Agents.IsActive | boolean | Whether the agent is active. | 
| SentinelOne.Agents.LastActiveDate | date | When was the agent last active. | 
| SentinelOne.Agents.RegisteredAt | date | The registration date of the agent. | 
| SentinelOne.Agents.ExternalIP | string | The agent IP address. | 
| SentinelOne.Agents.ThreatCount | number | Number of active threats. | 
| SentinelOne.Agents.EncryptedApplications | boolean | Whether disk encryption is enabled. | 
| SentinelOne.Agents.OSName | string | Name of operating system. | 
| SentinelOne.Agents.ComputerName | string | Name of agent computer. | 
| SentinelOne.Agents.Domain | string | Domain name of the agent. | 
| SentinelOne.Agents.CreatedAt | date | Creation time of the agent. | 
| SentinelOne.Agents.SiteName | string | Site name associated with the agent. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| activeThreats__gt | valid |
| computerName | valid |
| scanStatus | valid |
| osType | osTypes |
| createdAt__gte | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- | 
| SentinelOne.Agents.NetworkStatus | valid |
| SentinelOne.Agents.ID | valid |
| SentinelOne.Agents.AgentVersion | valid |
| SentinelOne.Agents.isDecommissioned | valid |
| SentinelOne.Agents.IsActive | valid |
| SentinelOne.Agents.LastActiveDate | valid |
| SentinelOne.Agents.RegisteredAt | valid |
| SentinelOne.Agents.ExternalIP | valid |
| SentinelOne.Agents.ThreatCount | activeThreat |
| SentinelOne.Agents.EncryptedApplications | valid |
| SentinelOne.Agents.OSName | valid |
| SentinelOne.Agents.ComputerName | valid |
| SentinelOne.Agents.Domain | valid |
| SentinelOne.Agents.CreatedAt | valid |
| SentinelOne.Agents.SiteName | valid |


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
| exclusion_type | Exclusion item type. Possible values are: file_type, path, white_hash, certificate, browser. | Required | 
| exclusion_value | Value of the exclusion item for the exclusion list. | Required | 
| os_type | Operating system type. Required for hash exclusions. Possible values are: windows, windows_legacy, macos, linux. | Required | 
| description | Description for adding the exclusion item. | Optional | 
| exclusion_mode | Exclusion mode (path exclusion only). Possible values are: suppress, disable_in_process_monitor_deep, disable_in_process_monitor, disable_all_monitors, disable_all_monitors_deep. | Optional | 
| path_exclusion_type | Excluded path for a path exclusion list. | Optional | 
| group_ids | A comma-separated list of group IDs by which to filter. | Optional | 
| site_ids | A comma-separated list of site IDs by which to filter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Exclusions.ID | string | The entity ID on the allow list. | 
| SentinelOne.Exclusions.Type | string | The item type on the allow list. | 
| SentinelOne.Exclusions.CreatedAt | date | Time when the allow list item was created. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| type | valid |
| value | valid |
| osType | valid |
| description | valid |
| mode | valid |
| groupIds | valid |
| siteIds | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- | 
| SentinelOne.Exclusions.ID | valid |
| SentinelOne.Exclusions.Type | valid |
| SentinelOne.Exclusions.CreatedAt | valid |


### sentinelone-get-white-list
***
Lists all exclusion items that match the specified input filter.


#### Base Command

`sentinelone-get-white-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_ids | List of IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| os_types | A comma-separated list of operating system types by which to filter, for example: "windows, linux". Possible values are: windows, windows_legacy, macos, linux. | Optional | 
| exclusion_type | Exclusion type. Possible values are: file_type, path, white_hash, certificate, browser. | Optional | 
| limit | The maximum number of items to return. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Exclusions.ID | string | The exclusion item ID. | 
| SentinelOne.Exclusions.Type | string | The exclusion item type. | 
| SentinelOne.Exclusions.CreatedAt | date | Timestamp when the exclusion item was added. | 
| SentinelOne.Exclusions.Value | string | Value of the exclusion item. | 
| SentinelOne.Exclusions.Source | string | Source of the exclusion item. | 
| SentinelOne.Exclusions.UserID | string | User ID of the user qho added the exclusion item. | 
| SentinelOne.Exclusions.UpdatedAt | date | Timestamp when the exclusion item was updated. | 
| SentinelOne.Exclusions.OsType | string | Operating system type of the exclusion item. | 
| SentinelOne.Exclusions.UserName | string | User name of the user who added the exclusion item. | 
| SentinelOne.Exclusions.Mode | string | A comma-separated list of modes by which to filter \(path exclusions only\), for example: "suppress". | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| ids | valid |
| osTypes | valid |
| type | valid |
| limit | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- | 
| SentinelOne.Exclusions.ID | valid |
| SentinelOne.Exclusions.Type | valid |
| SentinelOne.Exclusions.CreatedAt | valid |
| SentinelOne.Exclusions.Value | valid |
| SentinelOne.Exclusions.Source | valid |
| SentinelOne.Exclusions.UserID | valid |
| SentinelOne.Exclusions.UpdatedAt | valid |
| SentinelOne.Exclusions.OsType | valid |
| SentinelOne.Exclusions.UserName | valid |
| SentinelOne.Exclusions.Mode | valid |


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
Gets the file reputation by a SHA1 hash.


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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| {hash} | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Hash.Rank | valid |
| SentinelOne.Hash.Hash | None (need to return from the input) |
| SentinelOne.Hash.Classification | None |
| SentinelOne.Hash.Classification Source | None |


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
Returns threats according to the specified filters.


#### Base Command

`sentinelone-get-threats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_hash | A comma-separated list of content hashes of the threat. | Optional | 
| mitigation_status | A comma-separated list of mitigation statuses. Possible values are: mitigated, active, blocked, suspicious, pending, suspicious_resolved. | Optional | 
| created_before | Searches for threats created before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_after | Searches for threats created after this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_until | Searches for threats created on or before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_from | Search for threats created on or after this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| resolved | Whether to only return resolved threats. Possible values are: false, true. Default is false. | Optional | 
| display_name | Threat display name. For API version 2.0 it can be a partial display name, doesn't have to be an exact match. | Optional | 
| limit | The maximum number of threats to return. Default is 20. | Optional | 
| query | Full free-text search for fields. Can be "content_hash", "file_display_name", "file_path", "computer_name", or "uuid". | Optional | 
| threat_ids | A comma-separated list of threat IDs, for example: "225494730938493804,225494730938493915". | Optional | 
| classifications | A comma-separated list of threat classifications to search, for example: "Malware", "Network", "Benign". Possible values are: Engine, Static, Cloud, Behavioral. | Optional | 
| rank | Risk level threshold to retrieve (1-10). Relevant for API version 2.0 only. | Optional | 
| site_ids | A comma-separated list of site IDs to search for threats, for example: "225494730938493804,225494730938493915". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.AgentComputerName | String | The agent computer name. | 
| SentinelOne.Threat.CreatedDate | Date | The threat creation date. | 
| SentinelOne.Threat.SiteID | String | The site ID. | 
| SentinelOne.Threat.Classification | string | The threat classification. | 
| SentinelOne.Threat.ClassificationSource | string | Source of the threat classification. | 
| SentinelOne.Threat.ConfidenceLevel | string | SentinelOne threat confidence level. | 
| SentinelOne.Threat.FileSha256 | string | SHA256 hash of the file content. | 
| SentinelOne.Threat.MitigationStatus | String | The agent mitigation status. | 
| SentinelOne.Threat.AgentID | String | The threat agent ID. | 
| SentinelOne.Threat.Rank | Number | The number representing the cloud reputation \(1-10\). | 
| SentinelOne.Threat.MarkedAsBenign | Boolean | Whether the threat is marked as benign. Relevant for version 2.0 only. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| contentHash | contentHashes |
| mitigationStatuses | valid |
| createdAt__lt | valid |
| createdAt__gt | valid |
| createdAt__lte | valid |
| createdAt__gte | valid |
| resolved | valid |
| displayName__like | displayName |
| query | valid |
| ids | valid |
| limit | valid |
| classifications | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Threat.ID | valid |
| SentinelOne.Threat.AgentComputer | agentComputerName |
| SentinelOne.Threat.CreatedDate | createdAt |
| SentinelOne.Threat.SiteID | valid |
| SentinelOne.Threat.Classification | valid |
| SentinelOne.Threat.MitigationStatus | valid |
| SentinelOne.Threat.AgentID | valid |
| SentinelOne.Threat.Rank | None |
| SentinelOne.Threat.MarkedAsBenig | None |


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
Returns a dashboard threat summary.  Can only be used with API V2.1.


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
Marks suspicious threats as threats. Can only be used with API V2.0.


#### Base Command

`sentinelone-mark-as-threat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | A comma-separated list of threat IDs. | Optional | 
| target_scope | Scope to use for exclusions. Possible values are: site, tenant. | Required | 


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
| action | Mitigation action. Possible values are: kill, quarantine, un-quarantine, remediate, rollback-remediation. | Required | 
| threat_ids | A comma-separated list of threat IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Mitigated | Boolean | Whether the threat was successfully mitigated. | 
| SentinelOne.Threat.Mitigation.Action | Number | Number of threats affected. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| filter | valid |
| ids | valid |
| action | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Threat.ID | None (need to return from the input) |
| SentinelOne.Threat.Mitigated | None |
| SentinelOne.Threat.Mitigation.Action | effected |


### sentinelone-resolve-threat
***
Resolves threats using the threat ID. Can only be used with API V2.0.


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
Returns the details of an agent according to the agent ID.


#### Base Command

`sentinelone-get-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | A comma-separated list of agent IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.NetworkStatus | string | The agent network status. | 
| SentinelOne.Agent.ID | string | The agent ID. | 
| SentinelOne.Agent.AgentVersion | string | The agent software version. | 
| SentinelOne.Agent.IsDecommissioned | boolean | Whether the agent is decommissioned. | 
| SentinelOne.Agent.IsActive | boolean | Whether the agent is active. | 
| SentinelOne.Agent.LastActiveDate | date | When was the agent last active. | 
| SentinelOne.Agent.RegisteredAt | date | The registration date of the agent. | 
| SentinelOne.Agent.ExternalIP | string | The agent IP address. | 
| SentinelOne.Agent.ThreatCount | number | Number of active threats. | 
| SentinelOne.Agent.EncryptedApplications | boolean | Whether disk encryption is enabled. | 
| SentinelOne.Agent.OSName | string | Name of the operating system. | 
| SentinelOne.Agent.ComputerName | string | Name of the agent computer. | 
| SentinelOne.Agent.Domain | string | Domain name of the agent. | 
| SentinelOne.Agent.CreatedAt | date | Agent creation time. | 
| SentinelOne.Agent.SiteName | string | Site name associated with the agent. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| ids | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Agent.NetworkStatus | valid |
| SentinelOne.Agent.ID | valid |
| SentinelOne.Agent.AgentVersion | valid |
| SentinelOne.Agent.IsDecomissioned | isDecommissioned (misspelled) |
| SentinelOne.Agent.IsActive | valid |
| SentinelOne.Agent.LastActiveDate | valid |
| SentinelOne.Agent.RegisteredAt | valid |
| SentinelOne.Agent.ExternalIP | valid |
| SentinelOne.Agent.ThreatCount | activeThreats |
| SentinelOne.Agent.EncryptedApplica | valid |
| SentinelOne.Agent.OSName| valid |
| SentinelOne.Agent.ComputerName | valid |
| SentinelOne.Agent.Domain | valid |
| SentinelOne.Agent.CreatedAt | valid |
| SentinelOne.Agent.SiteName | valid |


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
| updated_at | Timestamp of the last update, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| query | Full-text search for fields: name, account_name. | Optional | 
| site_type | Site type. Possible values are: Trial, Paid, POC, DEV, NFR. | Optional | 
| features | Returns sites that support the specified features. Possible values are: firewall-control, device-control, ioc. | Optional | 
| state | Site state. Possible values are: active, deleted, expired. | Optional | 
| suite | The suite of product features active for this site. Possible values are: Core, Complete. | Optional | 
| admin_only | Sites for which the user has admin privileges. Possible values are: true, false. | Optional | 
| account_id | Account ID, for example: "225494730938493804". | Optional | 
| site_name | Site name, for example: "My Site". | Optional | 
| created_at | Timestamp of the site creation, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.Creator | string | The site creator name. | 
| SentinelOne.Site.Name | string | The site name. | 
| SentinelOne.Site.Type | string | The site type. | 
| SentinelOne.Site.AccountName | string | The site account name. | 
| SentinelOne.Site.State | string | The site state. | 
| SentinelOne.Site.HealthStatus | boolean | The health status of the site. | 
| SentinelOne.Site.Suite | string | The suite to which the site belongs. | 
| SentinelOne.Site.ActiveLicenses | number | Number of active licenses for the site. | 
| SentinelOne.Site.ID | string | ID of the site. | 
| SentinelOne.Site.TotalLicenses | number | Number of total licenses for the site. | 
| SentinelOne.Site.CreatedAt | date | Timestamp when the site was created. | 
| SentinelOne.Site.Expiration | string | Timestamp when the site will expire. | 
| SentinelOne.Site.UnlimitedLicenses | boolean | Whether the site has unlimited licenses. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| updatedAt | valid |
| query | valid |
| siteType | valid |
| features | valid |
| state | valid |
| suite | valid |
| adminOnly | valid |
| accountId | valid |
| name | valid |
| createdAt | valid |
| limit | valid |
| siteIds | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Site.Creator | valid |
| SentinelOne.Site.Name | valid |
| SentinelOne.Site.Type | siteType |
| SentinelOne.Site.AccountName | valid |
| SentinelOne.Site.State | valid |
| SentinelOne.Site.HealthStatus | valid |
| SentinelOne.Site.Suite | valid |
| SentinelOne.Site.ActiveLicenses | valid |
| SentinelOne.Site.ID | valid |
| SentinelOne.Site.TotalLicenses | valid |
| SentinelOne.Site.CreatedAt | valid |
| SentinelOne.Site.Expiration | valid |
| SentinelOne.Site.UnlimitedLicenses | valid |


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
Returns information about the site, according to the site ID.


#### Base Command

`sentinelone-get-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.Creator | string | The site creator name. | 
| SentinelOne.Site.Name | string | The site name. | 
| SentinelOne.Site.Type | string | The site type. | 
| SentinelOne.Site.AccountName | string | The site account name. | 
| SentinelOne.Site.State | string | The site state. | 
| SentinelOne.Site.HealthStatus | boolean | The health status of the site. | 
| SentinelOne.Site.Suite | string | The suite to which the site belongs. | 
| SentinelOne.Site.ActiveLicenses | number | Number of active licenses for the site. | 
| SentinelOne.Site.ID | string | ID of the site. | 
| SentinelOne.Site.TotalLicenses | number | Number of total licenses for the site. | 
| SentinelOne.Site.CreatedAt | date | Timestamp when the site was created. | 
| SentinelOne.Site.Expiration | string | Timestamp when the site will expire. | 
| SentinelOne.Site.UnlimitedLicenses | boolean | Whether the site has unlimited licenses. | 
| SentinelOne.Site.AccountID | string | Site account ID. | 
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
| site_id | Site ID. For example: "225494730938493804". | Required | 
| unlimited | If false, an expiration should be supplied. | Optional | 
| expiration | Expiration date in case unlimited is false, for example, "2019-08-03T04:49:26.257525Z". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.ID | string | Site ID. | 
| SentinelOne.Site.Reactivated | boolean | Whether the site was reactivated. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| site_id | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Site.ID | None (need to return from the input) |
| SentinelOne.Site.Reactivated | success |


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
| group_ids | List of group IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| created_until | Return activities created on or before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| include_hidden | Include internal activities hidden from display. Possible values are: true, false. | Optional | 
| activities_ids | A comma-separated list of activity IDs by which to filter, for example: "225494730938493804,225494730938493915". | Optional | 
| created_before | Return activities created before this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| threats_ids | A comma-separated list of threat IDs for which to return activities, for example: "225494730938493804,225494730938493915". | Optional | 
| activity_types | A comma-separated list of activity codes to return, for example: "52,53,71,72". | Optional | 
| user_ids | A comma-separated list of user IDs for users that invoked the activity (if applicable), for example: "225494730938493804,225494730938493915". | Optional | 
| created_from | Return activities created on or after this timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| created_between | Return activities created within this range (inclusive), for example: "1514978764288-1514978999999". | Optional | 
| agent_ids | Return activities related to specified agents. For example: "225494730938493804,225494730938493915". | Optional | 
| limit | Maximum number of items to return (1-100). | Optional | 
| sort_by | Field to sort results by. Possible values are: activityType, createdAt, id. | Optional | 
| sort_order | Order to sort by. Possible values are: asc, desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Activity.AgentID | String | Related agent \(if applicable\). | 
| SentinelOne.Activity.AgentUpdatedVersion | String | Agent's new version \(if applicable\). | 
| SentinelOne.Activity.SiteID | String | Related site \(if applicable\). | 
| SentinelOne.Activity.UserID | String | The user who invoked the activity \(if applicable\). | 
| SentinelOne.Activity.SecondaryDescription | String | Secondary description. | 
| SentinelOne.Activity.OsFamily | String | Agent's operating system type \(if applicable\). Can be "linux", "macos", "windows", or "windows_legacy". | 
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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| created_at__gt | valid |
| userEmails | valid |
| groupIds | valid |
| created_at__lte | valid |
| ids | valid |
| includeHidden | valid |
| created_at__lt | valid |
| threatIds | valid |
| activityTypes | valid |
| userIds | valid |
| created_at__gte | valid |
| createdAt_between | valid |
| agentIds | valid |
| limit | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Activity.AgentID | valid |
| SentinelOne.Activity.AgentUpdated | agentUpdatedVersion |
| SentinelOne.Activity.SiteID | valid |
| SentinelOne.Activity.UserID | valid |
| SentinelOne.Activity.SecondaryDescription | valid |
| SentinelOne.Activity.OsFamily | valid |
| SentinelOne.Activity.ActivityType | valid |
| SentinelOne.Activity.data.SiteID | None |
| SentinelOne.Activity.data.SiteName | valid |
| SentinelOne.Activity.data.username | valid |
| SentinelOne.Activity.Hash | valid |
| SentinelOne.Activity.UpdatedAt | valid |
| SentinelOne.Activity.Comments | valid |
| SentinelOne.Activity.ThreatID | valid |
| SentinelOne.Activity.PrimaryDescription | valid |
| SentinelOne.Activity.GroupID | valid |
| SentinelOne.Activity.ID | valid |
| SentinelOne.Activity.CreatedAt | valid |
| SentinelOne.Activity.Description | valid |


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
| query | Free-text search. | Optional | 
| rank | The priority of a dynamic group over others, for example, "1", which is the highest priority. | Optional | 
| limit | Maximum number of items to return (1-200). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Group.siteId | String | The ID of the site of which this group is a member. | 
| SentinelOne.Group.filterName | String | If the group is dynamic, the name of the filter which is used to associate agents. | 
| SentinelOne.Group.creatorId | String | The ID of the user who created the group. | 
| SentinelOne.Group.name | String | The name of the group. | 
| SentinelOne.Group.creator | String | The user who created the group. | 
| SentinelOne.Group.rank | Number | The rank, which sets the priority of a dynamic group over others. | 
| SentinelOne.Group.updatedAt | Date | Timestamp of the last update. | 
| SentinelOne.Group.totalAgents | Number | Number of agents in the group. | 
| SentinelOne.Group.filterId | String | If the group is dynamic, the group ID of the filter that is used to associate agents. | 
| SentinelOne.Group.isDefault | Boolean | Whether the groups is the default group of the site. | 
| SentinelOne.Group.inherits | Boolean | Whether the policy is inherited from a site. "False" if the group has its own edited policy. | 
| SentinelOne.Group.type | String | Group type. Can be static or dynamic | 
| SentinelOne.Group.id | String | The ID of the group. | 
| SentinelOne.Group.createdAt | Date | Timestamp of group creation. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| type | valid |
| groupIds | valid |
| id | valid |
| isDefault | valid |
| name | valid |
| query | valid |
| rank | valid |
| limit | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Group.siteId | valid |
| SentinelOne.Group.filterName | valid |
| SentinelOne.Group.creatorId | valid |
| SentinelOne.Group.name | valid |
| SentinelOne.Group.creator | valid |
| SentinelOne.Group.rank | valid |
| SentinelOne.Group.updatedAt | valid |
| SentinelOne.Group.totalAgents | valid |
| SentinelOne.Group.filterId | valid |
| SentinelOne.Group.isDefault | valid |
| SentinelOne.Group.inherits | valid |
| SentinelOne.Group.type | valid |
| SentinelOne.Group.id | valid |
| SentinelOne.Group.createdAt | valid |


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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| group_id | valid |
| agentIds | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Agent.AgentsMoved | valid |


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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.DeleteGroup.Success | String | the status of the command. | 

#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| group_id | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.DeleteGroup.Success | valid |


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

#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| ids | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Agent.memoryUsage | valid |
| SentinelOne.Agent.startTime | valid |
| SentinelOne.Agent.pid | valid |
| SentinelOne.Agent.processName | valid |
| SentinelOne.Agent.cpuUsage | valid |
| SentinelOne.Agent.executablePath | valid |



### sentinelone-connect-agent
***
Connects agents to the network.


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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| ids | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Agent.AgentsAffected | affected |
| SentinelOne.Agent.ID | None (need to return from the input) |


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
Disconnects agents from the network.


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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| ids | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Agent.NetworkStatus | None |
| SentinelOne.Agent.ID | None (need to return from the input) |


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
| message | The message to broadcast to agents. | Required | 
| active_agent | Whether to only include active agents. Default is "false". Possible values are: true, false. | Optional | 
| group_id | A comma-separated list of group IDs by which to filter the results. | Optional | 
| agent_id | A comma-separated list of agent IDs by which to filter the results. | Optional | 
| domain | A comma-separated of included network domains. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.BroadcastMessage.Affected  | String | Number of affected endpoints. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| isActive | valid |
| groupIds | valid |
| ids | valid |
| domains | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.BroadcastMessage.Affected | valid |


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
| limit | Maximum number of items to return (1-100). Default is 50. | Optional | 
| query_id | QueryId obtained when creating a query in the sentinelone-create-query command. Example: "q1xx2xx3". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Event.ProcessUID | String | Process unique identifier. | 
| SentinelOne.Event.SHA256 | String | SHA256 hash of the file. | 
| SentinelOne.Event.AgentOS | String | Operating system type. Can be "windows", "linux", "macos", or "windows_legac". | 
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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| query_id | valid |
| limit | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Event.ProcessUID | srcProcUid |
| SentinelOne.Event.SHA256 | valid |
| SentinelOne.Event.AgentOS | valid |
| SentinelOne.Event.ProcessID | pid |
| SentinelOne.Event.User | valid |
| SentinelOne.Event.Time | processStartTime |
| SentinelOne.Event.Endpoint | agentName |
| SentinelOne.Event.SiteName | valid |
| SentinelOne.Event.EventType | valid |
| SentinelOne.Event.ProcessName | valid |
| SentinelOne.Event.MD5 | valid |
| Event.ID | id |
| Event.Name | None |
| Event.Type | eventType |


#### Command Example
```!sentinelone-get-events query_id=q034ae362a30eba5a187cbe601d19abaa```

#### Human Readable Output

>No events were found.

### sentinelone-create-query
***
Runs a Deep Visibility query and returns the queryId. You can use the queryId for all other commands, such as the sentinelone-get-events command.


#### Base Command

`sentinelone-create-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query string for which to return events. | Required | 
| from_date | Query start date, for example, "2019-08-03T04:49:26.257525Z". Limited to 93 days ago. | Required | 
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
| limit | Maximum number of items to return (1-100). Default is 50. | Optional | 


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


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| query_id | valid |
| limit | valid |
| event_type | Event_type (need to be added if using GET/web/api/v2.1/dv/events/{event_type} ) |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Event.ParentProcessID | parentPid |
| SentinelOne.Event.ProcessUID | None |
| SentinelOne.Event.SHA1 | valid |
| SentinelOne.Event.SubsystemType | processSubSystem |
| SentinelOne.Event.ParentProcessStartTim | valid |
| SentinelOne.Event.ProcessID | Pid |
| SentinelOne.Event.ParentProcessUID | None |
| SentinelOne.Event.User | valid |
| SentinelOne.Event.Time | processStartTime |
| SentinelOne.Event.ParentProcessName | valid |
| SentinelOne.Event.SiteName | valid |
| SentinelOne.Event.EventType | valid |
| SentinelOne.Event.Endpoint | agentName |
| SentinelOne.Event.IntegrityLevel | processIntegrityLevel |
| SentinelOne.Event.CMD | processCmd |
| SentinelOne.Event.ProcessName | valid |
| SentinelOne.Event.ProcessDisplayName | valid |


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
| query | A free-text search term that will match applicable attributes (sub-string match). Note: A device's physical addresses will only be matched if they start with the search term (not if they contain the search term). | Optional | 
| agent_id | A comma-separated list of agents IDs to shutdown. | Optional | 
| group_id | The ID of the network group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.ID | String | The ID of the agent that was shutdown. | 


#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| query | valid |
| ids | valid |
| groupIds | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.Agent.ID | None |


### sentinelone-uninstall-agent
***
Sends an uninstall command to all agents that match the input filter.


#### Base Command

`sentinelone-uninstall-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text search term that will match applicable attributes (sub-string match). Note: A device's physical addresses will only be matched if they start with the search term (not if they contain the search term). | Optional | 
| agent_id | A comma-separated list of agents IDs to shutdown. | Optional | 
| group_id | The ID of the network group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.uninstall.Affected | String | Number of agents that were uninstalled | 

#### V2.0 to V2.1 API Changes

| **Params (input) API V2 (XOAR)** | **API V2.1 (S1)** | 
| --- | --- | 
| query | valid |
| ids | valid |
| groupIds | valid |

| **Params (Outputs) API V2 (XOAR) ** | **API V2.1 (S1)** | 
| --- | --- |
| SentinelOne.uninstall.Affected | valid |


### sentinelone-add-hash-to-blocklist
***
Add a hash to the Global blocklist in SentinelOne.


#### Base Command

`sentinelone-add-hash-to-blocklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | SHA1 hash to add to the Global blocklist. | Optional | 
| source | String describing the source of the block. Default is XSOAR. | Optional | 
| os_type | Type of operating system. Possible values are: windows, linux, macos. | Required | 
| description | Note stored in SentinelOne about the block. Default is Blocked from XSOAR. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.AddHashToBlocklist.hash | unknown | Hash of the file | 
| SentinelOne.AddHashToBlocklist.status | unknown | Status of the action to add a hash to the blocklist. | 

#### Command Example
```!sentinelone-add-hash-to-blocklist os_type=windows description="EICAR Test File" sha1=3395856ce81f2b7382dee72602f798b642f14140 source=XSOAR```
### sentinelone-remove-hash-from-blocklist
***
Remove a hash from the Global blocklist in SentinelOne


#### Base Command

`sentinelone-remove-hash-from-blocklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | SHA1 hash to remove from the Global blocklist. | Optional | 
| os_type | Optional operating system type. If not supplied, will remove across all platforms. Possible values are: windows, macos, linux. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.RemoveHashFromBlocklist.hash | unknown | Hash of the file. | 
| SentinelOne.RemoveHashFromBlocklist.status | unknown | Status of the action to remove a hash from the blocklist. | 

#### Command Example
```!sentinelone-remove-hash-from-blocklist os_type=windows sha1=3395856ce81f2b7382dee72602f798b642f14140```
### sentinelone-download-fetched-file
***
Download a file fetched using the sentinelone-fetch-file command to submit the request and the sentinelone-get-activities command to get the download path.


#### Base Command

`sentinelone-download-fetched-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | SentinelOne agent ID. Default is Agent ID. | Required | 
| activity_id | Activity ID in the get-activities command. | Required | 
| password | Password used in the sentinelone-fetch-file command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sentinelone-download-fetched-file activity_id=ACTIVITY_ID agent_id=AGENT_ID password=PossiblyInfected0987&*()```


### sentinelone-update-threats-verdict
***
Updates the analyst verdict to a group of threats that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-update-threats-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verdict | Analyst verdict action. Possible values are: undefined, true_positive, false_positive, suspicious. | Required | 
| threat_ids | A comma-separated list of threat IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Updated | Boolean | Whether the threat was successfully updated in the analyst verdict. | 
| SentinelOne.Threat.Update.Action | String | Name of the analyst verdict action performed on the threats. | 

#### Command Example
```!sentinelone-update-threats-verdict threat_ids="14417837215288624" action=false_positive```


### sentinelone-update-alerts-verdict
***
Updates the analyst verdict to a group of alerts that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-update-alerts-verdict`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verdict | Analyst verdict action. Possible values are: undefined, true_positive, false_positive, suspicious. | Required | 
| alert_ids | A comma-separated list of alert IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Alert.ID | String | The alert ID. | 
| SentinelOne.Alert.Updated | Boolean | Whether the alert was successfully updated in the analyst verdict. | 
| SentinelOne.Alert.Update.Action | String | Name of the analyst verdict action performed on the alerts. | 

#### Command Example
```!sentinelone-update-alerts-verdict threat_ids="14417837215288624" action=false_positive```

### sentinelone-create-star-rule
***
Creates a custom STAR rule. Relevant for API version 2.1.


#### Base Command

`sentinelone-create-star-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the STAR rule. | Required | 
| rule_severity | The rule severity. Possible values are: Low, Medium, High, Critical. | Required | 
| expiration_mode | Type of expiration mode. Possible values are: Permanent, Temporary. | Required | 
| query_type | Type of the query. For now it's "events". Possible values are: events, processes. | Required | 
| query | The query string for which to return events. | Required | 
| description | The description of the STAR rule. | Optional | 
| expiration_date | If expiration mode is "Temporary" then it should be supplied, for example, "2019-08-03T04:49:26.257525Z" . | Optional | 
| site_ids | A comma-separated list of site IDs. | Optional | 
| group_ids | A comma-separated list of Group IDs. | Optional | 
| account_ids | A comma-separated list of Account IDs. | Optional | 
| network_quarantine | Whether to enable the network quarantine of the STAR rule. Possible values are: true, false. | Required | 
| treatAsThreat | The treatAsThreat type. Possible values are: Malicious, Suspicious, UNDEFINED. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.StarRule.ID | String | The STAR rule ID. | 
| SentinelOne.StarRule.Name | String | The STAR rule name. | 
| SentinelOne.StarRule.Status | String | The status of the STAR rule. | 
| SentinelOne.StarRule.Severity | String | The severity of the STAR rule. | 
| SentinelOne.StarRule.Description | String | The description of the STAR rule. | 
| SentinelOne.StarRule.NetworkQuarantine | Boolean | The network quarantine of the STAR rule. | 
| SentinelOne.StarRule.TreatAsThreat | String | The Treat As Threat of the STAR rule. | 
| SentinelOne.StarRule.ExpirationMode | String | The expiration mode of the STAR rule. | 
| SentinelOne.StarRule.ExpirationDate | String | The expiration date of the STAR rule. | 
| SentinelOne.StarRule.ScopeHierarchy | String | The scope hierarchy of the STAR rule. | 
| SentinelOne.StarRule.CreatedAt | String | The created time for the STAR rule. | 
| SentinelOne.StarRule.UpdatedAt | String | The updated time for the STAR rule. | 

#### Command Example
```!sentinelone-create-star-rule name="test" rule_severity=Low expiration_mode=Temporary expiration_date=2022-06-23T09:29:29.206941Z query_type=events query="Dstip EXISTS" network_quarantine=false treatAsThreat=Malicious ```


### sentinelone-get-star-rules
***
Get a list of custom detection rules for a given scope. Relevant for API version 2.1.


#### Base Command

`sentinelone-get-star-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | A comma-separated list of the status of the STAR rule. Available options are: "Activating, Active, Deleted, Deleting, Disabled, Disabling and Draft".Example: "Draft,Active". | Optional | 
| creator_contains | Free-text filter by rule creator (supports multiple values). Example: "Service Pack 1". | Optional | 
| queryType | Return rules with the filtered type. Example: "events". Possible values are: events, processes. | Optional | 
| query | Free-text filter by S1 query (supports multiple values). Example: "Service Pack 1". | Optional | 
| description_contains | Free-text filter by rule description (supports multiple values). Example: "Service Pack 1". | Optional | 
| ruleIds | A comma-separated list of Rules IDs. Example: "225494730938493804,225494730938493915". | Optional | 
| name_contains | Free-text filter by rule name (supports multiple values). Example: "Service Pack 1". | Optional | 
| accountIds | A comma-separated list of Account IDs to filter by. Example: "225494730938493804,225494730938493915". | Optional | 
| expirationMode | Return rules with the filtered expiration mode. Example: "Permanent". Possible values are: Temporary, Permanent. | Optional | 
| limit | Limit number of returned items (1-1000). Example: "10". | Optional | 
| siteIds | A comma-separated list of site IDs to filter by. Example: "225494730938493804,225494730938493915". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.StarRule.ID | Number | The STAR rule ID. | 
| SentinelOne.StarRule.Creator | string | The STAR rule creator. | 
| SentinelOne.StarRule.Name | string | The STAR rule name. | 
| SentinelOne.StarRule.Status | string | The STAR rule status. | 
| SentinelOne.StarRule.Severity | string | The STAR rule severity. | 
| SentinelOne.StarRule.GeneratedAlerts | Number | The number of STAR rule generated alerts. | 
| SentinelOne.StarRule.Description | string | The STAR rule description. | 
| SentinelOne.StarRule.StatusReason | string | The STAR rule status reason. | 
| SentinelOne.StarRule.ExpirationMode | string | The STAR rule expiration mode. | 
| SentinelOne.StarRule.ExpirationDate | Date | The STAR rule expiration date. | 
| SentinelOne.StarRule.Expired | Boolean | Whether the STAR rule expired. | 

#### Command Example
```!sentinelone-get-star-rules```

### sentinelone-update-star-rule
***
Updates a custom STAR rule. Relevant for API version 2.1.


#### Base Command

`sentinelone-update-star-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID  Example: "225494730938493804". | Required | 
| name | The name of the STAR rule. | Required | 
| rule_severity | The rule severity. Possible values are: Low, Medium, High, Critical. | Required | 
| expiration_mode | Type of expiration mode. Possible values are: Permanent, Temporary. | Required | 
| query_type | Type of the query. For now it's "events". Possible values are: events, processes. | Required | 
| query | The query string for which to return events. | Required | 
| description | The description of the STAR rule. | Optional | 
| expiration_date | If expiration mode is "Temporary" then it should be supplied, for example, "2019-08-03T04:49:26.257525Z". | Optional | 
| site_ids | A comma-separated list of site IDs. | Optional | 
| group_ids | A comma-separated list of group IDs. | Optional | 
| account_ids | A comma-separated list of account IDs. | Optional | 
| network_quarantine | Whether to enable the network quarantine of the STAR rule. Possible values are: true, false. | Required | 
| treatAsThreat | The treatAsThreat. Possible values are: Malicious, Suspicious, UNDEFINED. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.StarRule.ID | String | The STAR rule ID. | 
| SentinelOne.StarRule.Name | String | The STAR rule name. | 
| SentinelOne.StarRule.Status | String | The status of the STAR rule. | 
| SentinelOne.StarRule.Severity | String | The severity of the STAR rule. | 
| SentinelOne.StarRule.Description | String | The description of the STAR rule. | 
| SentinelOne.StarRule.NetworkQuarantine | Boolean | The network quarantine of the STAR rule. | 
| SentinelOne.StarRule.TreatAsThreat | String | The Treat As Threat of the STAR rule. | 
| SentinelOne.StarRule.ExpirationMode | String | The expiration mode of the STAR rule. | 
| SentinelOne.StarRule.ExpirationDate | String | The expiration date of the STAR rule. | 
| SentinelOne.StarRule.ScopeHierarchy | String | The scope hierarchy of the STAR rule. | 
| SentinelOne.StarRule.CreatedAt | String | The created time for the STAR rule. | 
| SentinelOne.StarRule.UpdatedAt | String | The updated time for the STAR rule. | 


#### Command Example
```!sentinelone-update-star-rule rule_id=225494730938493804 name="test" rule_severity=Low expiration_mode=Temporary expiration_date=2022-06-23T09:29:29.206941Z query_type=events query="Dstip EXISTS" network_quarantine=false treatAsThreat=Malicious ```


### sentinelone-enable-star-rules
***
Activate Custom Detection rules that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-enable-star-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_ids | A comma-separated list of STAR rule IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.StarRule.ID | String | The Rule ID. | 
| SentinelOne.StarRule.Enabled | Boolean | Whether the star rule was successfully eabled or not. | 

#### Command Example
```!sentinelone-enable-star-rules rule_ids=225494730938493804```

### sentinelone-disable-star-rules
***
Disable Custom Detection rules that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-disable-star-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_ids | A comma-separated list of STAR rule IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.StarRule.ID | String | The Rule ID. | 
| SentinelOne.StarRule.Disabled | Boolean | Whether the star rule was successfully disabled or not. | 

#### Command Example
```!sentinelone-disable-star-rules rule_ids=225494730938493804```

### sentinelone-delete-star-rule
***
Deletes Custom Detection Rules that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-delete-star-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_ids | A comma-separated list of STAR rule IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.StarRule.ID | String | The Rule ID. | 
| SentinelOne.StarRule.Deleted | Boolean | Whether the STAR rule was successfully deleted. | 

### sentinelone-get-blocklist
***
Add a hash to the blocklist ("blacklist" in SentinelOne documentation). If the `global` flag is `true`, then group_ids, site_ids, and account_ids are ignored.


#### Base Command

`sentinelone-get-blocklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| global | Whether the global list is accessible. (Same as `tenant` flag in API docs.). Possible values are: true, false. Default is true. | Optional | 
| group_ids | Comma-separated list of group IDs to filter by. | Optional | 
| site_ids | Comma-separated list of site IDs to filter by. | Optional | 
| account_ids | Comma-separated list of account IDs to filter by. | Optional | 
| offset | The number of records to skip (for paging). Default is 0. | Optional | 
| limit | The maximum number of records to return. Default is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Blocklist.UserId | String | User ID. | 
| SentinelOne.Blocklist.UpdatedAt | String | When entry was most recently updated. | 
| SentinelOne.Blocklist.Value | String | File hash. | 
| SentinelOne.Blocklist.ScopePath | String | SentinelOne list scope. | 
| SentinelOne.Blocklist.Type | String | Block list type. | 
| SentinelOne.Blocklist.Source | String | Source of entry. | 
| SentinelOne.Blocklist.ID | String | Entry ID. | 
| SentinelOne.Blocklist.CreatedAt | String | Date entry was created. | 
| SentinelOne.Blocklist.Description | String | Description of the blocklist. | 
| SentinelOne.Blocklist.OSType | String | Operating system type block is enforced on. | 
| SentinelOne.Blocklist.ScopeName | String | Name of the blocklist scope. | 

#### Command Example
```!sentinelone-get-blocklist account_ids=ACCOUNT_ID global=true offset=0 limit=1```

### sentinelone-add-hash-to-blocklist
***
Add a hash to the global blocklist in SentinelOne.


#### Base Command

`sentinelone-add-hash-to-blocklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | SHA1 hash to add to the global blocklist. | Optional | 
| source | String describing the source of the block. Default is XSOAR. | Optional | 
| os_type | Type of operating system. Possible values are: windows, linux, macos. | Required | 
| description | Note stored in SentinelOne about the block. Default is Blocked from XSOAR. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.AddHashToBlocklist.hash | unknown | Hash of the file. | 
| SentinelOne.AddHashToBlocklist.status | unknown | Status of the action to add a hash to the blocklist. | 

#### Command Example
```!sentinelone-add-hash-to-blocklist os_type=windows description="EICAR Test File" sha1=3395856ce81f2b7382dee72602f798b642f14140 source=XSOAR```

### sentinelone-fetch-file
***
Invokes a fetch files command against an agent endpoint.


#### Base Command

`sentinelone-fetch-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID to retrieve the file from. | Required | 
| file_path | File path to download the file from. | Required | 
| password | Password to protect the zip file with. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sentinelone-fetch-file agent_id=AGENT_ID file_path="C:\Test\Path\To\File.txt" password=PossiblyInfected0987&*()```

### sentinelone-download-fetched-file
***
Download a file fetched using th sentinelone-fetch-file command to submit the request and the sentinelone-get-activities command to get the download path.


#### Base Command

`sentinelone-download-fetched-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | SentinelOne agent ID. Default is Agent ID. | Required | 
| activity_id | Activity ID in the get-activities command. | Required | 
| password | Password used in the sentinelone-fetch-file command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sentinelone-download-fetched-file activity_id=ACTIVITY_ID agent_id=AGENT_ID password=PossiblyInfected0987&*()```

### sentinelone-write-threat-note
***
Add a threat note to one or more threats. Relevant for API version 2.1.


#### Base Command

`sentinelone-write-threat-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | A comma-separated list of threat IDs. | Required | 
| note | Threat Note Text. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Note | String | The threat note. | 
| SentinelOne.Threat.Status | String | Whether the note was added successfully. | 

#### Command Example
```!sentinelone-write-threat-note threat_ids=14417837215288624 note="a sample test"```

### sentinelone-create-ioc
***
Add an IoC to the Threat Intelligence database. Relevant for API version 2.1.


#### Base Command

`sentinelone-create-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Threat Intelligence indicator name. | Required | 
| source | The source of the identified Threat Intelligence indicator. | Required | 
| type | The type of the Threat Intelligence indicator. Possible values are: DNS, IPV4, IPV6, MD5, SHA1, SHA256, URL. | Required | 
| method | The comparison method used by SentinelOne to trigger the event. Possible values are: EQUALS. | Required | 
| validUntil | Expiration date for the Threat Intelligence indicator. | Required | 
| value | The value of the Threat Intelligence indicator. | Required | 
| account_ids | List of account IDs to filter by. | Required | 
| externalId | The unique identifier of the indicator as provided by the Threat Intelligence source. | Optional | 
| description | Description of the Threat Intelligence indicator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.IOC.UUID | String | The IOC UUID. | 
| SentinelOne.IOC.Name | String | Threat Intelligence indicator name. | 
| SentinelOne.IOC.Source | String | The source of the identified Threat Intelligence indicator. | 
| SentinelOne.IOC.Type | String | The type of the Threat Intelligence indicator. | 
| SentinelOne.IOC.BatchId | String | The IOC batch ID. | 
| SentinelOne.IOC.Creator | String | The IOC creator. | 
| SentinelOne.IOC.Scope | String | The IOC scope. | 
| SentinelOne.IOC.ScopeId | String | The IOC scope ID. | 
| SentinelOne.IOC.ValidUntil | String | Expiration date for the Threat Intelligence indicator. | 
| SentinelOne.IOC.Description | String | Description of the Threat Intelligence indicator. | 
| SentinelOne.IOC.ExternalId | String | The unique identifier of the indicator as provided by the Threat Intelligence source. | 

#### Command Example
```!sentinelone-create-ioc name="test" source="proof_test" type="IPV4" method="EQUALS" validUntil="2022-06-25T07:52:09.428858Z" value="10.0.2.15" account_ids="106802936546889425464"```


### sentinelone-delete-ioc
***
Delete an IOC from the Threat Intelligence database that matches a filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-delete-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | List of account IDs to filter by. | Required | 
| uuids | UUID of Threat Intelligence indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.IOC.UUID | String | The IOC UUID. | 
| SentinelOne.IOC.Deleted | Boolean | Whether the Threat Intelligence indicator was deleted. | 

#### Command Example
```!sentinelone-delete-ioc account_ids=106802961889425793 uuids=ef367d66175288e75fa6b29c53d46d4```

### sentinelone-get-iocs
***
Get the IOCs of a specified account that match the filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-get-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | List of account IDs to filter by. | Required | 
| limit | Limit number of returned items (1-1000). Default is 1000. | Optional | 
| upload_time_gte | The time (greater than or equal to) at which the Threat Intelligence indicator was uploaded to the SentinelOne database. Example: "2022-07-13T20:33:29.007906Z". | Optional | 
| upload_time_lte | The time (less than or equal to) at which the Threat Intelligence indicator was uploaded to the SentinelOne database. Example: "2022-07-13T20:33:29.007906Z". | Optional | 
| cursor | Cursor position returned by the last request. Should be used for iterating over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=". | Optional | 
| uuids | A list of unique IDs of the parent process of the indicator of compromise. Example: "2cffae871197f20d864fe8363eee6651". | Optional | 
| type | The type of the Threat Intelligence indicator. Possible values are: DNS, IPV4, IPV6, MD5, SHA1, SHA256, URL. | Optional | 
| batch_id | Unique ID of the uploaded indicators batch. Example: "atmtn000000028a881bcf939dc6d92ab55443". | Optional | 
| source | List of the sources of the identified Threat Intelligence indicator. Example: "AlienVault". | Optional | 
| value | The value of the Threat Intelligence indicator. Example: "175.0.x.x". | Optional | 
| external_id | The unique identifier of the indicator as provided by the Threat Intelligence source. Example: "e277603e-1060-5ad4-9937-c26c97f1ca68". | Optional | 
| name_contains | A comma-separated list of free-text filtered by the indicator name. Example: "foo.dll". | Optional | 
| creator_contains | A comma-separated list of free-text filtered by the user who uploaded the Threat Intelligence indicator. Example: "admin@sentinelone.com". | Optional | 
| description_contains | A comma-separated list of free-text filtered by the description of the indicator. Example: "Malicious-activity". | Optional | 
| category_in | The categories of the Threat Intelligence indicator. Example: The malware type associated with the IOC. | Optional | 
| updated_at_gte | The time (greater or equal to) at which the indicator was last updated in the SentinelOne database. Example: "2021-07-13T20:33:29.007906Z". | Optional | 
| updated_at_lte | The time (less than or equal to) at which the indicator was last updated in the SentinelOne database. Example: "2021-07-13T20:33:29.007906Z". | Optional | 
| creation_time_gte | Creation time (greater than or equal to) as set by the user. Example: "2021-07-13T20:33:29.007906Z". | Optional | 
| creation_time_lte | Creation time (less than or equal to) as set by the user. Example: "2021-07-13T20:33:29.007906Z". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.IOC.UUID | String | The IOC UUID. | 
| SentinelOne.IOC.Creator | String | Threat Intelligence indicator creator. | 
| SentinelOne.IOC.Name | String | Threat Intelligence indicator name. | 
| SentinelOne.IOC.Value | String | Threat Intelligence indicator value. | 
| SentinelOne.IOC.Description | String | Threat Intelligence indicator description. | 
| SentinelOne.IOC.Type | String | Threat Intelligence indicator type. | 
| SentinelOne.IOC.ExternalId | String | Threat Intelligence indicator external ID. | 
| SentinelOne.IOC.Source | String | Threat Intelligence indicator source. | 
| SentinelOne.IOC.UploadTime | String | Threat Intelligence indicator upload time. | 
| SentinelOne.IOC.ValidUntil | String | Threat Intelligence indicator expiration time. | 

#### Command Example
```!sentinelone-get-iocs account_ids="1068029618885547693" upload_time_gte="2022-04-25T07:52:09.428858Z" upload_time_lte="2022-06-30T07:52:09.428858Z"```


### sentinelone-create-power-query
***
Start a Deep Visibility Power query to get back status and potential results (ping afterwards using the queryId if query has not finished). Relevant for API version 2.1


#### Base Command

`sentinelone-create-power-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Events matching the query search term will be returned. | Required | 
| from_date | Events created after this timestamp. | Required | 
| to_date | Events created before or at this timestamp. | Required | 
| limit | Limit number of returned items (1-100000). | Optional | 


#### Context Output

The context outputs are based on the power query

#### Command Example
```!sentinelone-create-power-query query="event.time = * | columns eventTime = event.time, agentUuid = agent.uuid" from_date="2022-06-05T04:49:26.257525Z" to_date="2022-06-07T04:49:26.257525Z"```

### sentinelone-ping-power-query
***
Ping a Deep Visibility Power query using the queryId argument if results have not returned from an initial Power query or a previous ping. Relevant for API version 2.1.

#### Base Command

`sentinelone-ping-power-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryId | QueryId. | Required | 


#### Context Output

The context outputs are based on the power query

#### Command Example
```!sentinelone-ping-power-query queryId="pqe18ccaaa69fedc65889eb155dbe039"```
### sentinelone-update-threats-status
***
Updates the incident status to a group of threats that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-update-threats-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Incident status. Possible values are: in_progress, resolved, unresolved. | Required | 
| threat_ids | A comma-separated list of threat IDs. | Required | 

#### Command Example
```!sentinelone-update-threats-status status=in_progress threat_ids=67683743445454363```


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Updated | Boolean | Whether the threat was successfully updated. | 
| SentinelOne.Threat.Status | String | Name of the status performed on the threats. | 

### sentinelone-update-alerts-status
***
Updates the incident status to a group of alerts that match the specified input filter. Relevant for API version 2.1.


#### Base Command

`sentinelone-update-alerts-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Incident status. Possible values are: in_progress, resolved, unresolved. | Required | 
| alert_ids | A comma-separated list of alert IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Alert.ID | String | The alert ID. | 
| SentinelOne.Alert.Updated | Boolean | Whether the alert was successfully updated. | 
| SentinelOne.Alert.Status | String | The status performed on the alerts. | 

#### Command Example
```!sentinelone-update-alerts-status status=in_progress alert_ids=36386764344636343```

### sentinelone-expire-site
***
Expire the site of the given ID


#### Base Command

`sentinelone-expire-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A valid site ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Site.ID | String | The site ID. | 
| SentinelOne.Site.Name | String | The site name. | 
| SentinelOne.Site.State | String | The site state. | 
| SentinelOne.Site.SKU | String | The SKU of product features active for this site. | 
| SentinelOne.Site.SiteType | String | The site type. | 
| SentinelOne.Site.Suite | String | The site suite. | 
| SentinelOne.Site.TotalLicenses | String | The total licenses. | 
| SentinelOne.Site.AccountID | String | The account ID. | 
| SentinelOne.Site.Creator | String | Full name of the creating user. | 
| SentinelOne.Site.CreatorID | String | ID of the creating user. | 
| SentinelOne.Site.Description | String | Description of the site. | 
| SentinelOne.Site.Expiration | String | Expiration date of the site. | 


### sentinelone-fetch-threat-file
***
Fetch a file associated with the threat that matches the filter.


#### Base Command

`sentinelone-fetch-threat-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | Please provide the Valid Threat ID. Example: 14629133470822878. | Required | 
| password | File encryption password. (At least 10 characters, three out of this list "uppercase", "lowercase", "digits" and "symbols" are mandatory. Maximum length is 256 characters.). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Threat.ID | String | The threat ID. | 
| SentinelOne.Threat.Downloadable | Boolean | Whether the file is downloadable. | 
| SentinelOne.Threat.ZippedFile | String | Details of the zipped folder. | 


#### Command Example
```!sentinelone-fetch-threat-file threat_ids=106802961889425793 password=Mypassword1!```


### sentinelone-get-alerts
***
Get the list of alerts that matches the filter provided. Relevant for API version 2.1.


#### Base Command

`sentinelone-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_from | Greater than or equal to the time created. Example: "2018-02-27T04:49:26.257525Z". | Required | 
| created_until | Less than or equal to the time created. Example: "2018-02-27T04:49:26.257525Z". | Required | 
| ruleName | Free-text filter by rule name. Example: "rule1". | Optional | 
| incidentStatus | Incident status. Example: "IN_PROGRESS". | Optional | 
| analystVerdict | Analyst verdict. Example: "TRUE_POSITIVE". | Optional | 
| alert_ids | A comma-separated list of alert IDs. | Optional | 
| limit | Limit number of returned items (1-1000). Default is 1000. | Optional | 
| site_ids | A comma-separated list of site IDs to filter by. Example: "225494730938493804,225494730938493915". | Optional | 
| cursor | Cursor position returned by the last request. Should be used for iterating over more than 1000 items. Example: "YWdlbnRfaWQ6NTgwMjkzODE=". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Alert.EventType | String | Event type. | 
| SentinelOne.Alert.RuleName | String | The rule name. | 
| SentinelOne.Alert.SrcProcUser | String | Source process user. | 
| SentinelOne.Alert.SrcProcName | String | Source process name. | 
| SentinelOne.Alert.SrcProcPath | String | Source process file path. | 
| SentinelOne.Alert.SrcProcCommandline | String | The command line | 
| SentinelOne.Alert.SrcProcSHA1 | String | Source process SHA1 file hash. | 
| SentinelOne.Alert.SrcProcStartTime | String | PID start time. | 
| SentinelOne.Alert.SrcProcStorylineId | String | Source process story line ID. | 
| SentinelOne.Alert.SrcParentProcName | String | Source parent process name. | 
| SentinelOne.Alert.SrcParentProcPath | String | Source parent process file path. | 
| SentinelOne.Alert.SrcParentProcCommandline | String | Source parent process command line. | 
| SentinelOne.Alert.SrcParentProcStartTime | String | PID start time. | 
| SentinelOne.Alert.SrcParentProcUser | String | Source parent process user. | 
| SentinelOne.Alert.SrcParentProcSHA1 | String | Source parent process SHA1 file hash. | 
| SentinelOne.Alert.SrcProcSignerIdentity | String | Source process file signer identity. | 
| SentinelOne.Alert.SrcParentProcSignerIdentity | String | Source parent process file signer identity. | 
| SentinelOne.Alert.AlertCreatedAt | String | The the alert was created. | 
| SentinelOne.Alert.AlertId | String | Alert ID. | 
| SentinelOne.Alert.AnalystVerdict | String | Analyst verdict. | 
| SentinelOne.Alert.IncidentStatus | String | Incident status | 
| SentinelOne.Alert.EndpointName | String | Endpoint name | 
| SentinelOne.Alert.AgentId | String | Agent ID. | 
| SentinelOne.Alert.AgentUUID | String | Agent UUID. | 
| SentinelOne.Alert.dvEventId | String | Deep Visibility event ID. | 
| SentinelOne.Alert.AgentOS | String | Agent operating system. | 
| SentinelOne.Alert.AgentVersion | String | Agent version. | 
| SentinelOne.Alert.SiteId | String | Site ID. | 
| SentinelOne.Alert.RuleId | String | Rule ID. | 

#### Command Example
```!sentinelone-get-alerts created_from=2012-02-27T04:49:26.257525Z created_until=2012-05-27T04:49:26.257525Z```


### sentinelone-get-installed-applications
***
Get the installed applications for a specific agent.


#### Base Command

`sentinelone-get-installed-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_ids | A comma-separated list of agent IDs. Example: 14629133470822878,14627455454652878. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Application.Name | String | The application name. | 
| SentinelOne.Application.Publisher | String | The publisher. | 
| SentinelOne.Application.Size | String | The size of the application in bytes. | 
| SentinelOne.Application.Version | String | The version of the application. | 
| SentinelOne.Application.InstalledOn | String | The date the application was installed. | 

#### Command Example
```!sentinelone-get-installed-applications agent_ids="1463801667584541849,1463801667584545236"```


### sentinelone-initiate-endpoint-scan
***
Initiate the endpoint virus scan on provided agent IDs.


#### Base Command

`sentinelone-initiate-endpoint-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_ids | A comma-separated list of Agent IDs. Example: 14629133470822878,14627455454652878. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Agent.AgentID | String | The Agent ID. | 
| SentinelOne.Agent.Initiated | Boolean | Whether the scan was initiated. |

#### Command Example
```!sentinelone-initiate-endpoint-scan agent_ids="1463801667584541849,1463801667584545236"```

