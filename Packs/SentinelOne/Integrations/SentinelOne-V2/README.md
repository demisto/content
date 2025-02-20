Use the SentinelOne integration to send requests to your management server and get responses with data pulled from agents or from the management database.
This integration was integrated and tested with versions 2.0 and 2.1 of SentinelOne V2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-sentinelone-v2).

## Configure SentinelOne v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://usea1.sentinelone.net) |  | True |
| API Token |  | False |
| API Version |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Fetch incidents from type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
| Minimum risk score for importing incidents (0-10), where 0 is low risk and 10 is high risk. Relevant for API version 2.0. |  | False |
| Defines Alert severity to fetch. |  | False |
| Define which Alerts should be fetched. |  | False |
| Define which Threats should be fetched. |  | False |
| Fetch limit: The maximum number of threats or alerts to fetch |  | False |
| Site IDs | Comma-separated list of site IDs to fetch incidents for. Leave blank to fetch all sites. | False |
| Block Site IDs | Comma-separated list of site IDs for where hashes should be blocked. If left blank all hashes will be blocked globally. If filled out with site ids all hashes will be no longer be blocked globally, they will now be blocked in the scope of those sites. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| API Token (Deprecated) | Use the "API Token \(Recommended\)" parameter instead. | False |
| Incidents Fetch Interval |  | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from SentinelOne to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to SentinelOne\), or Incoming and Outgoing \(from/to Cortex XSOAR and SentinelOne\). | False |
| Close Mirrored XSOAR Incident | When selected, closing the SentinelOne ticket is mirrored in Cortex XSOAR. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### sentinelone-list-agents

***
Returns all agents that match the specified criteria.

#### Base Command

`sentinelone-list-agents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_name | The computer name by which to filter the results. It can match a partial computer name value (substring). | Optional | 
| scan_status | A comma-separated list of scan statuses by which to filter the results, for example: "started,aborted". Possible values are: started, none, finished, aborted. | Optional | 
| os_type | Included operating system types, for example: "windows". Possible values are: windows, windows_legacy, macos, linux. | Optional | 
| created_at | Endpoint creation timestamp, for example: "2018-02-27T04:49:26.257525Z". | Optional | 
| min_active_threats | Minimum number of threats per agent. | Optional | 
| limit | The maximum number of agents to return. Default is 10. | Optional | 
| params | Query params field=value pairs delimited by comma (e.g., activeThreats=3,gatewayIp=1.2.3.4). Query params are OR'd. | Optional | 
| columns | A comma-separated list of additionals fields to display. | Optional |

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
| SentinelOne.Agents.MachineType | string | Machine type. |
| SentinelOne.Agents.Domain | string | Domain name of the agent. | 
| SentinelOne.Agents.CreatedAt | date | Creation time of the agent. | 
| SentinelOne.Agents.SiteName | string | Site name associated with the agent. | 
| SentinelOne.Agents.Tags | unknown | Tags associated with the agent. | 

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
| include_parent | Whether to include parent information of each item. Default value is false. Default is false. | Optional | 
| include_children | Whether to include children information of each item. Default value is false. Default is false. | Optional | 

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

### sentinelone-get-hash

***
Gets the file reputation verdict by a SHA1 hash.

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
| SentinelOne.Hash.Verdict | String | The hash reputation verdict. | 
| SentinelOne.Hash.Hash | String | The content hash. | 

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
| created_before | Searches for threats created before this timestamp, for example: "2018-02-27T04:49:26.257525Z", "10 days", "5 months", "2 hours". | Optional | 
| created_after | Searches for threats created after this timestamp, for example: "2018-02-27T04:49:26.257525Z", "10 days", "5 months", "2 hours". | Optional | 
| created_until | Searches for threats created on or before this timestamp, for example: "2018-02-27T04:49:26.257525Z", "10 days", "5 months", "2 hours". | Optional | 
| created_from | Search for threats created on or after this timestamp, for example: "2018-02-27T04:49:26.257525Z", "10 days", "5 months", "2 hours". | Optional | 
| resolved | Whether to only return resolved threats. Possible values are: false, true. Default is false. | Optional | 
| display_name | Threat display name. For API version 2.0 it can be a partial display name, doesn't have to be an exact match. | Optional | 
| limit | The maximum number of threats to return. Default is 20. | Optional | 
| query | Full free-text search for fields. Can be "content_hash", "file_display_name", "file_path", "computer_name", or "uuid". | Optional | 
| threat_ids | A comma-separated list of threat IDs, for example: "225494730938493804,225494730938493915". | Optional | 
| classifications | A comma-separated list of threat classifications to search, for example: "Malware", "Network", "Benign". Possible values are: Engine, Static, Cloud, Behavioral. | Optional | 
| rank | Risk level threshold to retrieve (1-10). Relevant for API version 2.0 only. | Optional | 
| site_ids | A comma-separated list of site IDs to search for threats, for example: "225494730938493804,225494730938493915". | Optional |
| incident_statuses | Incident status. Example: "IN_PROGRESS, UNRESOLVED". | Optional |
| include_resolved_param | Whether to include the resolved parameter in the query. Possible values are: false, true. Default is false. | Optional | 

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

### sentinelone-threat-summary

***
Returns a dashboard threat summary. Can only be used with API V2.1.

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
| SentinelOne.Threat.Mitigation.Action | String | The mitigation action performed. | 

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
| SentinelOne.Agent.MachineType | string | Machine type. |
| SentinelOne.Agent.Domain | string | Domain name of the agent. | 
| SentinelOne.Agent.CreatedAt | date | Agent creation time. | 
| SentinelOne.Agent.SiteName | string | Site name associated with the agent. | 

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.DeleteGroup.Success | String | The status of the command. | 

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
| SentinelOne.Agent.NetworkStatus | String | Agent network status. | 
| SentinelOne.Agent.ID | String | Input agents' IDs. | 

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
| SentinelOne.Agent.ID | String | Input agents' IDs. | 

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
| SentinelOne.BroadcastMessage.Affected | String | Number of affected endpoints. | 

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
| cursor | Cursor pointer to get next page of results from query. | Optional | 
| columns | A comma-separated list of additionals fields to display. | Optional |

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
| SentinelOne.Event.SourceIP | String | The source ip. | 
| SentinelOne.Event.SourcePort | String | The source port. | 
| SentinelOne.Event.DestinationIP | String | The destination IP. | 
| SentinelOne.Event.DestinationPort | String | The destination port. | 
| SentinelOne.Event.SourceProcessUser | String | The source process user. | 
| SentinelOne.Event.SourceProcessCommandLine | String | The source process command line. | 
| SentinelOne.Event.DNSRequest | String | The DNS Request. | 
| SentinelOne.Event.FileFullName | String | The file full name. | 
| SentinelOne.Event.EventTime | String | The event time. | 
| Event.ID | String | Event process ID. | 
| Event.Name | String | Event name. | 
| Event.Type | String | Event type. | 
| SentinelOne.Cursor.Event | String | cursor to recieve next page | 

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
| SentinelOne.uninstall.Affected | String | Number of affected agents. | 

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
| SentinelOne.StarRule.Enabled | Boolean | Whether the STAR rule was successfully enabled. | 

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
| SentinelOne.StarRule.Disabled | Boolean | Whether the STAR rule was successfully disabled. | 

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
| hash | Hash to search for in the blocklist. | Optional | 

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

### sentinelone-remove-hash-from-blocklist

***
Remove a hash from the global blocklist in SentinelOne

#### Base Command

`sentinelone-remove-hash-from-blocklist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha1 | SHA1 hash to remove from the global blocklist. | Optional | 
| os_type | Optional operating system type. If not supplied, will remove the SHA1 hash across all platforms. Possible values are: windows, macos, linux. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.RemoveHashFromBlocklist.hash | unknown | Hash of the file. | 
| SentinelOne.RemoveHashFromBlocklist.status | unknown | Status of the action to remove a hash from the blocklist. | 

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

### sentinelone-create-power-query

***
Deprecated. Start a Deep Visibility Power query to get back status and potential results (ping afterwards using the queryId if query has not finished). Relevant for API version 2.1

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

There is no context output for this command.
### sentinelone-ping-power-query

***
Deprecated. Ping a Deep Visibility Power query using the queryId argument if results have not returned from an initial Power query or a previous ping. Relevant for API version 2.1.

#### Base Command

`sentinelone-ping-power-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queryId | QueryId. | Required | 

#### Context Output

There is no context output for this command.
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

### sentinelone-get-alerts

***
Get the list of alerts that matches the filter provided. Relevant for API version 2.1.

#### Base Command

`sentinelone-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| created_from | Greater than or equal to the time created. Example: "2018-02-27T04:49:26.257525Z", "10 days", "2 hours","5 months". | Required | 
| created_until | Less than or equal to the time created. Example: "2018-02-27T04:49:26.257525Z", "10 days", "2 hours","5 months". | Optional | 
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

### sentinelone-remove-item-from-whitelist

***
Remove an item from the SentinelOne exclusion list

#### Base Command

`sentinelone-remove-item-from-whitelist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item | Value of the item to be removed from the exclusion list. | Required | 
| os_type | OS type. Can be "windows", "windows_legacy", "macos", or "linux". Possible values are: windows, windows_legacy, macos, linux. | Optional | 
| exclusion_type | Exclusion item type. The options are: file_type, path, white_hash, certificate, or browser. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.RemoveItemFromWhitelist.status | String | Status on if items were removed from whitelist or not found on whitelist. | 
| SentinelOne.RemoveItemFromWhitelist.item | String | Item removed fom whitelist. | 

### sentinelone-run-remote-script

***
Run a remote script that was uploaded to the SentinelOne Script Library.

#### Base Command

`sentinelone-run-remote-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. | Required | 
| output_destination | Output destination. Possible values: DataSetCloud/Local/None/SentinelCloud. Possible values are: DataSetCloud, Local, None, SentinelCloud. | Required | 
| task_description | Task description. | Required | 
| script_id | Script ID. | Required | 
| output_directory | Output directory. | Optional | 
| agent_ids | A comma-separated list of agent IDs on which the script should run. | Required | 
| singularity_xdr_Keyword | Singularityxdr keyword. | Optional |
| singularity_xdr_Url | Singularityxdr keyword. | Optional |
| api_key | Api key. | Optional |
| input_params | Input params. | Optional |
| password | Password. | Optional |
| script_runtime_timeout_seconds | Script runtime timout in seconds for current execution. | Optional |
| requires_approval | If set to true, execution will require approval. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.RunRemoteScript.pendingExecutionId | string | ID of the created pending execution. Present only if pending flag is true. | 
| SentinelOne.RunRemoteScript.pending | boolean | Flag indicating if the requested script execution requires approval and is created as a pending execution. | 
| SentinelOne.RunRemoteScript.affected | number | Number of entities affected by the requested operation. | 
| SentinelOne.RunRemoteScript.parentTaskId | string | The parent task ID of the script execution task. Null in case of pending execution. | 

### sentinelone-get-remote-script-task-status

***
Get remote script tasks using a variety of filters.

#### Base Command

`sentinelone-get-remote-script-task-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. Example: '225494730938493804,225494730938493915'. | Optional | 
| computer_name_contains | Free-text filter by agent computer name (supports multiple values). | Optional | 
| count_only | If true, only total number of items will be returned, without any of the actual objects. | Optional | 
| created_at_gt | Created at greater than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional | 
| created_at_gte | Created at greater or equal than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional | 
| created_at_lt | Created at lesser than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional | 
| created_at_lte | Created at lesser or equal than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional |
| cursor | Cursor position returned by the last request. Use to iterate over more than 1000 items. Example: 'YWdlbnRfaWQ6NTgwMjkzODE='. | Optional |
| description_contains | Only include tasks with specific description. | Optional |
| detailed_status_contains | Only include tasks with specific detailed status. | Optional |
| group_ids | Comma-separated list of Group IDs to filter by. Example: '225494730938493804,225494730938493915'. | Optional |
| ids | Comma-separated list of IDs to filter by. Example: '225494730938493804,225494730938493915'. | Optional |
| initiated_by_contains | Only include tasks from specific initiating user. | Optional |
| limit | Limit number of returned items (1-1000). Example: '10'. | Optional |
| parent_task_id | Parent task ID to fetch the status by. Example: '225494730938493804'. | Required |
| parent_task_id_in | Comma-separated list of IDs to filter by. | Optional |
| query | A free-text search term that will match applicable attributes (sub-string match). | Optional |
| site_ids | Comma-separated list of Site IDs to filter by. Example: '225494730938493804,225494730938493915'. | Optional |
| status | Status of the script task. Example: 'created'. | Optional |
| tenant | A tenant scope request. | Optional |
| updated_at_gt | Updated at greater than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional |
| updated_at_gte | Updated at greater or equal than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional |
| updated_at_lt | Updated at lesser than datetime. Example: '2018-02-27T04:49:26.257525Z'.  | Optional |
| updated_at_lte | Updated at lesser or equal than datetime. Example: '2018-02-27T04:49:26.257525Z'. | Optional |
| uuid_contains | Free-text filter by agent UUID (supports multiple values). | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.GetRemoteScript.id | string | ID of the task. | 
| SentinelOne.GetRemoteScript.accountId | string | Account ID where this script is executed. | 
| SentinelOne.GetRemoteScript.accountName | string | Account name where this script is executed. | 
| SentinelOne.GetRemoteScript.agentId | string | Agent ID where this script is executed. |
| SentinelOne.GetRemoteScript.agentIsActive | boolean | The status of the agent. |
| SentinelOne.GetRemoteScript.agentMachineType | string | Agent machine type. |
| SentinelOne.GetRemoteScript.agentOsType | string | Agent operating system type. |
| SentinelOne.GetRemoteScript.agentUuid | string | Agent UUID. |
| SentinelOne.GetRemoteScript.createdAt | string | The script created at datetime. |
| SentinelOne.GetRemoteScript.description | string | The description of the remote script. | 
| SentinelOne.GetRemoteScript.detailedStatus | string | The detailed status of the remote script. |
| SentinelOne.GetRemoteScript.groupId | string | Group ID where this script is executed. |
| SentinelOne.GetRemoteScript.groupName | string | Group name where this script is executed. |
| SentinelOne.GetRemoteScript.initiatedBy | string | Remote script initiate by. |
| SentinelOne.GetRemoteScript.initiatedById | string | ID of the remote script initiator. |
| SentinelOne.GetRemoteScript.parentTaskId | string | Parent task ID of the remote script. |
| SentinelOne.GetRemoteScript.siteId | string | Site ID where this script is executed. |
| SentinelOne.GetRemoteScript.siteName | string | Site name where this script is executed. |
| SentinelOne.GetRemoteScript.status | string  | Status of the remote script. |
| SentinelOne.GetRemoteScript.statusCode | string | Status code of the remote script. |
| SentinelOne.GetRemoteScript.statusDescription | string | Status description of the remote script. |
| SentinelOne.GetRemoteScript.type | string | Type of remote script. |
| SentinelOne.GetRemoteScript.updateAt | string | Remote script upated at. |


### sentinelone-get-remote-script-task-results

***
Get a script's result download URL.

#### Base Command

`sentinelone-get-remote-script-task-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| computer_names | A comma-separated list of partial or whole computer names, which ran scripts. | Optional | 
| task_ids | A comma-separated list of task IDs to get a download link for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.RemoteScriptResults.taskId | string | ID of the task. | 
| SentinelOne.RemoteScriptResults.fileName | string | File name. | 
| SentinelOne.RemoteScriptResults.downloadUrl | string | Download URL. |


### sentinelone-remote-script-automate-results

***
Automate a remote script's execution cycle and return the script's results.

#### Base Command

`sentinelone-remote-script-automate-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. | Required | 
| output_destination | Output destination. Possible values are: DataSetCloud, Local, None, SentinelCloud. | Required | 
| task_description | Task description. | Required | 
| script_id | Script ID. | Required | 
| output_directory | Output directory. | Optional | 
| agent_ids | A comma-separated list of agent IDs on which the script should run. | Required | 
| singularity_xdr_Keyword | Singularity XDR keyword. | Optional |
| singularity_xdr_Url | Singularity XDR URL. | Optional |
| api_key | API key. | Optional |
| input_params | Input parameters. | Optional |
| password | Password. | Optional |
| script_runtime_timeout_seconds | Script runtime timeout in seconds for current execution. | Optional |
| requires_approval | If set to true, execution will require approval. | Optional |
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 60. | Optional |
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 600. | Optional |
| parent_task_id | Parent task ID to fetch the status by. Example: '225494730938493804'. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.RemoteScriptResults.taskId | string | ID of the task. | 
| SentinelOne.RemoteScriptResults.fileName | string | File name. | 
| SentinelOne.RemoteScriptResults.downloadUrl | string | Download URL. |



### sentinelone-get-power-query-results


***
Automate a power query and return the query results. (The maximum timeout of 300 seconds is allowed.)

#### Base Command

`sentinelone-get-power-query-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. | Optional | 
| site_ids | A comma-separated list of site IDs on which the query should run. | Optional | 
| query | Events matching the query search term will be returned. | Required | 
| from_date | Events created after this date. Example: '2018-02-27T04:49:26.257525Z'. | Required | 
| to_date | Events created before or at this date. Example: '2018-02-27T04:49:26.257525Z'. | Required | 
| limit | Limit number of returned items (1-100000). | Optional | 
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. | Optional |
| timeout | Indicates the time in seconds until the polling sequence timeouts. | Optional |
| query_id | QueryId. Example: pq3be5e2747f716cxxxxxxxxxxxxx20a0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.PowerQuery.ResultIndex | List | Result from the power query in list of objects format | 


### get-mapping-fields

***
Returns the list of fields for an incident type.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### update-remote-system

***
Pushes local changes to the remote system.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Get remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required | 
| lastUpdate | Retrieve entries that were created after lastUpdate. | Required | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_update | Retrieve entries that were created after lastUpdate. | Optional | 

#### Context Output

There is no context output for this command.
### sentinelone-get-dv-query-status

***
Returns status of a Deep Visibility Query

#### Base Command

`sentinelone-get-dv-query-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The queryId that is returned when creating a query under Create Query. Example: "q1xx2xx3". Get the query_id from the "get-query-id" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- |--------| --- |
| SentinelOne.Query.Status.progressStatus | string | Progress Query Status | 
| SentinelOne.Query.Status.queryModeInfo.lastActivatedAt | string | Last Activated At | 
| SentinelOne.Query.Status.queryModeInfo.mode | string | Query Mode | 
| SentinelOne.Query.Status.responseState | string | State of the Query | 
| SentinelOne.Query.Status.warnings | string | Warnings during Query | 
| SentinelOne.Query.Status.QueryId | string | QueryID From Request | 

### sentinelone-get-agent-mac

***
Returns network interface details for a given Agent ID. This includes MAC address details and interface description.

#### Base Command

`sentinelone-get-agent-mac`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | AgentId of the System. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.MAC | string | Agent network interface details. | 
| SentinelOne.MAC.agent_id | string | AgentID | 
| SentinelOne.MAC.hostname | string | Hostname | 
| SentinelOne.MAC.int_name | string | Interface Name | 
| SentinelOne.MAC.ip | string | IP Address | 
| SentinelOne.MAC.mac | string | MAC Address | 

### sentinelone-get-accounts

***
Returns details of accounts.

#### Base Command

`sentinelone-get-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Can filter on one account ID. Otherwise, it returns information from all accounts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Accounts.AccountType | string | The account type. | 
| SentinelOne.Accounts.ActiveAgents | number | The account number of active agents. | 
| SentinelOne.Accounts.NumberOfSites | number | The account number of sites. | 
| SentinelOne.Accounts.State | string | The account state. | 
| SentinelOne.Accounts.CreatedAt | string | The account creation date. | 
| SentinelOne.Accounts.Expiration | string | The account expiration date. | 
| SentinelOne.Accounts.ID | string | The account ID. | 
| SentinelOne.Accounts.Name | string | The account name. | 

### sentinelone-get-threat-notes

***
Returns threat notes.

#### Base Command

`sentinelone-get-threat-notes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.Notes.CreatedAt | string | The note creation date. | 
| SentinelOne.Notes.Creator | string | The note creator. | 
| SentinelOne.Notes.CreatorID | string | The note creator ID. | 
| SentinelOne.Notes.Edited | boolean | Whether the note was edited or not.. | 
| SentinelOne.Notes.ID | string | The note ID. | 
| SentinelOne.Notes.Text | string | The note text. | 
| SentinelOne.Notes.UpdatedAt | string | The note updated time. | 

### sentinelone-list-installed-singularity-marketplace-applications

***
Returns all installed singularity marketplace applications that match the specified filter values.

#### Base Command

`sentinelone-list-installed-singularity-marketplace-applications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. | Optional | 
| application_catalog_id | Filter results by application catalog id. | Optional |
| creator_contains | Free-text filter by application creator. | Optional |
| id | A comma-separated list of applications IDs. | Optional |
| name_contains | Free-text filter by application name | Optional |
| site_ids | A comma-separated list of site IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.InstalledApps.ID | string | The application ID. | 
| SentinelOne.InstalledApps.Account | string | The account name. | 
| SentinelOne.InstalledApps.AccountId | string | The account ID. | 
| SentinelOne.InstalledApps.ApplicationCatalogId | string | The application Catalog ID. | 
| SentinelOne.InstalledApps.applicationCatalogName | string | The application Catalog name. | 
| SentinelOne.InstalledApps.AlertMessage | string | The alert message. | 
| SentinelOne.InstalledApps.CreatedAt | date | Application created at. |
| SentinelOne.InstalledApps.Creator | string | Application creator. |
| SentinelOne.InstalledApps.CreatorId | string | Application creator ID. |
| SentinelOne.InstalledApps.DesiredStatus | string | Application desired status. |
| SentinelOne.InstalledApps.HasAlert | boolean | Application has alert. |
| SentinelOne.InstalledApps.LastEntityCreatedAt | date | Application last entity created at. |
| SentinelOne.InstalledApps.Modifier | string | Modifier. |
| SentinelOne.InstalledApps.ModifierId | string | Modifier ID. |
| SentinelOne.InstalledApps.ScopeId | string | The scope ID. |
| SentinelOne.InstalledApps.ScopeLevel | string | The scope level. |
| SentinelOne.InstalledApps.Status | string | Status of application. |
| SentinelOne.InstalledApps.UpdatedAt | string | Application updated at. |
| SentinelOne.InstalledApps.ApplicationInstanceName | string | Application instance name. |


### sentinelone-get-service-users

***
Returns all service users that match the specified filter values.

#### Base Command

`sentinelone-get-service-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. | Optional | 
| role_ids | A comma-separated list of rbac roles to filter by. | Optional |
| ids | A comma-separated list of service user IDs to filter by. | Optional |
| site_ids | A comma-separated list of site IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SentinelOne.ServiceUsers.ID | string | The service user ID. | 
| SentinelOne.ServiceUsers.ApiTokenCreatedAt | date | Api token created at. | 
| SentinelOne.ServiceUsers.ApiTokenExpiresAt | date | Api token expires at. | 
| SentinelOne.ServiceUsers.CreatedAt | date | Service user created at. | 
| SentinelOne.ServiceUsers.CreatedById | string | The service user created by Id. | 
| SentinelOne.ServiceUsers.CreatedByName | string | The service user created by name. |
| SentinelOne.ServiceUsers.Description | string |  Service user description. |
| SentinelOne.ServiceUsers.LastActivation | date | Last activation date. |
| SentinelOne.ServiceUsers.Name | string | Service user name. |
| SentinelOne.ServiceUsers.Scope | string | Service user scope. |
| SentinelOne.ServiceUsers.UpdatedAt | date | Service user updated at. |
| SentinelOne.ServiceUsers.UpdatedById | string | Service user updated by Id. |
| SentinelOne.ServiceUsers.UpdatedByName | string | Service user updated by name. |
| SentinelOne.ServiceUsers.ScopeRolesRoleId | string | Scope roles role Id. |
| SentinelOne.ServiceUsers.ScopeRolesRoleName | string | Scope roles role name. |
| SentinelOne.ServiceUsers.ScopeRolesAccountName | string | Scope roles account name. |
| SentinelOne.ServiceUsers.ScopeRolesId | string | Scope roles Id. |


### Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and SentinelOne v2 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in SentinelOne v2 events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in SentinelOne v2 events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and SentinelOne v2 events will be reflected in both directions. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.

**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and SentinelOne v2.