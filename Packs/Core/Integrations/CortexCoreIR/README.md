Cortex XDR is the world's first detection and response app that natively integrates network, endpoint, and cloud data to stop sophisticated attacks.
This integration was integrated and tested with version xx of Cortex Core - IR

## Configure Investigation & Response on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Investigation & Response.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | Server URL (copy URL from Core - click ? to see more info.) |  | False |
    | API Key ID |  | False |
    | API Key |  | False |
    | HTTP Timeout | The timeout of the HTTP requests sent to Cortex XDR API \(in seconds\). | False |
    | Sync Incident Owners | For Cortex XSOAR version 6.0.0 and above. If selected, for every incident fetched from Cortex XDR to Cortex XSOAR, the incident owners will be synced. Note that once this value is changed and synchronized between the systems, additional changes will not be reflected. For example, if you change the owner in Cortex XSOAR, the new owner will also be changed in Cortex XDR. However, if you now change the owner back in Cortex XDR, this additional change will not be reflected in Cortex XSOAR. In addition, for this change to be reflected, the owners must exist in both Cortex XSOAR and Cortex XDR. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### core-isolate-endpoint
***
Isolates the specified endpoint.


#### Base Command

`core-isolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | For polling use. | Optional | 
| endpoint_id | The endpoint ID (string) to isolate. You can retrieve the string from the core-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to isolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Isolation.endpoint_id | String | The endpoint ID. | 

### core-unisolate-endpoint
***
Reverses the isolation of an endpoint.


#### Base Command

`core-unisolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id | The endpoint ID (string) for which to reverse the isolation. You can retrieve it from the core-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to unisolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.UnIsolation.endpoint_id | String | Isolates the specified endpoint. | 

### core-get-endpoints
***
Gets a list of endpoints, according to the passed filters. If there are no filters, all endpoints are returned. Filtering by multiple fields will be concatenated using AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of endpoint from the start of the result set (start by counting from 0).


#### Base Command

`core-get-endpoints`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id_list | A comma-separated list of endpoint IDs. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names. <br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of IP addresses.<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | The group name to which the agent belongs.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform. Valid values are\: "windows", "linux", "macos", or "android". . Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated. Possible values are: isolated, unisolated. | Optional | 
| hostname | Hostname<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of endpoints to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies whether to sort endpoints by the first time or last time they were seen. Can be "first_seen" or "last_seen". Possible values are: first_seen, last_seen. | Optional | 
| sort_order | The order by which to sort results. Can be "asc" (ascending) or "desc" ( descending). Default set to asc. Possible values are: asc, desc. Default is asc. | Optional | 
| status | The status of the endpoint to filter. Possible values are: connected, disconnected, lost, uninstalled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Endpoint.endpoint_id | String | The endpoint ID. | 
| Core.Endpoint.endpoint_name | String | The endpoint name. | 
| Core.Endpoint.endpoint_type | String | The endpoint type. | 
| Core.Endpoint.endpoint_status | String | The status of the endpoint. | 
| Core.Endpoint.os_type | String | The endpoint OS type. | 
| Core.Endpoint.ip | Unknown | A list of IP addresses. | 
| Core.Endpoint.users | Unknown | A list of users. | 
| Core.Endpoint.domain | String | The endpoint domain. | 
| Core.Endpoint.alias | String | The endpoint's aliases. | 
| Core.Endpoint.first_seen | Unknown | First seen date/time in Epoch \(milliseconds\). | 
| Core.Endpoint.last_seen | Date | Last seen date/time in Epoch \(milliseconds\). | 
| Core.Endpoint.content_version | String | Content version. | 
| Core.Endpoint.installation_package | String | Installation package. | 
| Core.Endpoint.active_directory | String | Active directory. | 
| Core.Endpoint.install_date | Date | Install date in Epoch \(milliseconds\). | 
| Core.Endpoint.endpoint_version | String | Endpoint version. | 
| Core.Endpoint.is_isolated | String | Whether the endpoint is isolated. | 
| Core.Endpoint.group_name | String | The name of the group to which the endpoint belongs. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.IPAddress | String | The IP address of the endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Account.Username | String | The username in the relevant system. | 
| Account.Domain | String | The domain of the account. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

#### Command example
```!core-get-endpoints isolate="unisolated" first_seen_gte="3 month" page="0" limit="30" sort_order="asc"```
#### Context Example
```json
{
    "Account": [
        {
            "Domain": "xdrdummyurl.com",
            "Username": "xdrdummyurl.com"
        }
    ],
    "Core": {
        "Endpoint": [
            {
                "active_directory": null,
                "alias": "",
                "content_release_timestamp": 1643023344000,
                "content_version": "360-81029",
                "domain": "xdrdummyurl.com",
                "endpoint_id": "87ae5fc622604ea4809dd28f01c436d0",
                "endpoint_name": "dummy_new_name2",
                "endpoint_status": "DISCONNECTED",
                "endpoint_type": "AGENT_TYPE_SERVER",
                "endpoint_version": "1.1.1.1",
                "first_seen": 1642943216960,
                "group_name": [],
                "install_date": 1642943217006,
                "installation_package": "",
                "ip": [
                    "1.1.1.1"
                ],
                "is_isolated": "AGENT_UNISOLATED",
                "isolated_date": null,
                "last_content_update_time": 1643026320796,
                "last_seen": 1643026320166,
                "operational_status": "PROTECTED",
                "operational_status_description": null,
                "os_type": "AGENT_OS_WINDOWS",
                "os_version": "1.1.1",
                "scan_status": "SCAN_STATUS_NONE",
                "users": [
                    "woo@demisto.com"
                ]
            }
    ]
}
```

#### Human Readable Output

>### Endpoints
>|active_directory|alias|content_release_timestamp|content_version|domain|endpoint_id|endpoint_name|endpoint_status|endpoint_type|endpoint_version|first_seen|group_name|install_date|installation_package|ip|is_isolated|isolated_date|last_content_update_time|last_seen|operational_status|operational_status_description|os_type|os_version|scan_status|users|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 1643023344000 | 360-81029 | api.xdrurl.com | 87ae5fc622604ea4809dd28f01c436d0 | dummy_new_name2 | DISCONNECTED | AGENT_TYPE_SERVER | 1.1.1.1 | 1642943216960 |  | 1642943217006 | HOLODECK_1 | 1.1.1.1 | AGENT_UNISOLATED |  | 1643026320796 | 1643026320166 | PROTECTED |  | AGENT_OS_WINDOWS | 1.1.1. | SCAN_STATUS_NONE | woo@demisto.com |

### core-get-distribution-versions
***
Gets a list of all the agent versions to use for creating a distribution list.


#### Base Command

`core-get-distribution-versions`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.DistributionVersions.windows | Unknown | A list of Windows agent versions. | 
| Core.DistributionVersions.linux | Unknown | A list of Linux agent versions. | 
| Core.DistributionVersions.macos | Unknown | A list of Mac agent versions. | 

#### Command example
```!core-get-distribution-versions```
#### Context Example
```json
{
    "Core": {
        "DistributionVersions": {
            "container": [
                "1.1.1.1"
            ],
            "linux": [
                "1.1.1.1"
            ],
            "macos": [
                "1.1.1.1"
            ],
            "windows": [
                "1.1.1.1"
            ]
        }
    }
}
```

#### Human Readable Output

>### windows
>|versions|
>|---|
>| 1.1.1.1 |
>
>
>### linux
>|versions|
>|---|
>| 1.1.1.1 |
>
>
>### macos
>|versions|
>|---|
>| 1.1.1.1 |
>
>
>### container
>|versions|
>|---|
>| 1.1.1.1 |


### core-create-distribution
***
Creates an installation package. This is an asynchronous call that returns the distribution ID. This does not mean that the creation succeeded. To confirm that the package has been created, check the status of the distribution by running the Get Distribution Status API.


#### Base Command

`core-create-distribution`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A string representing the name of the installation package. | Required | 
| platform | String, valid values are:<br/>• windows <br/>• linux<br/>• macos <br/>• android. Possible values are: windows, linux, macos, android. | Required | 
| package_type | A string representing the type of package to create.<br/>standalone - An installation for a new agent<br/>upgrade - An upgrade of an agent from ESM. Possible values are: standalone, upgrade. | Required | 
| agent_version | agent_version returned from core-get-distribution-versions. Not required for Android platfom. | Required | 
| description | Information about the package. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Distribution.id | String | The installation package ID. | 
| Core.Distribution.name | String | The name of the installation package. | 
| Core.Distribution.platform | String | The installation OS. | 
| Core.Distribution.agent_version | String | Agent version. | 
| Core.Distribution.description | String | Information about the package. | 

#### Command example
```!core-create-distribution agent_version=6.1.4.1680 name="dist_1" package_type=standalone platform=linux description="some description"```
#### Context Example
```json
{
    "Core": {
        "Distribution": {
            "agent_version": "6.1.4.1680",
            "description": "some description",
            "id": "52c0e7988a024cbab32d4cd888e44dfb",
            "name": "dist_1",
            "package_type": "standalone",
            "platform": "linux"
        }
    }
}
```

#### Human Readable Output

>Distribution 52c0e7988a024cbab32d4cd888e44dfb created successfully

### core-get-distribution-url
***
Gets the distribution URL for downloading the installation package.


#### Base Command

`core-get-distribution-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_id | The ID of the installation package.<br/>Copy the distribution_id from the "id" field on Endpoints &gt; Agent Installation page. | Required | 
| package_type | The installation package type. Valid<br/>values are:<br/>• upgrade<br/>• sh - For Linux<br/>• rpm - For Linux<br/>• deb - For Linux<br/>• pkg - For Mac<br/>• x86 - For Windows<br/>• x64 - For Windows. Possible values are: upgrade, sh, rpm, deb, pkg, x86, x64. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Distribution.id | String | Distribution ID. | 
| Core.Distribution.url | String | URL for downloading the installation package. | 

### core-get-create-distribution-status
***
Gets the status of the installation package.


#### Base Command

`core-get-create-distribution-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_ids | A comma-separated list of distribution IDs to get the status of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Distribution.id | String | Distribution ID. | 
| Core.Distribution.status | String | The status of installation package. | 

### core-get-audit-management-logs
***
Gets management logs. You can filter by multiple fields, which will be concatenated using the AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of management logs from the start of the result set (start by counting from 0).


#### Base Command

`core-get-audit-management-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | User’s email address. | Optional | 
| type | The audit log type. Possible values are: REMOTE_TERMINAL, RULES, AUTH, RESPONSE, INCIDENT_MANAGEMENT, ENDPOINT_MANAGEMENT, ALERT_WHITELIST, PUBLIC_API, DISTRIBUTIONS, STARRED_INCIDENTS, POLICY_PROFILES, DEVICE_CONTROL_PROFILE, HOST_FIREWALL_PROFILE, POLICY_RULES, PROTECTION_POLICY, DEVICE_CONTROL_TEMP_EXCEPTIONS, DEVICE_CONTROL_GLOBAL_EXCEPTIONS, GLOBAL_EXCEPTIONS, MSSP, REPORTING, DASHBOARD, BROKER_VM. | Optional | 
| sub_type | The audit log subtype. | Optional | 
| result | Result type. Possible values are: SUCCESS, FAIL, PARTIAL. | Optional | 
| timestamp_gte | Return logs for which the timestamp is after 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of audit logs to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies the field by which to sort the results. By default the sort is defined as creation-time and DESC. Can be "type", "sub_type", "result", or "timestamp". Possible values are: type, sub_type, result, timestamp. | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default set to "desc". Possible values are: asc, desc. Default is desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AuditManagementLogs.AUDIT_ID | Number | Audit log ID. | 
| Core.AuditManagementLogs.AUDIT_OWNER_NAME | String | Audit owner name. | 
| Core.AuditManagementLogs.AUDIT_OWNER_EMAIL | String | Audit owner email address. | 
| Core.AuditManagementLogs.AUDIT_ASSET_JSON | String | Asset JSON. | 
| Core.AuditManagementLogs.AUDIT_ASSET_NAMES | String | Audit asset names. | 
| Core.AuditManagementLogs.AUDIT_HOSTNAME | String | Host name. | 
| Core.AuditManagementLogs.AUDIT_RESULT | String | Audit result. | 
| Core.AuditManagementLogs.AUDIT_REASON | String | Audit reason. | 
| Core.AuditManagementLogs.AUDIT_DESCRIPTION | String | Description of the audit. | 
| Core.AuditManagementLogs.AUDIT_ENTITY | String | Audit entity \(e.g., AUTH, DISTRIBUTIONS\). | 
| Core.AuditManagementLogs.AUDIT_ENTITY_SUBTYPE | String | Entity subtype \(e.g., Login, Create\). | 
| Core.AuditManagementLogs.AUDIT_CASE_ID | Number | Audit case ID. | 
| Core.AuditManagementLogs.AUDIT_INSERT_TIME | Date | Log's insert time. | 

#### Command example
```!core-get-audit-management-logs result=SUCCESS type=DISTRIBUTIONS limit=2 timestamp_gte="3 month"```
#### Context Example
```json
{
    "Core": {
        "AuditManagementLogs": [
            {
                "AUDIT_ASSET_JSON": null,
                "AUDIT_ASSET_NAMES": "",
                "AUDIT_CASE_ID": null,
                "AUDIT_DESCRIPTION": "Created a Windows Standalone installer installation package 'HOLODECK_3' with agent version 7.5.1.38280",
                "AUDIT_ENTITY": "DISTRIBUTIONS",
                "AUDIT_ENTITY_SUBTYPE": "Create",
                "AUDIT_HOSTNAME": null,
                "AUDIT_ID": 1002,
                "AUDIT_INSERT_TIME": 1636017216034,
                "AUDIT_OWNER_EMAIL": "moo@demisto.com",
                "AUDIT_OWNER_NAME": "",
                "AUDIT_REASON": null,
                "AUDIT_RESULT": "SUCCESS",
                "AUDIT_SESSION_ID": null,
                "AUDIT_SEVERITY": "SEV_010_INFO"
            }
        ]
    }
}
```

#### Human Readable Output

>### Audit Management Logs
>|AUDIT_ID|AUDIT_RESULT|AUDIT_DESCRIPTION|AUDIT_OWNER_NAME|AUDIT_OWNER_EMAIL|AUDIT_ASSET_JSON|AUDIT_ASSET_NAMES|AUDIT_HOSTNAME|AUDIT_REASON|AUDIT_ENTITY|AUDIT_ENTITY_SUBTYPE|AUDIT_SESSION_ID|AUDIT_CASE_ID|AUDIT_INSERT_TIME|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1002 | SUCCESS | Created a Windows Standalone installer installation package 'HOLODECK_3' with agent version 1.1.1.1 | Moo | moo@demisto.com |  |  |  |  | DISTRIBUTIONS | Create |  |  | 1636017216034 |
>| 1001 | SUCCESS | Edited installation package 'HOLODECK_1' | Moo | moo@demisto.com |  |  |  |  | DISTRIBUTIONS | Edit |  |  | 1636017119505 |


### core-get-audit-agent-reports
***
Gets agent event reports. You can filter by multiple fields, which will be concatenated using the AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of reports from the start of the result set (start by counting from 0).


#### Base Command

`core-get-audit-agent-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. | Optional | 
| endpoint_names | A comma-separated list of endpoint names. | Optional | 
| type | The report type. Can be "Installation", "Policy", "Action", "Agent Service", "Agent Modules", or "Agent Status". Possible values are: Installation, Policy, Action, Agent Service, Agent Modules, Agent Status. | Optional | 
| sub_type | The report subtype. Possible values are: Install, Uninstall, Upgrade, Local Configuration, Content Update, Policy Update, Process Exception, Hash Exception, Scan, File Retrieval, File Scan, Terminate Process, Isolate, Cancel Isolation, Payload Execution, Quarantine, Restore, Stop, Start, Module Initialization, Local Analysis Model, Local Analysis Feature Extraction, Fully Protected, OS Incompatible, Software Incompatible, Kernel Driver Initialization, Kernel Extension Initialization, Proxy Communication, Quota Exceeded, Minimal Content, Reboot Eequired, Missing Disc Access. | Optional | 
| result | The result type. Can be "Success" or "Fail". If not passed, returns all event reports. Possible values are: Success, Fail. | Optional | 
| timestamp_gte | Return logs that their timestamp is greater than 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'timestamp_lte'.<br/><br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | The maximum number of reports to return. Default and maximum is 30. Default is 30. | Optional | 
| sort_by | The field by which to sort results. Can be "type", "category", "trapsversion", "timestamp", or "domain"). Possible values are: type, category, trapsversion, timestamp, domain. | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default is "asc". Possible values are: asc, desc. Default is asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AuditAgentReports.ENDPOINTID | String | Endpoint ID. | 
| Core.AuditAgentReports.ENDPOINTNAME | String | Endpoint name. | 
| Core.AuditAgentReports.DOMAIN | String | Agent domain. | 
| Core.AuditAgentReports.TRAPSVERSION | String | Traps version. | 
| Core.AuditAgentReports.RECEIVEDTIME | Date | Received time in Epoch time. | 
| Core.AuditAgentReports.TIMESTAMP | Date | Timestamp in Epoch time. | 
| Core.AuditAgentReports.CATEGORY | String | Report category \(e.g., Audit\). | 
| Core.AuditAgentReports.TYPE | String | Report type \(e.g., Action, Policy\). | 
| Core.AuditAgentReports.SUBTYPE | String | Report subtype \(e.g., Fully Protected,Policy Update,Cancel Isolation\). | 
| Core.AuditAgentReports.RESULT | String | Report result. | 
| Core.AuditAgentReports.REASON | String | Report reason. | 
| Core.AuditAgentReports.DESCRIPTION | String | Agent report description. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 

#### Command example
```!core-get-audit-agent-reports result=Success timestamp_gte="100 days" endpoint_ids=ea303670c76e4ad09600c8b346f7c804 type=Policy limit=2```
#### Context Example
```json
{
    "Core": {
        "AuditAgentReports": null
    }
}
```

#### Human Readable Output

>### Audit Agent Reports
>**No entries.**


### core-blocklist-files
***
Block lists requested files which have not already been block listed or added to allow list.


#### Base Command

`core-blocklist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to block list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| detailed_response | Whether to response detailed response. default value = false. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.blocklist.added_hashes | Number | Added fileHash to blocklist | 
| Core.blocklist.excluded_hashes | Number | Added fileHash to blocklist | 

#### Command example
```!core-blocklist-files hash_list=11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252```
#### Context Example
```json
{
    "Core": {
        "blocklist": {
            "added_hashes": {
                "fileHash": [
                    "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Blocklist Files
>|Added _ Hashes|
>|---|
>| 11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252 |


### core-allowlist-files
***
Adds requested files to allow list if they are not already on block list or allow list.


#### Base Command

`core-allowlist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| detailed_response | Whether to response detailed response. default value = false. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.allowlist.added_hashes | Number | Added fileHash to allowlist | 
| Core.allowlist.excluded_hashes | Number | Added fileHash to allowlist | 

#### Command example
```!core-allowlist-files hash_list=11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252```
#### Context Example
```json
{
    "Core": {
        "allowlist": {
            "added_hashes": {
                "fileHash": [
                    "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Allowlist Files
>|Added _ Hashes|
>|---|
>| 11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252 |


### core-quarantine-files
***
Quarantines a file on selected endpoints. You can select up to 1000 endpoints.


#### Base Command

`core-quarantine-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Required | 
| file_path | String that represents the path of the file you want to quarantine. | Required | 
| file_hash | String that represents the file’s hash. Must be a valid SHA256 hash. | Required | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

There is no context output for this command.
### core-get-quarantine-status
***
Retrieves the quarantine status for a selected file.


#### Base Command

`core-get-quarantine-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | String the represents the endpoint ID. | Required | 
| file_hash | String that represents the file hash. Must be a valid SHA256 hash. | Required | 
| file_path | String that represents the file path. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!core-get-quarantine-status endpoint_id=f8a2f58846b542579c12090652e79f3d file_hash=55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4 file_path=/home/ec2-user/test_file.txt```
#### Context Example
```json
{
    "Core": {
        "quarantineFiles": {
            "status": {
                "endpointId": "f8a2f58846b542579c12090652e79f3d",
                "fileHash": "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4",
                "filePath": "/home/ec2-user/test_file.txt",
                "status": false
            }
        }
    }
}
```

#### Human Readable Output

>### Quarantine files status
>|Status|Endpoint Id|File Path|File Hash|
>|---|---|---|---|
>| false | f8a2f58846b542579c12090652e79f3d | /home/ec2-user/test_file.txt | 55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4 |


### core-restore-file
***
Restores a quarantined file on requested endpoints.


#### Base Command

`core-restore-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| file_hash | String that represents the file in hash. Must be a valid SHA256 hash. | Required | 
| endpoint_id | String that represents the endpoint ID. If you do not enter a specific endpoint ID, the request will run restore on all endpoints which relate to the quarantined file you defined. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

There is no context output for this command.
### core-endpoint-scan
***
Runs a scan on a selected endpoint. To scan all endpoints, run this command with argument all=true. Do note that scanning all the endpoints may cause performance issues and latency.


#### Base Command

`core-endpoint-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Optional | 
| dist_name | Name of the distribution list. | Optional | 
| gte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| gte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| ip_list | List of IP addresses. | Optional | 
| group_name | Name of the endpoint group. | Optional | 
| platform | Type of operating system. Possible values are: windows, linux, macos, android. | Optional | 
| alias | Endpoint alias name. | Optional | 
| isolate | Whether an endpoint has been isolated. Can be "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints or not. Default is false. Scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.endpointScan.actionId | Number | The action ID of the scan request. | 
| Core.endpointScan.aborted | Boolean | Was the scan aborted. | 

### core-endpoint-scan-abort
***
Cancel the scan of selected endpoints. A scan can only be aborted if the selected endpoints are Pending or In Progress. To scan all endpoints, run the command with the argument all=true. Note that scanning all of the endpoints may cause performance issues and latency.


#### Base Command

`core-endpoint-scan-abort`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Optional | 
| dist_name | Name of the distribution list. | Optional | 
| gte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| gte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| ip_list | List of IP addresses. | Optional | 
| group_name | Name of the endpoint group. | Optional | 
| platform | Type of operating system. Possible values are: windows, linux, macos, android. | Optional | 
| alias | Endpoint alias name. | Optional | 
| isolate | Whether an endpoint has been isolated. Can be "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints or not. Default is false. Note that scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.endpointScan.actionId | Unknown | The action id of the abort scan request. | 
| Core.endpointScan.aborted | Boolean | Was the scan aborted. | 

### core-get-policy
***
Gets the policy name for a specific endpoint.


#### Base Command

`core-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID. Can be retrieved by running the core-get-endpoints command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Policy | string | The policy allocated with the endpoint. | 
| Core.Policy.policy_name | string | Name of the policy allocated with the endpoint. | 
| Core.Policy.endpoint_id | string | Endpoint ID. | 

### core-get-scripts
***
Gets a list of scripts available in the scripts library.


#### Base Command

`core-get-scripts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_name | A comma-separated list of the script names. | Optional | 
| description | A comma-separated list of the script descriptions. | Optional | 
| created_by | A comma-separated list of the users who created the script. | Optional | 
| limit | The maximum number of scripts returned to the War Room. Default is 50. | Optional | 
| offset | (Int) Offset in the data set. Default is 0. | Optional | 
| windows_supported | Whether the script can be executed on a Windows operating system. Possible values are: true, false. | Optional | 
| linux_supported | Whether the script can be executed on a Linux operating system. Possible values are: true, false. | Optional | 
| macos_supported | Whether the script can be executed on a Mac operating system. Possible values are: true, false. | Optional | 
| is_high_risk | Whether the script has a high-risk outcome. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Scripts | Unknown | The scripts command results. | 
| Core.Scripts.script_id | Unknown | Script ID. | 
| Core.Scripts.name | string | Name of the script. | 
| Core.Scripts.description | string | Description of the script. | 
| Core.Scripts.modification_date | Unknown | Timestamp of when the script was last modified. | 
| Core.Scripts.created_by | string | Name of the user who created the script. | 
| Core.Scripts.windows_supported | boolean | Whether the script can be executed on a Windows operating system. | 
| Core.Scripts.linux_supported | boolean | Whether the script can be executed on a Linux operating system. | 
| Core.Scripts.macos_supported | boolean | Whether the script can be executed on Mac operating system. | 
| Core.Scripts.is_high_risk | boolean | Whether the script has a high-risk outcome. | 
| Core.Scripts.script_uid | string | Globally Unique Identifier of the script, used to identify the script when executing. | 

#### Command example
```!core-get-scripts created_by="Palo Alto Networks" is_high_risk=true```
#### Context Example
```json
{
    "Core": {
        "Scripts": [
          {
            "created_by": "Palo Alto Networks",
            "description": "Delete a file by path",
            "is_high_risk": true,
            "linux_supported": true,
            "macos_supported": true,
            "modification_date": "2021-05-04T14:33:48",
            "modification_date_timestamp": 1620138828748,
            "name": "delete_file",
            "script_id": 1,
            "script_uid": "548023b6e4a01ec51a495ba6e5d2a15d",
            "windows_supported": true
          }
        ]
    }
}
```

#### Human Readable Output

>### Scripts
>|Name|Description|Script Uid|Modification Date|Created By|Windows Supported|Linux Supported|Macos Supported|Is High Risk|
>|---|---|---|---|---|---|---|---|---|
>| delete_file | Delete a file by path | 548023b6e4a01ec51a495ba6e5d2a15d | 2021-05-04T14:33:48 | Palo Alto Networks | true | true | true | true |
>| execute_commands | Execute list of shell commands | a6f7683c8e217d85bd3c398f0d3fb6bf | 2022-01-05T10:14:14 | Palo Alto Networks | true | true | true | true |
>| process_kill_cpu | Kill all processes with a CPU usage higher than specified | 3d928a24f61cd3c1116544900c424098 | 2022-01-05T10:14:14 | Palo Alto Networks | true | true | true | true |
>| process_kill_mem | Kill all processes with a RAM usage higher than specified | 87d4547df6d4882a3c006ec58c3b8bf4 | 2021-05-04T14:33:48 | Palo Alto Networks | true | true | true | true |
>| process_kill_name | Kill processes by name | fd0a544a99a9421222b4f57a11839481 | 2021-05-04T14:33:48 | Palo Alto Networks | true | true | true | true |
>| registry_delete | Delete registry value or delete registry key with all its values | ad36488a20cdbdd1604ec4bec9da5c41 | 2021-05-04T14:33:48 | Palo Alto Networks | true | false | false | true |
>| registry_set | Set registry value | 896392a13b2ef0ae75b3f2396125037d | 2021-05-04T14:33:48 | Palo Alto Networks | true | false | false | true |


### core-delete-endpoints
***
Deletes selected endpoints in the Cortex XDR app. You can delete up to 1000 endpoints.


#### Base Command

`core-delete-endpoints`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | Comma-separated list of endpoint IDs. You can retrieve the endpoint IDs from the core-get-endpoints command. | Required | 


#### Context Output

There is no context output for this command.
### core-get-endpoint-device-control-violations
***
Gets a list of device control violations filtered by selected fields. You can retrieve up to 100 violations.


#### Base Command

`core-get-endpoint-device-control-violations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | Comma-separated list of endpoint IDs. You can retrieve the endpoint IDs from the core-get-endpoints command. | Optional | 
| type | Type of violation. Possible values are: "cd-rom", "disk drive", "floppy disk", and "portable device". Possible values are: cd-rom, disk drive, floppy disk, portable device. | Optional | 
| timestamp_gte | Timestamp of the violation. Violations that are greater than or equal to this timestamp will be returned. Values can be in either ISO date format, relative time, or epoch timestamp. For example:  "2019-10-21T23:45:00" (ISO date format), "3 days ago" (relative time) 1579039377301 (epoch time). | Optional | 
| timestamp_lte | Timestamp of the violation. Violations that are less than or equal to this timestamp will be returned. Values can be in either ISO date format, relative time, or epoch timestamp. For example:  "2019-10-21T23:45:00" (ISO date format), "3 days ago" (relative time) 1579039377301 (epoch time). | Optional | 
| ip_list | Comma-separated list of IP addresses. | Optional | 
| vendor | Name of the vendor. | Optional | 
| vendor_id | Vendor ID. | Optional | 
| product | Name of the product. | Optional | 
| product_id | Product ID. | Optional | 
| serial | Serial number. | Optional | 
| hostname | Hostname. | Optional | 
| violation_id_list | Comma-separated list of violation IDs. | Optional | 
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.EndpointViolations | Unknown | Endpoint violations command results. | 
| Core.EndpointViolations.violations | Unknown | A list of violations. | 
| Core.EndpointViolations.violations.os_type | string | Type of the operating system. | 
| Core.EndpointViolations.violations.hostname | string | Hostname of the violation. | 
| Core.EndpointViolations.violations.username | string | Username of the violation. | 
| Core.EndpointViolations.violations.ip | string | IP address of the violation. | 
| Core.EndpointViolations.violations.timestamp | number | Timestamp of the violation. | 
| Core.EndpointViolations.violations.violation_id | number | Violation ID. | 
| Core.EndpointViolations.violations.type | string | Type of violation. | 
| Core.EndpointViolations.violations.vendor_id | string | Vendor ID of the violation. | 
| Core.EndpointViolations.violations.vendor | string | Name of the vendor of the violation. | 
| Core.EndpointViolations.violations.product_id | string | Product ID of the violation. | 
| Core.EndpointViolations.violations.product | string | Name of the product of the violation. | 
| Core.EndpointViolations.violations.serial | string | Serial number of the violation. | 
| Core.EndpointViolations.violations.endpoint_id | string | Endpoint ID of the violation. | 

#### Command example
```!core-get-endpoint-device-control-violations violation_id_list=100,90,80```
#### Context Example
```json
{
    "Core": {
        "EndpointViolations": null
    }
}
```

#### Human Readable Output

>### Endpoint Device Control Violation
>**No entries.**


### core-retrieve-files
***
Retrieves files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints. At least one endpoint ID and one file path are necessary in order to run the command. After running this command, you can use the core-action-status-get command with returned action_id, to check the action status.


#### Base Command

`core-retrieve-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. | Required | 
| windows_file_paths | A comma-separated list of file paths on the Windows platform. | Optional | 
| linux_file_paths | A comma-separated list of file paths on the Linux platform. | Optional | 
| mac_file_paths | A comma-separated list of file paths on the Mac platform. | Optional | 
| generic_file_path | A comma-separated list of file paths in any platform. Can be used instead of the mac/windows/linux file paths. The order of the files path list must be parellel to the endpoints list order, therefore, the first file path in the list is related to the first endpoint and so on. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.RetrievedFiles.action_id | string | ID of the action to retrieve files from selected endpoints. | 

### core-retrieve-file-details
***
View the file retrieved by the core-retrieve-files command according to the action ID. Before running this command, you can use the core-action-status-get command to check if this action completed successfully.


#### Base Command

`core-retrieve-file-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action ID retrieved from the core-retrieve-files command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 

#### Command example
```!core-retrieve-file-details action_id=1763```
#### Human Readable Output

>### Action id : 1763 
> Retrieved 0 files from 0 endpoints. 
> To get the exact action status run the core-action-status-get command

### core-get-script-metadata
***
Gets the full definition of a specific script in the scripts library.


#### Base Command

`core-get-script-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_uid | Unique identifier of the script, returned by the core-get-scripts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptMetadata | Unknown | The script metadata command results. | 
| Core.ScriptMetadata.script_id | number | Script ID. | 
| Core.ScriptMetadata.name | string | Script name. | 
| Core.ScriptMetadata.description | string | Script description. | 
| Core.ScriptMetadata.modification_date | unknown | Timestamp of when the script was last modified. | 
| Core.ScriptMetadata.created_by | string | Name of the user who created the script. | 
| Core.ScriptMetadata.is_high_risk | boolean | Whether the script has a high-risk outcome. | 
| Core.ScriptMetadata.windows_supported | boolean | Whether the script can be executed on a Windows operating system. | 
| Core.ScriptMetadata.linux_supported | boolean | Whether the script can be executed on a Linux operating system. | 
| Core.ScriptMetadata.macos_supported | boolean | Whether the script can be executed on a Mac operating system. | 
| Core.ScriptMetadata.entry_point | string | Name of the entry point selected for the script. An empty string indicates  the script defined as just run. | 
| Core.ScriptMetadata.script_input | string | Name and type for the specified entry point. | 
| Core.ScriptMetadata.script_output_type | string | Type of the output. | 
| Core.ScriptMetadata.script_output_dictionary_definitions | Unknown | If the script_output_type is a dictionary, an array with friendly name, name, and type for each output. | 

#### Command example
```!core-get-script-metadata script_uid=43973479d389f2ac7e99b6db88eaee40```
#### Context Example
```json
{
    "Core": {
        "ScriptMetadata": {
            "created_by": "Palo Alto Networks",
            "description": "List all directories under path",
            "entry_point": "run",
            "is_high_risk": false,
            "linux_supported": true,
            "macos_supported": true,
            "modification_date": 1620138828771,
            "name": "list_directories",
            "script_id": 4,
            "script_input": [
                {
                    "name": "path",
                    "type": "string"
                },
                {
                    "name": "number_of_levels",
                    "type": "number"
                }
            ],
            "script_output_dictionary_definitions": null,
            "script_output_type": "string_list",
            "script_uid": "43973479d389f2ac7e99b6db88eaee40",
            "windows_supported": true
        }
    }
}
```

#### Human Readable Output

>### Script Metadata
>|Created By|Description|Entry Point|Is High Risk|Linux Supported|Macos Supported|Modification Date|Modification Date Timestamp|Name|Script Id|Script Input|Script Output Type|Script Uid|Windows Supported|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Palo Alto Networks | List all directories under path | run | false | true | true | 2021-05-04T14:33:48 | 1620138828771 | list_directories | 4 | {'name': 'path', 'type': 'string'},<br/>{'name': 'number_of_levels', 'type': 'number'} | string_list | 43973479d389f2ac7e99b6db88eaee40 | true |


### core-get-script-code
***
Gets the code of a specific script in the script library.


#### Base Command

`core-get-script-code`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_uid | Unique identifier of the script, returned by the core-get-scripts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptCode | Unknown | The script code command results. | 
| Core.ScriptCode.code | string | The code of a specific script in the script library. | 
| Core.ScriptCode.script_uid | string | Unique identifier of the script. | 

#### Command example
```!core-get-script-code script_uid=548023b6e4a01ec51a495ba6e5d2a15d```
#### Context Example
```json
{
    "Core": {
        "ScriptCode": {
            "code": "import os\nimport sys\nimport traceback\n\n\ndef run(file_path):\n    path = os.path.expanduser(file_path)\n    path = os.path.expandvars(path)\n    if os.path.isabs(path):\n        try:\n            os.remove(path)\n        except IOError:\n            sys.stderr.write(f\"File not accessible: {path}\")\n            return False\n        except Exception as e:\n            sys.stderr.write(f\"Exception occured: {traceback.format_exc()}\")\n            return False\n    return True\n",
            "script_uid": "548023b6e4a01ec51a495ba6e5d2a15d"
        }
    }
}
```

#### Human Readable Output

>### Script code: 
> ``` import os
>import sys
>import traceback
>
>
>def run(file_path):
>    path = os.path.expanduser(file_path)
>    path = os.path.expandvars(path)
>    if os.path.isabs(path):
>        try:
>            os.remove(path)
>        except IOError:
>            sys.stderr.write(f"File not accessible: {path}")
>            return False
>        except Exception as e:
>            sys.stderr.write(f"Exception occured: {traceback.format_exc()}")
>            return False
>    return True
> ```

### core-action-status-get
***
Retrieves the status of the requested actions according to the action ID.


#### Base Command

`core-action-status-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | The action ID of the selected request. After performing an action, you will receive an action ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.GetActionStatus | Unknown | The action status command results. | 
| Core.GetActionStatus.endpoint_id | string | Endpoint ID. | 
| Core.GetActionStatus.status | string | The status of the specific endpoint ID. | 
| Core.GetActionStatus.action_id | number | The specified action ID. | 

#### Command example
```!core-action-status-get action_id="1819"```
#### Context Example
```json
{
    "Core": {
        "GetActionStatus": null
    }
}
```

#### Human Readable Output

>### Get Action Status
>**No entries.**


### core-run-script
***
Initiates a new endpoint script execution action using a script from the script library.


#### Base Command

`core-run-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| script_uid | Unique identifier of the script. Can be retrieved by running the core-get-scripts command. | Required | 
| parameters | Dictionary contains the parameter name as key and its value for this execution as the value. For example, {"param1":"param1_value","param2":"param2_value"}. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-snippet-code-script
***
Initiates a new endpoint script execution action using the provided snippet code.


#### Base Command

`core-run-snippet-code-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| snippet_code | Section of a script you want to initiate on an endpoint (e.g., print("7")). | Required | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-get-script-execution-status
***
Retrieves the status of a script execution action.


#### Base Command

`core-get-script-execution-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action IDs retrieved from the core-run-script command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptStatus.general_status | String | General status of the action, considering the status of all the endpoints. | 
| Core.ScriptStatus.error_message | String | Error message regarding permissions for running APIs or the action doesn’t exist. | 
| Core.ScriptStatus.endpoints_timeout | Number | Number of endpoints in "timeout" status. | 
| Core.ScriptStatus.action_id | Number | ID of the action initiated. | 
| Core.ScriptStatus.endpoints_pending_abort | Number | Number of endpoints in "pending abort" status. | 
| Core.ScriptStatus.endpoints_pending | Number | Number of endpoints in "pending" status. | 
| Core.ScriptStatus.endpoints_in_progress | Number | Number of endpoints in "in progress" status. | 
| Core.ScriptStatus.endpoints_failed | Number | Number of endpoints in "failed" status. | 
| Core.ScriptStatus.endpoints_expired | Number | Number of endpoints in "expired" status. | 
| Core.ScriptStatus.endpoints_completed_successfully | Number | Number of endpoints in "completed successfully" status. | 
| Core.ScriptStatus.endpoints_canceled | Number | Number of endpoints in "canceled" status. | 
| Core.ScriptStatus.endpoints_aborted | Number | Number of endpoints in "aborted" status. | 

### core-get-script-execution-results
***
Retrieve the results of a script execution action.


#### Base Command

`core-get-script-execution-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action IDs retrieved from the core-run-script command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptResult.action_id | Number | ID of the action initiated. | 
| Core.ScriptResult.results.retrieved_files | Number | Number of successfully retrieved files. | 
| Core.ScriptResult.results.endpoint_ip_address | String | Endpoint IP address. | 
| Core.ScriptResult.results.endpoint_name | String | Number of successfully retrieved files. | 
| Core.ScriptResult.results.failed_files | Number | Number of files failed to retrieve. | 
| Core.ScriptResult.results.endpoint_status | String | Endpoint status. | 
| Core.ScriptResult.results.domain | String | Domain to which the endpoint belongs. | 
| Core.ScriptResult.results.endpoint_id | String | Endpoint ID. | 
| Core.ScriptResult.results.execution_status | String | Execution status of this endpoint. | 
| Core.ScriptResult.results.return_value | String | Value returned by the script in case the type is not a dictionary. | 
| Core.ScriptResult.results.standard_output | String | The STDOUT and the STDERR logged by the script during the execution. | 
| Core.ScriptResult.results.retention_date | Date | Timestamp in which the retrieved files will be deleted from the server. | 

### core-get-script-execution-result-files
***
Gets the files retrieved from a specific endpoint during a script execution.


#### Base Command

`core-get-script-execution-result-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action ID retrieved from the core-run-script command. | Required | 
| endpoint_id | Endpoint ID. Can be retrieved by running the core-get-endpoints command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | EntryID of the file | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### core-run-script-execute-commands
***
Initiate a new endpoint script execution of shell commands.


#### Base Command

`core-run-script-execute-commands`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| commands | Comma-separated list of shell commands to execute. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-script-delete-file
***
Initiates a new endpoint script execution to delete the specified file.


#### Base Command

`core-run-script-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| file_path | Paths of the files to delete, in a comma-separated list. Paths of the files to check for existence. All of the given file paths will run on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-script-file-exists
***
Initiates a new endpoint script execution to check if file exists.


#### Base Command

`core-run-script-file-exists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| file_path | Paths of the files to check for existence, in a comma-separated list. All of the given file paths will run on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-script-kill-process
***
Initiates a new endpoint script execution kill process.


#### Base Command

`core-run-script-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| process_name | Names of processes to kill. Will kill all of the given processes on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### endpoint
***
Returns information about an endpoint.


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint IP address. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

### core-report-incorrect-wildfire
***
report FP to wildfire through XDR


#### Base Command

`core-report-incorrect-wildfire`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | String that represents the file’s hash. Must be a valid SHA256 hash. | Required | 
| new_verdict | The new verdict of the file. 0 - benign, 1 - malware. Possible values are: 0, 1. | Required | 
| reason | String that represents the reason of the report. | Required | 
| email | User’s email address. | Required | 


#### Context Output

There is no context output for this command.
### core-remove-allowlist-files
***
Removes requested files from allow list.


#### Base Command

`core-remove-allowlist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.allowlist.removed_hashes | Number | Removed file hash | 

#### Command example
```!core-remove-allowlist-files hash_list=11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252```
#### Context Example
```json
{
    "Core": {
        "allowlist": [
            {
                "removed_hashes": "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
            }
        ]
    }
}
```

#### Human Readable Output

>### Allowlist Files Removed
>|Removed _ Hashes|
>|---|
>| 11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252 |


### core-remove-blocklist-files
***
Removes requested files from block list.


#### Base Command

`core-remove-blocklist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.blocklist.removed_hashes | Number | Removed fileHash from blocklist | 

#### Command example
```!core-remove-blocklist-files hash_list=11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252```
#### Context Example
```json
{
    "Core": {
        "blocklist": [
            {
                "removed_hashes": "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
            }
        ]
    }
}
```

#### Human Readable Output

>### Blocklist Files Removed
>|Removed _ Hashes|
>|---|
>| 11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252 |


### core-add-exclusion
***
Adds exclusion.


#### Base Command

`core-add-exclusion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the exclusion. | Required | 
| filterObject | Filter object for the exclusion. example: {"filter":{"AND":[{"SEARCH_FIELD":"alert_category","SEARCH_TYPE":"NEQ","SEARCH_VALUE":"Phishing"}]}}. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| status | Status of exclusion. default value = ENABLED. Possible values are: ENABLED, DISABLED. Default is ENABLED. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.exclusion.rule_id | Number | Added exclusion rule id | 

#### Command example
```!core-add-exclusion filterObject={\"filter\":{\"AND\":[{\"SEARCH_FIELD\":\"alert_category\",\"SEARCH_TYPE\":\"NEQ\",\"SEARCH_VALUE\":\"Phishing\"}]}} name=test1```
#### Context Example
```json
{
    "Core": {
        "exclusion": {
            "rule_id": 44
        }
    }
}
```

#### Human Readable Output

>### Add Exclusion
>|rule_id|
>|---|
>| 44 |


### core-delete-exclusion
***
Delete exclusion.


#### Base Command

`core-delete-exclusion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_exclusion_id | The desired alert_exclusion_id to be removed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.deletedExclusion.rule_id | Number | Deleted exclusion rule id | 

#### Command example
```!core-delete-exclusion alert_exclusion_id=36```
#### Context Example
```json
{
    "Core": {
        "deletedExclusion": {
            "rule_id": null
        }
    }
}
```

#### Human Readable Output

>Successfully deleted the following exclusion: 36

### core-get-exclusion
***
Gets exclusion list.


#### Base Command

`core-get-exclusion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_ID | Allows to link the response action to the tenant that triggered it. | Optional | 
| filterObject | Filter object for the exclusion. example: {"filter":{"AND":[{"SEARCH_FIELD":"alert_category","SEARCH_TYPE":"NEQ","SEARCH_VALUE":"Phishing"}]}}. | Optional | 
| limit | Limit for the response. You will get the first "limit" exclusions. Default value is 20. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.exclusion.ALERT_WHITELIST_ID | Number |  | 
| Core.exclusion.ALERT_WHITELIST_MODIFY_TIME | Date |  | 
| Core.exclusion.ALERT_WHITELIST_NAME | String |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR_TEXT.pretty_name | String |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR_TEXT.data_type | Unknown |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR_TEXT.render_type | String |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR_TEXT.entity_map | Unknown |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR_TEXT.dml_type | Unknown |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR.filter.AND.SEARCH_FIELD | String |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR.filter.AND.SEARCH_TYPE | String |  | 
| Core.exclusion.ALERT_WHITELIST_INDICATOR.filter.AND.SEARCH_VALUE | String |  | 
| Core.exclusion.ALERT_WHITELIST_HITS | Number |  | 
| Core.exclusion.ALERT_WHITELIST_COMMENT | String |  | 
| Core.exclusion.ALERT_WHITELIST_USER | String |  | 
| Core.exclusion.ALERT_WHITELIST_PRETTY_USER | String |  | 
| Core.exclusion.ALERT_WHITELIST_STATUS | String |  | 
| Core.exclusion.ALERT_WHITELIST_BACKWARDS_SCAN_STATUS | String |  | 
| Core.exclusion.ALERT_WHITELIST_BACKWARDS_SCAN_TIMESTAMP | Unknown |  | 
| Core.exclusion.ALERT_WHITELIST_MIGRATED_FROM_ANALYTICS | Number |  | 

#### Command example
```!core-get-exclusion filterObject={\"filter\":{\"AND\":[{\"SEARCH_FIELD\":\"ALERT_WHITELIST_COMMENT\",\"SEARCH_TYPE\":\"NEQ\",\"SEARCH_VALUE\":\"Phishing\"}]}}```
#### Context Example
```json
{
    "Core": {
        "exclusion": [
            {
                "ALERT_WHITELIST_BACKWARDS_SCAN_STATUS": "DISABLED",
                "ALERT_WHITELIST_BACKWARDS_SCAN_TIMESTAMP": null,
                "ALERT_WHITELIST_COMMENT": "",
                "ALERT_WHITELIST_HITS": 0,
                "ALERT_WHITELIST_ID": 43,
                "ALERT_WHITELIST_INDICATOR": {
                    "filter": {
                        "AND": [
                            {
                                "SEARCH_FIELD": "alert_category",
                                "SEARCH_TYPE": "NEQ",
                                "SEARCH_VALUE": "Phishing"
                            }
                        ]
                    }
                },
                "ALERT_WHITELIST_INDICATOR_TEXT": [
                    {
                        "data_type": "TEXT",
                        "dml_type": null,
                        "entity_map": null,
                        "pretty_name": "category",
                        "render_type": "attribute"
                    },
                    {
                        "data_type": null,
                        "entity_map": null,
                        "pretty_name": "!=",
                        "render_type": "operator"
                    },
                    {
                        "data_type": null,
                        "entity_map": null,
                        "pretty_name": "Phishing",
                        "render_type": "value"
                    }
                ],
                "ALERT_WHITELIST_MIGRATED_FROM_ANALYTICS": 0,
                "ALERT_WHITELIST_MODIFY_TIME": 1644157302128,
                "ALERT_WHITELIST_NAME": "test1",
                "ALERT_WHITELIST_PRETTY_USER": "Public API - 3",
                "ALERT_WHITELIST_STATUS": "ENABLED",
                "ALERT_WHITELIST_USER": "N/A"
            },
            {
                "ALERT_WHITELIST_BACKWARDS_SCAN_STATUS": "DISABLED",
                "ALERT_WHITELIST_BACKWARDS_SCAN_TIMESTAMP": null,
                "ALERT_WHITELIST_COMMENT": "",
                "ALERT_WHITELIST_HITS": 0,
                "ALERT_WHITELIST_ID": 44,
                "ALERT_WHITELIST_INDICATOR": {
                    "filter": {
                        "AND": [
                            {
                                "SEARCH_FIELD": "alert_category",
                                "SEARCH_TYPE": "NEQ",
                                "SEARCH_VALUE": "Phishing"
                            }
                        ]
                    }
                },
                "ALERT_WHITELIST_INDICATOR_TEXT": [
                    {
                        "data_type": "TEXT",
                        "dml_type": null,
                        "entity_map": null,
                        "pretty_name": "category",
                        "render_type": "attribute"
                    },
                    {
                        "data_type": null,
                        "entity_map": null,
                        "pretty_name": "!=",
                        "render_type": "operator"
                    },
                    {
                        "data_type": null,
                        "entity_map": null,
                        "pretty_name": "Phishing",
                        "render_type": "value"
                    }
                ],
                "ALERT_WHITELIST_MIGRATED_FROM_ANALYTICS": 0,
                "ALERT_WHITELIST_MODIFY_TIME": 1644162015295,
                "ALERT_WHITELIST_NAME": "test1",
                "ALERT_WHITELIST_PRETTY_USER": "Public API - 3",
                "ALERT_WHITELIST_STATUS": "ENABLED",
                "ALERT_WHITELIST_USER": "N/A"
            }
        ]
    }
}
```

#### Human Readable Output

>### Exclusion
>|ALERT_WHITELIST_BACKWARDS_SCAN_STATUS|ALERT_WHITELIST_BACKWARDS_SCAN_TIMESTAMP|ALERT_WHITELIST_COMMENT|ALERT_WHITELIST_HITS|ALERT_WHITELIST_ID|ALERT_WHITELIST_INDICATOR|ALERT_WHITELIST_INDICATOR_TEXT|ALERT_WHITELIST_MIGRATED_FROM_ANALYTICS|ALERT_WHITELIST_MODIFY_TIME|ALERT_WHITELIST_NAME|ALERT_WHITELIST_PRETTY_USER|ALERT_WHITELIST_STATUS|ALERT_WHITELIST_USER|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| DISABLED |  |  | 0 | 43 | filter: {"AND": [{"SEARCH_FIELD": "alert_category", "SEARCH_TYPE": "NEQ", "SEARCH_VALUE": "Phishing"}]} | {'pretty_name': 'category', 'data_type': 'TEXT', 'render_type': 'attribute', 'entity_map': None, 'dml_type': None},<br/>{'pretty_name': '!=', 'data_type': None, 'render_type': 'operator', 'entity_map': None},<br/>{'pretty_name': 'Phishing', 'data_type': None, 'render_type': 'value', 'entity_map': None} | 0 | 1644157302128 | test1 | Public API - 3 | ENABLED | N/A |
>| DISABLED |  |  | 0 | 44 | filter: {"AND": [{"SEARCH_FIELD": "alert_category", "SEARCH_TYPE": "NEQ", "SEARCH_VALUE": "Phishing"}]} | {'pretty_name': 'category', 'data_type': 'TEXT', 'render_type': 'attribute', 'entity_map': None, 'dml_type': None},<br/>{'pretty_name': '!=', 'data_type': None, 'render_type': 'operator', 'entity_map': None},<br/>{'pretty_name': 'Phishing', 'data_type': None, 'render_type': 'value', 'entity_map': None} | 0 | 1644162015295 | test1 | Public API - 3 | ENABLED | N/A |

