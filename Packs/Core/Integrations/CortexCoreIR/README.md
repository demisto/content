The Cortex Core IR integration uses the Cortex API for detection and response, by natively integrating network, endpoint, and cloud data to stop sophisticated attacks.

## Configure Investigation & Response in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| Server URL (copy URL from Core - click ? to see more info.) |  | False |
| API Key ID |  | False |
| API Key |  | False |
| HTTP Timeout | The timeout of the HTTP requests sent to Cortex API \(in seconds\). | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### core-isolate-endpoint
***
Isolates the specified endpoint.


#### Base Command

`core-isolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the triggered incident. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | For polling use. | Optional | 
| endpoint_id | The endpoint ID (string) to isolate. Retrieve the string from the core-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Suppress an error when trying to isolate a disconnected endpoint. When set to false, an error is returned. Possible values are: true, false. Default is false. | Optional | 


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
| incident_id | Links the response action to the triggered incident. | Optional | 
| endpoint_id | The endpoint ID (string) to reverse the isolation. Retrieve it from the core-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Suppress an error when trying to unisolate a disconnected endpoint. When set to false, an error is be returned. Possible values are: true, false. Default is false. | Optional | 
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
| ip_list | A comma-separated list of private IP addresses.<br/> Example: 10.1.1.1,192.168.1.1. | Optional | 
| public_ip_list | A comma-separated list of public IP addresses that correlate to the last IPv4 address from which the Cortex XDR agent connected (know as `Last Origin IP`).<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
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
| status | A comma-separated list of endpoints statuses to filter. Possible values are: connected, disconnected, lost, uninstalled. | Optional |
| username | The usernames to query for, accepts a single user, or comma-separated list of usernames. | Optional |

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
| agent_version | agent_version returned from core-get-distribution-versions. Not required for Android platfoms. | Required | 
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
| download_package | Supported only for package_type x64 or x86. Whether to download the installation package file. | Optional | 


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
| distribution_ids | Status of distribution IDs, in a comma-separated list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Distribution.id | String | Distribution ID. | 
| Core.Distribution.status | String | Installation package status. | 

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
| timestamp_gte | Return logs when the timestamp is after 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs when the timestamp is before the 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of audit logs to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies the field by which to sort the results. By default the sort is defined as creation-time and descending. Can be "type", "sub_type", "result", or "timestamp". Possible values are: type, sub_type, result, timestamp. | Optional | 
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


### core-blocklist-files
***
Block lists requested files which have not already been block listed or added to allow lists.


#### Base Command

`core-blocklist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the triggered incident. | Optional | 
| hash_list | String that represents a list of hashed files you want to block list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| detailed_response | Choose either regular response or detailed response. Default value = false, regular response. Possible values are: true, false. Default is false. | Optional | 


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
| incident_id | Links the response action to the triggered incident. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow lists. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| detailed_response | Choose either regular response or detailed response. Default value = false, regular response. Possible values are: true, false. Default is false. | Optional | 


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
| incident_id | Links the response action to the triggered incident. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Required | 
| file_path | String that represents the path of the file you want to quarantine. | Required | 
| file_hash | String that represents the file’s hash. Must be a valid SHA256 hash. | Required | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-get-quarantine-status
***
Retrieves the quarantine status for a selected file.


#### Base Command

`core-get-quarantine-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | String that represents the endpoint ID. | Required | 
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
| incident_id | Links the response action to the incident that triggered it. | Optional | 
| file_hash | String that represents the file in hash. Must be a valid SHA256 hash. | Required | 
| endpoint_id | String that represents the endpoint ID. If you do not enter a specific endpoint ID, the request will run restore on all endpoints which relate to the quarantined file you defined. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-endpoint-scan
***
Runs a scan on a selected endpoint. To scan all endpoints, run this command with argument all=true. Note that scanning all the endpoints may cause performance issues and latency.


#### Base Command

`core-endpoint-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the triggered incident. | Optional | 
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
| isolate | Choose if an endpoint has been isolated. Select "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Choose whether to scan all of the endpoints or not. Default is false. Scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.endpointScan.actionId | Number | The action ID of the scan request. | 
| Core.endpointScan.aborted | Boolean | Was the scan aborted. | 
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-endpoint-scan-abort
***
Cancel the selected endpoints scan. A scan can only be cancelled if the selected endpoints are Pending or In Progress. To scan all endpoints, run the command with the argument all=true. Note that scanning all of the endpoints may cause performance issues and latency.


#### Base Command

`core-endpoint-scan-abort`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| isolate | Choose whether an endpoint has been isolated. Select "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints or not. Default is false. Note that scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.endpointScan.actionId | Unknown | The action id of the abort scan request. | 
| Core.endpointScan.aborted | Boolean | Was the scan cancelled. | 

### core-get-policy
***
Gets the policy name for a specific endpoint.


#### Base Command

`core-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID. Retrieve by running the core-get-endpoints command. | Required | 


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
| windows_supported | Choose to run the script on a Windows operating system. Possible values are: true, false. | Optional | 
| linux_supported | Choose to run the script on a Linux operating system. Possible values are: true, false. | Optional | 
| macos_supported | Choose to run the script on a Mac operating system. Possible values are: true, false. | Optional | 
| is_high_risk | Choose if the script has a high-risk outcome. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.Scripts | Unknown | The scripts command results. | 
| Core.Scripts.script_id | Unknown | Script ID. | 
| Core.Scripts.name | string | Name of the script. | 
| Core.Scripts.description | string | Description of the script. | 
| Core.Scripts.modification_date | Unknown | Timestamp of when the script was last modified. | 
| Core.Scripts.created_by | string | Name of the user who created the script. | 
| Core.Scripts.windows_supported | boolean | Choose to run the script on a Windows operating system. | 
| Core.Scripts.linux_supported | boolean | Choose to run the script on a Linux operating system. | 
| Core.Scripts.macos_supported | boolean | Choose to run the script on a Mac operating system. | 
| Core.Scripts.is_high_risk | boolean | Choose if the script has a high-risk outcome. | 
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
            },
            {
                "created_by": "Palo Alto Networks",
                "description": "Execute list of shell commands",
                "is_high_risk": true,
                "linux_supported": true,
                "macos_supported": true,
                "modification_date": "2022-01-05T10:14:14",
                "modification_date_timestamp": 1641377654469,
                "name": "execute_commands",
                "script_id": 2,
                "script_uid": "a6f7683c8e217d85bd3c398f0d3fb6bf",
                "windows_supported": true
            },
            {
                "created_by": "Palo Alto Networks",
                "description": "Kill all processes with a CPU usage higher than specified",
                "is_high_risk": true,
                "linux_supported": true,
                "macos_supported": true,
                "modification_date": "2022-01-05T10:14:14",
                "modification_date_timestamp": 1641377654480,
                "name": "process_kill_cpu",
                "script_id": 6,
                "script_uid": "3d928a24f61cd3c1116544900c424098",
                "windows_supported": true
            },
            {
                "created_by": "Palo Alto Networks",
                "description": "Kill all processes with a RAM usage higher than specified",
                "is_high_risk": true,
                "linux_supported": true,
                "macos_supported": true,
                "modification_date": "2021-05-04T14:33:48",
                "modification_date_timestamp": 1620138828795,
                "name": "process_kill_mem",
                "script_id": 7,
                "script_uid": "87d4547df6d4882a3c006ec58c3b8bf4",
                "windows_supported": true
            },
            {
                "created_by": "Palo Alto Networks",
                "description": "Kill processes by name",
                "is_high_risk": true,
                "linux_supported": true,
                "macos_supported": true,
                "modification_date": "2021-05-04T14:33:48",
                "modification_date_timestamp": 1620138828803,
                "name": "process_kill_name",
                "script_id": 8,
                "script_uid": "fd0a544a99a9421222b4f57a11839481",
                "windows_supported": true
            },
            {
                "created_by": "Palo Alto Networks",
                "description": "Delete registry value or delete registry key with all its values",
                "is_high_risk": true,
                "linux_supported": false,
                "macos_supported": false,
                "modification_date": "2021-05-04T14:33:48",
                "modification_date_timestamp": 1620138828812,
                "name": "registry_delete",
                "script_id": 9,
                "script_uid": "ad36488a20cdbdd1604ec4bec9da5c41",
                "windows_supported": true
            },
            {
                "created_by": "Palo Alto Networks",
                "description": "Set registry value",
                "is_high_risk": true,
                "linux_supported": false,
                "macos_supported": false,
                "modification_date": "2021-05-04T14:33:48",
                "modification_date_timestamp": 1620138828829,
                "name": "registry_set",
                "script_id": 11,
                "script_uid": "896392a13b2ef0ae75b3f2396125037d",
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
Deletes selected endpoints in the Cortex app. You can delete up to 1000 endpoints.


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
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

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
| Core.ScriptMetadata.windows_supported | boolean | Choose to run the script on a Windows operating system. | 
| Core.ScriptMetadata.linux_supported | boolean | Choose to run the script on a Linux operating system. | 
| Core.ScriptMetadata.macos_supported | boolean | Choose to run the script on a Mac operating system. | 
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
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

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


### core-run-script (Deprecated)
***
Deprecated. Use core-script-run instead. 

#### Base Command

`core-run-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| incident_id | Links the response action to the incident that triggered it. it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| snippet_code | Section of a script you want to initiate on an endpoint, for example, print("7"). | Required | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

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
| Core.ScriptResult.results.command | String | The command that was executed by the script. | 
| Core.ScriptResult.results.command_output | Array | The output of the command executed by the script. | 

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
| incident_id | Link the response action to triggered incident. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| commands | Comma-separated list of shell commands to execute. Set the `is_raw_command` argument to `true` to prevent splitting by commas. (Useful when using `\|\|`, `&amp;&amp;`, `;` separators for controlling the flow of multiple commands). | Required | 
| is_raw_command | Whether to pass the command as-is. When false, the command is split by commas and sent as a list of commands, that are run independently. | Optional | 
| command_type | Type of shell command. Possible values are: powershell, native. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| action_id | For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptRun.action_id | Number | ID of the action initiated. | 
| Core.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-run-script-delete-file
***
Initiates a new endpoint script execution to delete the specified file.


#### Base Command

`core-run-script-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-run-script-file-exists
***
Initiates a new endpoint script execution to check if file exists.


#### Base Command

`core-run-script-file-exists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-run-script-kill-process
***
Initiates a new endpoint script execution kill process.


#### Base Command

`core-run-script-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

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
Reports to WildFire about incorrect hash verdict through Cortex.


#### Base Command

`core-report-incorrect-wildfire`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | String that represents the file’s hash. Must be a valid SHA256 hash. | Required | 
| new_verdict | The new verdict of the file. 0 - benign, 1 - malware. Possible values are: 0, 1. | Required | 
| reason | String that represents the reason of the report. | Required | 
| email | User’s email address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.WildFire.file_hash | Number | String that represents the file’s hash. | 
| Core.WildFire.new_verdict | Number | The new verdict of the file. | 

### core-remove-allowlist-files
***
Removes requested files from allow list.


#### Base Command

`core-remove-allowlist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
| incident_id | Links the response action to the incident that triggered it. | Optional | 
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
Adds alert exclusion rule based on filterObject.


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
            "rule_id": 45
        }
    }
}
```

#### Human Readable Output

>### Add Exclusion
>|rule_id|
>|---|
>| 45 |


### core-delete-exclusion
***
Delete an alert exclusion rule based on rule ID.


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
Get a list of the alerts exclusion.


#### Base Command

`core-get-exclusion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_ID | Links the response action to the tenant that triggered it. | Optional | 
| filterObject | Filter object for the exclusion. Example: {"filter":{"AND":[{"SEARCH_FIELD":"alert_category","SEARCH_TYPE":"NEQ","SEARCH_VALUE":"Phishing"}]}}. | Optional | 
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
                "ALERT_WHITELIST_ID": 45,
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
                "ALERT_WHITELIST_MODIFY_TIME": 1645102011552,
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
>| DISABLED |  |  | 0 | 45 | filter: {"AND": [{"SEARCH_FIELD": "alert_category", "SEARCH_TYPE": "NEQ", "SEARCH_VALUE": "Phishing"}]} | {'pretty_name': 'category', 'data_type': 'TEXT', 'render_type': 'attribute', 'entity_map': None, 'dml_type': None},<br/>{'pretty_name': '!=', 'data_type': None, 'render_type': 'operator', 'entity_map': None},<br/>{'pretty_name': 'Phishing', 'data_type': None, 'render_type': 'value', 'entity_map': None} | 0 | 1645102011552 | test1 | Public API - 3 | ENABLED | N/A |

### core-get-cloud-original-alerts
***
Returns information about each alert ID.


#### Base Command

`core-get-cloud-original-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alert IDs. | Required | 
| events_from_decider_format | Whether to return events_from_decider context output as a dictionary (the raw API response) or as a list (improved for playbook automation) - relevant only when filter_alert_fields is set to False. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.OriginalAlert.event._time | String | The timestamp of the occurence of the event. | 
| Core.OriginalAlert.event.vendor | String | Vendor name. | 
| Core.OriginalAlert.event.event_timestamp | Number | Event timestamp. | 
| Core.OriginalAlert.event.event_type | Number | Event type \(static 500\). | 
| Core.OriginalAlert.event.cloud_provider | String | The cloud provider - GCP, AZURE, or AWS. | 
| Core.OriginalAlert.event.project | String | The project in which the event occurred. | 
| Core.OriginalAlert.event.cloud_provider_event_id | String | The ID given to the event by the cloud provider, if the ID exists. | 
| Core.OriginalAlert.event.cloud_correlation_id | String | The ID the cloud provider is using to aggregate events that are part of the same general event. | 
| Core.OriginalAlert.event.operation_name_orig | String | The name of the operation that occurred, as supplied by the cloud provider. | 
| Core.OriginalAlert.event.operation_name | String | The normalized name of the operation performed by the event. | 
| Core.OriginalAlert.event.identity_orig | String | Contains the original identity related fields as provided by the cloud provider. | 
| Core.OriginalAlert.event.identity_name | String | The name of the identity that initiated the action. | 
| Core.OriginalAlert.event.identity_uuid | String | Same as identity_name but also contains the UUID of the identity if it exists. | 
| Core.OriginalAlert.event.identity_type | String | An enum representing the type of the identity. | 
| Core.OriginalAlert.event.identity_sub_type | String | An enum representing the sub-type of the identity, respective to its identity_type. | 
| Core.OriginalAlert.event.identity_invoked_by_name | String | The name of the identity that invoked the action as it appears in the log. | 
| Core.OriginalAlert.event.identity_invoked_by_uuid | String | The UUID of the identity that invoked the action as it appears in the log. | 
| Core.OriginalAlert.event.identity_invoked_by_type | String | An enum that represents the type of identity event that invoked the action. | 
| Core.OriginalAlert.event.identity_invoked_by_sub_type | String | An enum that represents the respective sub_type of the type of identity \(identity_type\) that has invoked the action. | 
| Core.OriginalAlert.event.operation_status | String | Status of whether the operation has succeed or failed, if provided. | 
| Core.OriginalAlert.event.operation_status_orig | String | The operation status code as it appears in the log, including lookup from code number to code name. | 
| Core.OriginalAlert.event.operation_status_orig_code | String | The operation status code as it appears in the log. | 
| Core.OriginalAlert.event.operation_status_reason_provided | String | Description of the error, if the log record indicates an error and the cloud provider supplied the reason. | 
| Core.OriginalAlert.event.resource_type | String | The normalized type of the service that emitted the log row. | 
| Core.OriginalAlert.event.resource_type_orig | String | The type of the service that omitted the log as provided by the cloud provider. | 
| Core.OriginalAlert.event.resource_sub_type | String | The sub-type respective to the resource_type field, normalized across all cloud providers. | 
| Core.OriginalAlert.event.resource_sub_type_orig | String | The sub-type of the service that emitted this log row as provided by the cloud provider. | 
| Core.OriginalAlert.event.region | String | The cloud region of the resource that emitted the log. | 
| Core.OriginalAlert.event.zone | String | The availability zone of the resource that emitted the log. | 
| Core.OriginalAlert.event.referenced_resource | String | The cloud resource referenced in the audit log. | 
| Core.OriginalAlert.event.referenced_resource_name | String | Same as referenced_resource but provides only the substring that represents the resource name instead of the full asset ID. | 
| Core.OriginalAlert.event.referenced_resources_count | Number | The number of extracted resources referenced in this audit log. | 
| Core.OriginalAlert.event.user_agent | String | The user agent provided in the call to the API of the cloud provider. | 
| Core.OriginalAlert.event.caller_ip | String | The IP of the caller that performed the action in the log. | 
| Core.OriginalAlert.event.caller_ip_geolocation | String | The geolocation associated with the caller_ip's value. | 
| Core.OriginalAlert.event.caller_ip_asn | Number | The ASN of the caller_ip's value. | 
| Core.OriginalAlert.event.caller_project | String | The project of the caller entity. | 
| Core.OriginalAlert.event.raw_log | Unknown | The raw log that is being normalized. | 
| Core.OriginalAlert.event.log_name | String | The name of the log that contains the log row. | 
| Core.OriginalAlert.event.caller_ip_asn_org | String | The organization associated with the ASN of the caller_ip's value. | 
| Core.OriginalAlert.event.event_base_id | String | Event base ID. | 
| Core.OriginalAlert.event.ingestion_time | String | Ingestion time. | 

### core-get-dynamic-analysis
***
Returns dynamic analysis of each alert ID.


#### Base Command

`core-get-dynamic-analysis`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alert IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.DynamicAnalysis.causalityId | String |  | 
| Core.DynamicAnalysis.internals.name | String |  | 
| Core.DynamicAnalysis.internals.factName | String |  | 
| Core.DynamicAnalysis.internals.timestamp | Date |  | 
| Core.DynamicAnalysis.internals.eventId | String |  | 
| Core.DynamicAnalysis.internals.attributes.user_presence | String |  | 
| Core.DynamicAnalysis.internals.attributes.shellcode_address | String |  | 
| Core.DynamicAnalysis.internals.attributes.tid | String |  | 
| Core.DynamicAnalysis.internals.attributes.parent_pid | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_sign | String |  | 
| Core.DynamicAnalysis.internals.attributes.sync_action | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_remote_session | String |  | 
| Core.DynamicAnalysis.internals.attributes.peb | String |  | 
| Core.DynamicAnalysis.internals.attributes.process_image_path | String |  | 
| Core.DynamicAnalysis.internals.attributes.command_line | String |  | 
| Core.DynamicAnalysis.internals.attributes.scanned_buffer_crc32_stacktrace_allocation_base_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.page_base_shellcode_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.os_sig_status | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_info_legal_copyright | String |  | 
| Core.DynamicAnalysis.internals.attributes.user_name | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_heavens_gate | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_impersonated | String |  | 
| Core.DynamicAnalysis.internals.attributes.os_parent_instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_info_internal_name | String |  | 
| Core.DynamicAnalysis.internals.attributes.stack_trace | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_injected | String |  | 
| Core.DynamicAnalysis.internals.attributes.pid | String |  | 
| Core.DynamicAnalysis.internals.attributes.thread_context_eip_image_path | String |  | 
| Core.DynamicAnalysis.internals.attributes.image_path_sha256 | String |  | 
| Core.DynamicAnalysis.internals.attributes.montepi_err | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_info_company_name | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_info_original_name | String |  | 
| Core.DynamicAnalysis.internals.attributes.instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.yara_file_scan_result | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_obj_flags | String |  | 
| Core.DynamicAnalysis.internals.attributes.should_obfuscate | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_size | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_info_is_dot_net | String |  | 
| Core.DynamicAnalysis.internals.attributes.call_region_shellcode_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.allocation_base_shellcode_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.signer_name | String |  | 
| Core.DynamicAnalysis.internals.attributes.original_command_line | String |  | 
| Core.DynamicAnalysis.internals.attributes.yara_rules_results_stacktrace_page_base_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.rpc_interface_uuid | String |  | 
| Core.DynamicAnalysis.internals.attributes.rpc_interface_minor_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.telem | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_trusted_signer | String |  | 
| Core.DynamicAnalysis.internals.attributes.thread_context_eip | String |  | 
| Core.DynamicAnalysis.internals.attributes.requested_parent_instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_cgo | String |  | 
| Core.DynamicAnalysis.internals.attributes.parent_cid | String |  | 
| Core.DynamicAnalysis.internals.attributes.enabled_privileges | Date |  | 
| Core.DynamicAnalysis.internals.attributes.peb32 | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_embedded_sign | String |  | 
| Core.DynamicAnalysis.internals.attributes.rpc_function_opnum | String |  | 
| Core.DynamicAnalysis.internals.attributes.parent_thread_instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.remote_causality_actor_ip | String |  | 
| Core.DynamicAnalysis.internals.attributes.canonized_process_image_path | String |  | 
| Core.DynamicAnalysis.internals.attributes.scanned_buffer_crc32_stacktrace_call_region_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.yara_rules_results_stacktrace_allocation_base_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.entry_point_rva | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_stack_pivot | String |  | 
| Core.DynamicAnalysis.internals.attributes.os_parent_pid | String |  | 
| Core.DynamicAnalysis.internals.attributes.image_path_md5 | String |  | 
| Core.DynamicAnalysis.internals.attributes.causality_actor_type | String |  | 
| Core.DynamicAnalysis.internals.attributes.timestamp | String |  | 
| Core.DynamicAnalysis.internals.attributes.is_in_transaction | String |  | 
| Core.DynamicAnalysis.internals.attributes.cid | String |  | 
| Core.DynamicAnalysis.internals.attributes.integrity_level | String |  | 
| Core.DynamicAnalysis.internals.attributes.actor_type | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_info_description | String |  | 
| Core.DynamicAnalysis.internals.attributes.chisq_prob | String |  | 
| Core.DynamicAnalysis.internals.attributes.parent_tid | String |  | 
| Core.DynamicAnalysis.internals.attributes.rpc_interface_major_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.dse_internal | String |  | 
| Core.DynamicAnalysis.internals.attributes.telem_bit_mask | String |  | 
| Core.DynamicAnalysis.internals.attributes.process_image_name | String |  | 
| Core.DynamicAnalysis.internals.attributes.parent_instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.entropy | String |  | 
| Core.DynamicAnalysis.internals.attributes.call_region_base_address | String |  | 
| Core.DynamicAnalysis.internals.attributes.yara_rules_results_stacktrace_call_region_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.scanned_buffer_crc32_stacktrace_page_base_buffer | String |  | 
| Core.DynamicAnalysis.internals.attributes.image_base | String |  | 
| Core.DynamicAnalysis.internals.attributes.sync_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.effective_user_sid | String |  | 
| Core.DynamicAnalysis.internals.attributes.requested_parent_pid | String |  | 
| Core.DynamicAnalysis.internals.attributes.event_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.rpc_protocol | String |  | 
| Core.DynamicAnalysis.internals.processIdx | Number |  | 
| Core.DynamicAnalysis.internals.instanceId | String |  | 
| Core.DynamicAnalysis.internals.attributes.scriptblock_text | String |  | 
| Core.DynamicAnalysis.internals.attributes.script_path | String |  | 
| Core.DynamicAnalysis.internals.attributes.actor_pid | String |  | 
| Core.DynamicAnalysis.internals.attributes.actor_instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.actor_thread_instance_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.etw_event_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.actor_tid | String |  | 
| Core.DynamicAnalysis.internals.attributes.suspicious_strings | String |  | 
| Core.DynamicAnalysis.internals.attributes.suspicious_strings_context | String |  | 
| Core.DynamicAnalysis.internals.attributes.content_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.script_hash | String |  | 
| Core.DynamicAnalysis.internals.attributes.dotnet_callstack | String |  | 
| Core.DynamicAnalysis.internals.attributes.hook_type | String |  | 
| Core.DynamicAnalysis.internals.attributes.appdomain_id | String |  | 
| Core.DynamicAnalysis.internals.attributes.ps_assembly_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.original_length | String |  | 
| Core.DynamicAnalysis.internals.attributes.invoke_expression_count | String |  | 
| Core.DynamicAnalysis.internals.attributes.file_path | String |  | 
| Core.DynamicAnalysis.internals.attributes.content | String |  | 
| Core.DynamicAnalysis.internals.attributes.edr_assembly_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.expression_tree_scan_result | String |  | 
| Core.DynamicAnalysis.internals.attributes.content_length | String |  | 
| Core.DynamicAnalysis.internals.attributes.local_analysis_verdict | String |  | 
| Core.DynamicAnalysis.internals.attributes.clr_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.powershell_version | String |  | 
| Core.DynamicAnalysis.internals.attributes.script_source | String |  | 
| Core.DynamicAnalysis.internals.attributes.prio | String |  | 
| Core.DynamicAnalysis.internals.attributes.build_timestamp | Date |  | 
| Core.DynamicAnalysis.potentialPreventionActionOverride | Boolean |  | 
| Core.DynamicAnalysis.isBiocRule | Boolean |  | 
| Core.DynamicAnalysis.biocId | Number |  | 
| Core.DynamicAnalysis.additionalData | String |  | 
| Core.DynamicAnalysis.biocRuleName | String |  | 
| Core.DynamicAnalysis.reachedMaxActivationsPerRule | Boolean |  | 
| Core.DynamicAnalysis.syncActionStatus | Number |  | 
| Core.DynamicAnalysis.spawnerImagePath | String |  | 
| Core.DynamicAnalysis.spawnerCmdline | String |  | 
| Core.DynamicAnalysis.spawnerSigner | String |  | 
| Core.DynamicAnalysis.osSpawnerImagePath | String |  | 
| Core.DynamicAnalysis.osSpawnerCmdline | String |  | 
| Core.DynamicAnalysis.osSpawnerSigner | String |  | 

### core-get-hash-analytics-prevalence
***
Get the prevalence of a file, identified by sha256.


#### Base Command

`core-get-hash-analytics-prevalence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The sha256 of a file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AnalyticsPrevalence.Hash.value | Boolean | Whether the hash is prevalent or not. | 
| Core.AnalyticsPrevalence.Hash.data.global_prevalence.value | Number | The global prevalence of the hash. | 
| Core.AnalyticsPrevalence.Hash.data.local_prevalence.value | Number | The local prevalence of the hash. | 
| Core.AnalyticsPrevalence.Hash.data.prevalence.value | Number | The prevalence of the hash. | 

### core-get-IP-analytics-prevalence
***
Get the prevalence of an ip, identified by ip_address.


#### Base Command

`core-get-IP-analytics-prevalence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AnalyticsPrevalence.Ip.value | Boolean | Whether the IP address is prevalent or not. | 
| Core.AnalyticsPrevalence.Ip.data.global_prevalence.value | Number | The global prevalence of the IP. | 
| Core.AnalyticsPrevalence.Ip.data.local_prevalence.value | Number | The local prevalence of the IP. | 
| Core.AnalyticsPrevalence.Ip.data.prevalence.value | Number | The prevalence of the IP. | 

### core-get-domain-analytics-prevalence
***
Get the prevalence of a domain, identified by domain_name.


#### Base Command

`core-get-domain-analytics-prevalence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | The domain name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AnalyticsPrevalence.Domain.value | Boolean | Whether the domain is prevalent or not. | 
| Core.AnalyticsPrevalence.Domain.data.global_prevalence.value | Number | The global prevalence of the domain. | 
| Core.AnalyticsPrevalence.Domain.data.local_prevalence.value | Number | The local prevalence of the domain. | 
| Core.AnalyticsPrevalence.Domain.data.prevalence.value | Number | The prevalence of the domain. | 

### core-get-process-analytics-prevalence
***
Get the prevalence of a process, identified by process_name.


#### Base Command

`core-get-process-analytics-prevalence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_name | The process name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AnalyticsPrevalence.Process.value | Boolean | Whether the process is prevalent or not. | 
| Core.AnalyticsPrevalence.Process.data.global_prevalence.value | Number | The global prevalence of the process. | 
| Core.AnalyticsPrevalence.Process.data.local_prevalence.value | Number | The local prevalence of the process. | 
| Core.AnalyticsPrevalence.Process.data.prevalence.value | Number | The prevalence of the process. | 

### core-get-registry-analytics-prevalence
***
Get the prevalence of a registry_path, identified by key_name, value_name.


#### Base Command

`core-get-registry-analytics-prevalence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_name | The key name of a registry path. | Required | 
| value_name | The value name of a registry path. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AnalyticsPrevalence.Registry.value | Boolean | Whether the registry is prevalent or not. | 
| Core.AnalyticsPrevalence.Registry.data.global_prevalence.value | Number | The global prevalence of the registry. | 
| Core.AnalyticsPrevalence.Registry.data.local_prevalence.value | Number | The local prevalence of the registry. | 
| Core.AnalyticsPrevalence.Registry.data.prevalence.value | Number | The prevalence of the registry. | 

### core-get-cmd-analytics-prevalence
***
Get the prevalence of a process_command_line, identified by process_command_line.


#### Base Command

`core-get-cmd-analytics-prevalence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_command_line | The process command line. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.AnalyticsPrevalence.Cmd.value | Boolean | Whether the CMD is prevalent or not. | 
| Core.AnalyticsPrevalence.Cmd.data.global_prevalence.value | Number | The global prevalence of the CMD. | 
| Core.AnalyticsPrevalence.Cmd.data.local_prevalence.value | Number | The local prevalence of the CDM. | 
| Core.AnalyticsPrevalence.Cmd.data.prevalence.value | Number | The prevalence of the Cmd. | 


### core-add-endpoint-tag
***
Add a tag to one or more endpoints.


#### Base Command

`core-add-endpoint-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of tenant IDs of the endpoint(s) for which you want to assign the tag. | Required | 
| tag | The tag name to assign to the endpoint(s). | Required | 
| endpoint_id_list | A comma-separated list of endpoint IDs to filter by them. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names. <br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of IP addresses.<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | A comma-separated list of group names to which the agent belongs.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform. Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated. Possible values are: isolated, unisolated. | Optional | 
| hostname | A comma-separated list of hostnames.<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| status | The status of the endpoint to filter. Possible values are: connected, disconnected, lost, uninstalled. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example
```!core-add-endpoint-tag endpoint_ids=1234 tag=test```
#### Human Readable Output

>Successfully added tag test to endpoint(s) ['1234']

### core-remove-endpoint-tag
***
Remove a tag from one or more endpoints.

#### Base Command

`core-remove-endpoint-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of tenant IDs of the endpoint(s) for which you want to remove the tag. | Required | 
| tag | The tag name to remove from the endpoint(s). | Required | 
| endpoint_id_list | A comma-separated list of endpoint IDs to filter by them. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names. <br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of IP addresses.<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | A comma-separated list of group names to which the agent belongs.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform. Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated. Possible values are: isolated, unisolated. | Optional | 
| hostname | A comma-separated list of hostnames.<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| status | The status of the endpoint to filter. Possible values are: connected, disconnected, lost, uninstalled. | Optional | 


#### Context Output
There is no context output for this command.

#### Command example
```!core-remove-endpoint-tag endpoint_ids=1234 tag=test```

#### Human Readable Output

>Successfully removed tag test from endpoint(s) ['1234']

### core-endpoint-alias-change
***
Gets a list of endpoints according to the passed filters, and changes their alias name. Filtering by multiple fields will be concatenated using the AND condition (OR is not supported).

#### Base Command

`core-endpoint-alias-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the endpoint to use as a filter. Possible values are: connected, disconnected. | Optional | 
| endpoint_id_list | A comma-separated list of endpoint IDs to use as a filter. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names to use as a filter.<br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of IP addresses to use as a filter.<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | A comma-separated list of group names to which the agent belongs to use as a filter.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform to use as a filter. Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names to use as a filter.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated to use as a filter. Possible values are: isolated, unisolated.  Note: This argument returns only the first endpoint that matches. | Optional | 
| hostname | A comma-separated list of hostnames to use as a filter.<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen after {last_seen_gte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| username | The usernames to query for to use as a filter. Accepts a single user, or comma-separated list of usernames. | Optional | 
| new_alias_name | The alias name to change to. Note: If you send an empty field, (e.g new_alias_name=\"\") the current alias name is deleted.| Required | 
| scan_status | The scan status of the endpoint to use as a filter. Possible values are: none, pending, in_progress, canceled, aborted, pending_cancellation, success, error. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!core-endpoint-alias-change new_alias_name=test scan_status=success ip_list=1.1.1.1```
#### Human Readable Output

>The endpoint alias was changed successfully.
Note: If there is no error in the process, then this is the output even when the specific endpoint does not exist.

### core-list-users

***
Retrieve a list of the current users in the environment.
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per TB.

#### Base Command

`core-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.User.user_email | string | Email address of the user | 
| Core.User.user_first_name | string | First name of the user | 
| Core.User.user_last_name | string | Last name of the user. | 
| Core.User.role_name | string | Role name associated with the user. | 
| Core.User.last_logged_in | Number | Timestamp of when the user last logged in. | 
| Core.User.user_type | string | Type of user. | 
| Core.User.groups | array | Name of user groups associated with the user, if applicable. | 
| Core.User.scope | array | Name of scope associated with the user, if applicable. | 

#### Command example
```!core-list-users```
#### Context Example
```json
{
    "dummy": {
        "User": [
            {
                "groups": [],
                "last_logged_in": 1648158415051,
                "role_name": "dummy",
                "scope": [],
                "user_email": "dummy@dummy.com",
                "user_first_name": "dummy",
                "user_last_name": "dummy",
                "user_type": "dummy"
            },
             {
                "groups": [],
                "last_logged_in": null,
                "role_name": "dummy",
                "scope": [],
                "user_email": "dummy@dummy.com",
                "user_first_name": "dummy",
                "user_last_name": "dummy",
                "user_type": "dummy"
            }            
        ]
    }
}
```

#### Human Readable Output

>### Users
>|First Name|Groups|Last Name|Role|Type|User email|
>|---|---|---|---|---|---|
>| dummy |  | dummy | dummy | dummy | dummy |
>| dummy |  | dummy | dummy | dummy | dummy |



### core-list-risky-users

***
Retrieve the risk score of a specific user or list of users with the highest risk score in the environment along with the reason affecting each score.
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per TB.

#### Base Command

`core-list-risky-users`

#### Input

| **Argument Name** | **Description**                                                                                                         | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------| --- |
| user_id | Unique ID of a specific user.<br/>User ID could be either of the `foo/dummy` format, or just `dummy`.<br/>.             | Optional | 
| limit | Limit the number of users that will appear in the list. (Use limit when no specific host is requested.). Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.RiskyUser.type | String | Form of identification element. | 
| Core.RiskyUser.id | String | Identification value of the type field. | 
| Core.RiskyUser.score | Number | The score assigned to the user. | 
| Core.RiskyUser.reasons.date created | String | Date when the incident was created. | 
| Core.RiskyUser.reasons.description | String | Description of the incident. | 
| Core.RiskyUser.reasons.severity | String | The severity of the incident | 
| Core.RiskyUser.reasons.status | String | The incident status | 
| Core.RiskyUser.reasons.points | Number | The score. | 

#### Command example
```!core-list-risky-users user_id=dummy```
#### Context Example
```json
{
    "Core": {
        "RiskyUser": {
            "id": "dummy",
            "reasons": [],
            "score": 0,
            "type": "user"
        }
    }
}
```

#### Human Readable Output

>### Risky Users
>|User ID|Score|Description|
>|---|---|---|
>| dummy | 0 |  |


### core-list-risky-hosts

***
Retrieve the risk score of a specific host or list of hosts with the highest risk score in the environment along with the reason affecting each score.
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per TB.

#### Base Command

`core-list-risky-hosts`

#### Input

| **Argument Name** | **Description**                                                                                                                                           | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| host_id | The host name of a specific host.                                                                                                                         | Optional | 
| limit | Limit the number of hosts that will appear in the list. By default, the limit is 10 hosts.(Use limit when no specific host is requested.). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.RiskyHost.type | String | Form of identification element. | 
| Core.RiskyHost.id | String | Identification value of the type field. | 
| Core.RiskyHost.score | Number | The score assigned to the host. | 
| Core.RiskyHost.reasons.date created | String | Date when the incident was created. | 
| Core.RiskyHost.reasons.description | String | Description of the incident. | 
| Core.RiskyHost.reasons.severity | String | The severity of the incident | 
| Core.RiskyHost.reasons.status | String | The incident status | 
| Core.RiskyHost.reasons.points | Number | The score. | 

#### Command example
```!core-list-risky-hosts host_id=dummy```
#### Context Example
```json
{
    "Core": {
        "RiskyHost": {
            "id": "dummy",
            "reasons": [],
            "score": 0,
            "type": "dummy"
        }
    }
}
```

#### Human Readable Output

>### Risky Hosts
>|Host ID|Score|Description|
>|---|---|---|
>| dummy | 0 |  |


### core-list-user-groups

***
Retrieve a list of the current user emails associated with one or more user groups in the environment.
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per TB.

#### Base Command

`core-list-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_names | A comma-separated list of one or more user group names for which you want the associated users. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.UserGroup.group_name | String | Name of the user group. | 
| Core.UserGroup.description | String | Description of the user group, if available. | 
| Core.UserGroup.pretty_name | String | Name of the user group as it appears in the management console. | 
| Core.UserGroup.insert_time | Number | Timestamp of when the user group was created. | 
| Core.UserGroup.update_time | Number | Timestamp of when the user group was last updated. | 
| Core.UserGroup.user_email | array | List of email addresses belonging to the users associated with the user group. | 
| Core.UserGroup.source | String | Type of user group. | 

#### Command example
```!core-list-user-groups group_names=test```
#### Context Example
```json
{
    "Core": {
        "UserGroup": {
            "description": "test",
            "group_name": "test",
            "insert_time": 1684746187678,
            "pretty_name": null,
            "source": "Custom",
            "update_time": 1684746209062,
            "user_email": [
                null
            ]
        }
    }
}
```

#### Human Readable Output

>### Groups
>|Group Name|Group Description|User email|
>|---|---|---|
>| test | test for demo |  |


### core-get-incidents

***
Returns a list of incidents, which you can filter by a list of incident IDs (max. 100), the time the incident was last modified, and the time the incident was created.
If you pass multiple filtering arguments, they will be concatenated using the AND condition. The OR condition is not supported.

##### Required Permissions

Required Permissions For API call:
`Alerts And Incidents` --> `View`
Builtin Roles with this permission includes: "Investigator", "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`core-get-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or before the specified date/time will be retrieved. | Optional | 
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or after the specified date/time will be retrieved. | Optional | 
| lte_modification_time | Filters returned incidents that were created on or before the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| gte_modification_time | Filters returned incidents that were modified on or after the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| incident_id_list | An array or CSV string of incident IDs. | Optional | 
| since_creation_time | Filters returned incidents that were created on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional | 
| since_modification_time | Filters returned incidents that were modified on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional | 
| sort_by_modification_time | Sorts returned incidents by the date/time that the incident was last modified ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. Default is 100. | Optional | 
| status | Filters only incidents in the specified status. The options are: new, under_investigation, resolved_known_issue, resolved_false_positive, resolved_true_positive resolved_security_testing, resolved_other, resolved_auto. | Optional | 
| starred | Whether the incident is starred (Boolean value: true or false). Possible values are: true, false. | Optional | 
| starred_incidents_fetch_window | Starred fetch window timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days. | Optional | 


#### Context Output

| **Path** | **Type** | **Description**                                                                                                      |
| --- | --- |----------------------------------------------------------------------------------------------------------------------|
| Core.Incident.incident_id | String | Unique ID assigned to each returned incident.                                                                        | 
| Core.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity. Can be "low", "medium", "high" | 
| Core.Incident.manual_description | String | Incident description provided by the user.                                                                           | 
| Core.Incident.assigned_user_mail | String | Email address of the assigned user.                                                                                  | 
| Core.Incident.high_severity_alert_count | String | Number of alerts with the severity HIGH.                                                                             | 
| Core.Incident.host_count | number | Number of hosts involved in the incident.                                                                            | 
| Core.Incident.xdr_url | String | A link to the incident view on Cortex XDR or XSIAM.                                                                  | 
| Core.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident.                                                                      | 
| Core.Incident.alert_count | number | Total number of alerts in the incident.                                                                              | 
| Core.Incident.med_severity_alert_count | number | Number of alerts with the severity MEDIUM.                                                                           | 
| Core.Incident.user_count | number | Number of users involved in the incident.                                                                            | 
| Core.Incident.severity | String | Calculated severity of the incident. Valid values are:                                                               
"low","medium","high"
 | 
| Core.Incident.low_severity_alert_count | String | Number of alerts with the severity LOW. | 
| Core.Incident.status | String | Current status of the incident. Valid values are: "new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing" or "resolved_other".
 | 
| Core.Incident.description | String | Dynamic calculated description of the incident. | 
| Core.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| Core.Incident.notes | String | Comments entered by the user regarding the incident. | 
| Core.Incident.creation_time | date | Date and time the incident was created on Cortex XDR or XSIAM. | 
| Core.Incident.detection_time | date | Date and time that the first alert occurred in the incident. | 
| Core.Incident.modification_time | date | Date and time that the incident was last modified. | 


##### Command Example

```!core-get-incidents gte_creation_time=2010-10-10T00:00:00 limit=3 sort_by_creation_time=desc```

##### Context Example

```
{
    "Core.Incident": [
        {
            "host_count": 1, 
            "incident_id": "4", 
            "manual_severity": "medium", 
            "description": "5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast  ", 
            "severity": "medium", 
            "modification_time": 1579290004178, 
            "assigned_user_pretty_name": null, 
            "notes": null, 
            "creation_time": 1577276587937, 
            "alert_count": 5, 
            "med_severity_alert_count": 1, 
            "detection_time": null, 
            "assigned_user_mail": null, 
            "resolve_comment": "This issue was solved in Incident number 192304", 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/4", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 4, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "3", 
            "manual_severity": "medium", 
            "description": "'test 1' generated by Virus Total - Firewall", 
            "severity": "medium", 
            "modification_time": 1579237974014, 
            "assigned_user_pretty_name": "woo@demisto.com", 
            "notes": null, 
            "creation_time": 1576100096594, 
            "alert_count": 1, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": "woo@demisto.com", 
            "resolve_comment": null, 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/3", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 1, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "2", 
            "manual_severity": "high", 
            "description": "'Alert Name Example 333' along with 1 other alert generated by Virus Total - VPN & Firewall-3 and Checkpoint - SandBlast", 
            "severity": "high", 
            "modification_time": 1579288790259, 
            "assigned_user_pretty_name": null, 
            "notes": null, 
            "creation_time": 1576062816474, 
            "alert_count": 2, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": null, 
            "resolve_comment": null, 
            "status": "under_investigation", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/2", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 2, 
            "manual_description": null
        }
    ]
}
```

##### Human Readable Output

>### Incidents

>|alert_count|assigned_user_mail|assigned_user_pretty_name|creation_time|description|detection_time|high_severity_alert_count|host_count|incident_id|low_severity_alert_count|manual_description|manual_severity|med_severity_alert_count|modification_time|notes|resolve_comment|severity|starred|status|user_count|xdr_url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 5 |  |  | 1577276587937 | 5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast   |  | 4 | 1 | 4 | 0 |  | medium | 1 | 1579290004178 |  | This issue was solved in Incident number 192304 | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/4` |
>| 1 | woo@demisto.com | woo@demisto.com | 1576100096594 | 'test 1' generated by Virus Total - Firewall |  | 1 | 1 | 3 | 0 |  | medium | 0 | 1579237974014 |  |  | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/3` |
>| 2 |  |  | 1576062816474 | 'Alert Name Example 333' along with 1 other alert generated by Virus Total - VPN & Firewall-3 and Checkpoint - SandBlast |  | 2 | 1 | 2 | 0 |  | high | 0 | 1579288790259 |  |  | high | false | under_investigation | 1 | `https://some.xdr.url.com/incident-view/2` 
>

### core-script-run

***
Initiates a new endpoint script execution action using a script from the script library and returns the results.

#### Base Command

`core-script-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| script_uid | Unique identifier of the script. Can be retrieved by running the core-get-scripts command. | Required | 
| parameters | Dictionary containing the parameter name as key and its value for this execution as the value. For example, {"param1":"param1_value","param2":"param2_value"}. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| polling_interval_in_seconds | Interval in seconds between each poll. Default is 10. | Optional | 
| polling_timeout_in_seconds | Polling timeout in seconds. Default is 600. | Optional | 
| action_id | The action ID for polling use. | Optional | 
| hide_polling_output | Whether to hide the polling result (automatically filled by polling). | Optional | 
| is_core | Is the command being called from a core pack. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.ScriptResult.action_id | Number | ID of the action initiated. | 
| Core.ScriptResult.results.retrieved_files | Number | Number of successfully retrieved files. | 
| Core.ScriptResult.results.endpoint_ip_address | String | Endpoint IP address. | 
| Core.ScriptResult.results.endpoint_name | String | Name of successfully retrieved files. | 
| Core.ScriptResult.results.failed_files | Number | Number of files failed to be retrieved. | 
| Core.ScriptResult.results.endpoint_status | String | Endpoint status. | 
| Core.ScriptResult.results.domain | String | Domain to which the endpoint belongs. | 
| Core.ScriptResult.results.endpoint_id | String | Endpoint ID. | 
| Core.ScriptResult.results.execution_status | String | Execution status of this endpoint. | 
| Core.ScriptResult.results.return_value | String | Value returned by the script in case the type is not a dictionary. | 
| Core.ScriptResult.results.standard_output | String | The STDOUT and the STDERR logged by the script during the execution. | 
| Core.ScriptResult.results.retention_date | Date | Timestamp in which the retrieved files will be deleted from the server. | 

#### Command example

```!core-script-run endpoint_ids=111 script_uid=111 polling_timeout_in_seconds=1200 timeout=1200```

##### Context Example

```
{
    "Core.ScriptResult": [
        {
            "action_id": 1, 
            "results": [
                {
                    "retrieved_files" : 0,
                    "_return_value": [],
                    "standard_output": ""
                    "domain" : "222",
                    "endpoint_id" : "111",
                    "endpoint_ip_address" : ["1.1.1.1"],
                    "command" : "_return_value",
                    "retention_date" : NULL,
                    "command_output" : [],
                    "endpoint_name" : "test",
                    "failed_files" : 0,
                    "execution_status" : "COMPLETED_SUCCESSFULLY",
                    "endpoint_status" : "STATUS_010_CONNECTED"
                },
            ]
        }
    ],
    "Core.ScriptRun": [
        {
            "action_id": 1,
            "endpoints_count": 1,
            "status": 1
        }
    ]
}
```

##### Human Readable Output

>### Script Execution Results

>| _return_value| domain | endpoint_id| endpoint_ip_address| endpoint_name| endpoint_status| execution_status| failed_files| retention_date| retrieved_files| standard_output|
>|---|---|---|---|---|---|---|---|---|---|---|
>||222|111|1.1.1.1|test|STATUS_010_CONNECTED|COMPLETED_SUCCESSFULLY|0||0||


### core-terminate-process

***
Terminate a process by its instance ID. Available only for XSIAM 2.4 and above.

#### Base Command

`core-terminate-process`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The agent ID. | Required | 
| instance_id | The instance ID. | Required | 
| process_name | The process name. | Optional | 
| incident_id | The incident ID. | Optional | 
| action_id | The action ID. For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.TerminateProcess.action_id | String | The action ID. | 
| Core.GetActionStatus | Unknown | The action status command results. | 
| Core.GetActionStatus.endpoint_id | string | Endpoint ID. | 
| Core.GetActionStatus.status | string | The status of the specific endpoint ID. | 
| Core.GetActionStatus.action_id | number | The specified action ID. | 
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### core-terminate-causality

***
Terminate a process tree by its causality ID. Available only for XSIAM 2.4 and above.

##### Command Example

```!core-terminate-process agent_id=1 instance_id=1 process_name=process incident_id=2```

##### Context Example

```
{
    "Core.TerminateProcess": [
        {
            "action_id": "1",
        }
       
    ]
}
```

#### Base Command

`core-terminate-causality`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | The agent ID. | Required | 
| causality_id | The causality ID. | Required | 
| process_name | The process name. | Optional | 
| incident_id | The incident ID. | Optional | 
| action_id | The action ID. For polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.TerminateCausality.action_id | String | The action id. | 
| Core.GetActionStatus | Unknown | The action status command results. | 
| Core.GetActionStatus.endpoint_id | string | Endpoint ID. | 
| Core.GetActionStatus.status | string | The status of the specific endpoint ID. | 
| Core.GetActionStatus.action_id | number | The specified action ID. | 
| Core.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| Core.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| Core.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| Core.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| Core.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| Core.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

##### Command Example

```!core-terminate-causality agent_id=1 causality_id=1 process_name=process incident_id=2```

##### Context Example

```
{
    "Core.TerminateCausality": [
        {
            "action_id": "1",
        }
       
    ]
}
```

### core-get-asset-details

***
Get asset information.

#### Base Command

`core-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset unique identifier. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Core.CoreAsset | unknown | Asset additional information. | 
| Core.CoreAsset.xdm__asset__provider | unknown | The cloud provider or source responsible for the asset. | 
| Core.CoreAsset.xdm__asset__realm | unknown | The realm or logical grouping of the asset. | 
| Core.CoreAsset.xdm__asset__last_observed | unknown | The timestamp of when the asset was last observed, in ISO 8601 format. | 
| Core.CoreAsset.xdm__asset__type__id | unknown | The unique identifier for the asset type. | 
| Core.CoreAsset.xdm__asset__first_observed | unknown | The timestamp of when the asset was first observed, in ISO 8601 format. | 
| Core.CoreAsset.asset_hierarchy | unknown | The hierarchy or structure representing the asset. | 
| Core.CoreAsset.xdm__asset__type__category | unknown | The category type of the asset. | 
| Core.CoreAsset.xdm__cloud__region | unknown | The cloud region where the asset resides. | 
| Core.CoreAsset.xdm__asset__module_unstructured_fields | unknown | The unstructured fields or metadata associated with the asset module. | 
| Core.CoreAsset.xdm__asset__source | unknown | The originating source of the asset's information. | 
| Core.CoreAsset.xdm__asset__id | unknown | A unique identifier for the asset. | 
| Core.CoreAsset.xdm__asset__type__class | unknown | The classification or type class of the asset. | 
| Core.CoreAsset.xdm__asset__type__name | unknown | The specific name of the asset type. | 
| Core.CoreAsset.xdm__asset__strong_id | unknown | The strong or immutable identifier for the asset. | 
| Core.CoreAsset.xdm__asset__name | unknown | The name of the asset. | 
| Core.CoreAsset.xdm__asset__raw_fields | unknown | The raw fields or unprocessed data related to the asset. | 
| Core.CoreAsset.xdm__asset__normalized_fields | unknown | The normalized fields associated with the asset. | 
| Core.CoreAsset.all_sources | unknown | A list of all sources providing information about the asset. | 

##### Command Example

```!core-get-asset-details asset_id=123```

##### Context Example

```
{
    "Core.CoreAsset": [
        {
            "asset_hierarchy": ["123"],
            "xdm__asset__type__category": "Policy",
            "xdm__cloud__region": "Global",
            "xdm__asset__module_unstructured_fields": {},
            "xdm__asset__source": "XSIAM",
            "xdm__asset__id": "123",
            "xdm__asset__type__class": "Identity",
            "xdm__asset__normalized_fields": {},
            "xdm__asset__first_observed": 100000000,
            "xdm__asset__last_observed": 100000000,
            "xdm__asset__name": "Fake Name",
            "xdm__asset__type__name": "IAM",
            "xdm__asset__strong_id": "FAKE ID"
        }
    ]
}
```

##### Human Readable Output

>| asset_hierarchy | xdm__asset__type__category | xdm__cloud__region | xdm__asset__module_unstructured_fields | xdm__asset__source | xdm__asset__id | xdm__asset__type__class | xdm__asset__normalized_fields | xdm__asset__first_observed | xdm__asset__last_observed | xdm__asset__name |
xdm__asset__type__name | xdm__asset__strong_id |
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|123|Policy|Global||XSIAM|123|Identity||100000000|100000000|Fake Name|IAM|FAKE ID|

