Trend Micro Apex central automation to manage agents and User-Defined Suspicious Objects

This integration was integrated and tested with version 2019 of Trend Micro Apex Central
## Configure Trend Micro Apex on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Apex.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://vxsuz5.manage.trendmicro.com\) | True |
| application_id | Application ID | True |
| token | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trendmicro-apex-udso-list
***
Retrieve a list of User-Defined Suspicious Objects from the Apex Central server.


#### Base Command

`trendmicro-apex-udso-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The suspicious object type to query | Optional | 
| content_filter | Filters the list to suspicious objects that match the specified string | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.UDSO.type | String | Indicator type of the UDSO object, for example: ip, file, file_sha1, url, domain. | 
| TrendMicroApex.UDSO.content | String | Indicator content of the UDSO object. | 
| TrendMicroApex.UDSO.notes | String | Indicator notes of the UDSO object. | 
| TrendMicroApex.UDSO.scan_action | String | Scan action of the UDSO object, for example: log, block, quarantine. | 
| TrendMicroApex.UDSO.expiration_utc_date | Date | Expiration date of the UDSO object in UTC. | 


#### Command Example
```!trendmicro-apex-udso-list```

#### Context Example
```
{
    "TrendMicroApex": {
        "UDSO": [
            {
                "content": "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3",
                "expiration_utc_date": null,
                "notes": "Documentation",
                "scan_action": "log",
                "type": "file"
            },
            {
                "content": "8.8.8.8",
                "expiration_utc_date": null,
                "notes": "Documentation",
                "scan_action": "log",
                "type": "ip"
            }
        ]
    }
}
```

#### Human Readable Output

>### Apex UDSO List
>|content|expiration_utc_date|notes|scan_action|type|
>|---|---|---|---|---|
>| A94A8FE5CCB19BA61C4C0873D391E987982FBBD3 |  | Documentation | log | file |
>| 8.8.8.8 |  | Documentation | log | ip |


### trendmicro-apex-udso-add
***
Add suspicious file SHA-1, IP address, domain, or URL objects to the User-Defined Suspicious Object list.


#### Base Command

`trendmicro-apex-udso-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The suspicious object type | Required | 
| content | The suspicious object content for the specified type, for example 8.8.8.8 (for type "file", provide the binary content of the suspicious file as a base64 string) | Required | 
| scan_action | The scan action to perform on the suspicious object (The "quarantine" scan action is only available for file type objects) | Required | 
| notes | Description of the object. | Optional | 
| expiration | The UTC expiration date and time of the suspicious object, for example: 2020-01-25T09:00:00Z | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trendmicro-apex-udso-add type="ip" content="8.8.8.8" scan_action="log" notes="Documentation"```

#### Context Example
```
{}
```

#### Human Readable Output

>### UDSO "8.8.8.8" of type "ip" was added successfully with scan action "log"

### trendmicro-apex-udso-delete
***
Delete suspicious file SHA-1, IP address, domain, or URL objects from the User-Defined Suspicious Object list.


#### Base Command

`trendmicro-apex-udso-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The suspicious object type | Required | 
| content | The suspicious object content for the specified type | Required | 
| notes | Description of the object (maximum length: 256 characters). | Optional | 
| scan_action | The scan action to perform on the suspicious object. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trendmicro-apex-udso-delete type=ip content=8.8.8.8```

#### Context Example
```
{}
```

#### Human Readable Output

>### UDSO "8.8.8.8" of type "ip" was deleted successfully

### trendmicro-apex-isolate
***
Isolate an agent from the network


#### Base Command

`trendmicro-apex-isolate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| multi_match | Whether to allow multiple matches or not. If this parameter is set to "false", and the provided parameters match multiple agents, the action will be unsuccessful. | Optional | 
| entity_id | The GUID of the managed product agent | Optional | 
| ip_address | The IP address of the managed product agent | Optional | 
| mac_address | The MAC address of the managed product agent | Optional | 
| host_name | The endpoint name of the managed product agent | Optional | 
| product | The Trend Micro product on the server instance | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trendmicro-apex-isolate multi_match="true" ip_address="8.8.8.8"```

#### Context Example
```
{}
```

#### Human Readable Output

>### No agents were affected.

### trendmicro-apex-restore
***
Restore an isolated agent connection to the network.


#### Base Command

`trendmicro-apex-restore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| multi_match | Whether to allow multiple matches or not. If this argument is set to "false", and the provided parameters match multiple agents, the action will be unsuccessful. | Optional | 
| entity_id | The GUID of the managed product agent | Optional | 
| ip_address | The IP address of the managed product agent | Optional | 
| mac_address | The MAC address of the managed product agent | Optional | 
| host_name | The endpoint name of the managed product agent | Optional | 
| product | The Trend Micro product on the server instance | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trendmicro-apex-restore multi_match="true" ip_address="8.8.8.8"```

#### Context Example
```
{}
```

#### Human Readable Output

>### No agents were affected.

### trendmicro-apex-list-logs
***
Retrieves a maximum of 1000 logs of detection types from the server. The `Pattern Update Status` and `Engine Update Status` log types returns all logs (no maximum) from the specified "since_time". In some cases the command might return alerts that were created before the specified time. This is a known issue with the API.


#### Base Command

`trendmicro-apex-list-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_token | The log ID of the first record to query. Note: For Pattern Update Status and Engine Update Status logs, the value of page_token must be "0". | Optional | 
| since_time | The date/time of the first record to query, in one of the following formats:  '2020-06-21T08:00:00Z', 'Jun 21 2020 08:00:00 GMT+00:00'. In some cases the command might return logs that were created before the specified time. This is a known issue with the API. | Optional | 
| log_type | The type of log data to retrieve. | Required | 
| limit | The number of items to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.Log.LogVersion | Number | The version of the log. | 
| TrendMicroApex.Log.EventName | String | The name of the event. | 
| TrendMicroApex.Log.EventID | String | The event ID. | 
| TrendMicroApex.Log.ApplianceVersion | Number | The version of the appliance. | 
| TrendMicroApex.Log.ApplianceProduct | String | The product name. | 
| TrendMicroApex.Log.ApplianceVendor | String | The vendor name. | 


#### Command Example
```!trendmicro-apex-list-logs log_type="Web Violation" limit=2 since_time="Jun 21 2020 07:56:09 GMT+00:00"```

#### Context Example
```
{
    "TrendMicroApex": {
        "Log": [
            {
                "ApplianceProduct": "Apex Central",
                "ApplianceVendor": "Trend Micro",
                "ApplianceVersion": "2019",
                "CreationTime": "Jun 21 2020 07:56:09 GMT+00:00",
                "EventID": "WB:36",
                "EventName": "36",
                "LogVersion": "0",
                "SLF_PolicyName": "Internal User Policy",
                "SLF_SeverityLevel": "100 ",
                "Severity": "3",
                "Web_Reputation_Rating": "49",
                "act": "2",
                "app": "5",
                "cat": "36",
                "cnt": "1",
                "deviceDirection": "2",
                "deviceExternalId": "1",
                "deviceFacility": "Apex One",
                "deviceProcessName": "C:\\\\Program Files (x86)\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
                "dpt": "80",
                "duser": "TRENDMICROAPEX-\\\\admin",
                "dvchost": "CU-PRO1-8254-2",
                "request": "http://www.eicar.org/download/eicar.com.txt",
                "shost": "TRENDMICROAPEX-",
                "src": "10.128.0.11"
            },
            {
                "ApplianceProduct": "Apex Central",
                "ApplianceVendor": "Trend Micro",
                "ApplianceVersion": "2019",
                "CreationTime": "Jun 21 2020 07:56:28 GMT+00:00",
                "EventID": "WB:36",
                "EventName": "36",
                "LogVersion": "0",
                "SLF_PolicyName": "Internal User Policy",
                "SLF_SeverityLevel": "100 ",
                "Severity": "3",
                "Web_Reputation_Rating": "49",
                "act": "2",
                "app": "5",
                "cat": "36",
                "cnt": "1",
                "deviceDirection": "2",
                "deviceExternalId": "2",
                "deviceFacility": "Apex One",
                "deviceProcessName": "C:\\\\Program Files (x86)\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
                "dpt": "80",
                "duser": "TRENDMICROAPEX-\\\\admin",
                "dvchost": "CU-PRO1-8254-2",
                "request": "http://www.eicar.org/download/eicar.com",
                "shost": "TRENDMICROAPEX-",
                "src": "10.128.0.11"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trend Micro Apex - Web Violation Logs
>|EventName|EventID|CreationTime|LogVersion|ApplianceVersion|ApplianceProduct|ApplianceVendor|
>|---|---|---|---|---|---|---|
>| 36 | WB:36 | Jun 21 2020 07:56:09 GMT+00:00 | 0 | 2019 | Apex Central | Trend Micro |
>| 36 | WB:36 | Jun 21 2020 07:56:28 GMT+00:00 | 0 | 2019 | Apex Central | Trend Micro |


### trendmicro-apex-udso-file-add
***
Adds the uploaded file information to the User-Defined Suspicious Objects list. If the file already exists, it will be updated with the new arguments.


#### Base Command

`trendmicro-apex-udso-file-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_scan_action | The scan action to perform. Can be 'Log', 'Block' or 'Quarantine'. Default is 'Log'.  | Required | 
| note | Additional information. | Optional | 
| entry_id | The entry ID of the file to upload. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!trendmicro-apex-udso-file-add entry_id=10378@f6e9c46f-e2e9-446f-8cd9-909bd5f72dbf file_scan_action=Log note="Documentation"```

#### Context Example
```
{}
```

#### Human Readable Output

>### The file "test" was added to the UDSO list successfully

### trendmicro-apex-managed-servers-list
***
Retrieves a list of managed product servers reporting to Apex Central.


#### Base Command

`trendmicro-apex-managed-servers-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | The GUID of the managed product server. | Optional | 
| ip_address | The IP address of the endpoint. | Optional | 
| mac_address | The MAC address of the endpoint. | Optional | 
| host_name | The name of the endpoint. | Optional | 
| product | The Trend Micro product name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.Server.entity_id | String | The GUID of the managed product server. | 
| TrendMicroApex.Server.product | String | The Trend Micro product on the server instance. | 
| TrendMicroApex.Server.ad_domain | String | The Active Directory domain that the server belongs to \(if applicable\). | 
| TrendMicroApex.Server.ip_address_list | String | The IP address list on the server. | 
| TrendMicroApex.Server.host_name | String | The hostname of the server. | 
| TrendMicroApex.Server.capabilities | String | The API actions that can be performed on the server. | 


#### Command Example
```!trendmicro-apex-managed-servers-list```

#### Context Example
```
{
    "TrendMicroApex": {
        "Server": [
            {
                "ad_domain": "",
                "capabilities": [],
                "entity_id": "E9DF20C5-F060-4BC5-8A4B-5452163A1C77",
                "host_name": "cu-pro1-8254-2",
                "ip_address_list": [
                    "8.8.8.8"
                ],
                "product": "SLF_PRODUCT_PLS_TMSM"
            },
            {
                "ad_domain": "",
                "capabilities": [
                    "cmd_deploy_update_sources"
                ],
                "entity_id": "B220EB61-6240-44B4-9B94-4AC3F22E6A62",
                "host_name": "CU-PRO1-8254-2",
                "ip_address_list": [
                    "8.8.8.8"
                ],
                "product": "SLF_PRODUCT_OFFICESCAN_CE"
            },
            {
                "ad_domain": "",
                "capabilities": [],
                "entity_id": "DA010000-0000-0004-6B00-FFFFFFFFFFFF",
                "host_name": "",
                "ip_address_list": [
                    ""
                ],
                "product": "SLF_PRODUCT_HEADLESS_DSM"
            }
        ]
    }
}
```

#### Human Readable Output

>### Trend Micro Apex Servers List
>|Entity Id|Product|Host Name|Ip Address List|Capabilities|
>|---|---|---|---|---|
>| E9DF20C5-F060-4BC5-8A4B-5452163A1C77 | SLF_PRODUCT_PLS_TMSM | cu-pro1-8254-2 | 8.8.8.8 |  |
>| B220EB61-6240-44B4-9B94-4AC3F22E6A62 | SLF_PRODUCT_OFFICESCAN_CE | CU-PRO1-8254-2 | 8.8.8.8 | cmd_deploy_update_sources |
>| DA010000-0000-0004-6B00-FFFFFFFFFFFF | SLF_PRODUCT_HEADLESS_DSM |  |  |  |


### trendmicro-apex-security-agents-list
***
Retrieves a list of Security Agents.


#### Base Command

`trendmicro-apex-security-agents-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | The GUID of the Security Agent. | Optional | 
| ip_address | The IP address of the endpoint. | Optional | 
| mac_address | The MAC address of the endpoint. | Optional | 
| host_name | The name of the endpoint. | Optional | 
| product | The Trend Micro product name. | Optional | 
| managing_server_id | The GUID of the product server that manages the Security Agent. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.Agent.entity_id | String | The GUID of the Security Agent. | 
| TrendMicroApex.Agent.product | String | The Trend Micro product name. | 
| TrendMicroApex.Agent.managing_server_id | String | The GUID of the product server that manages the Security Agent. | 
| TrendMicroApex.Agent.ad_domain | String | The Active Directory domain that the agent belongs to \(if applicable\). | 
| TrendMicroApex.Agent.folder_path | String | The folder path of the agent in the machine. | 
| TrendMicroApex.Agent.ip_address_list | String | The IP address list on the server. | 
| TrendMicroApex.Agent.mac_address_list | String | The MAC address of the endpoint. | 
| TrendMicroApex.Agent.host_name | String | The name of the endpoint. | 
| TrendMicroApex.Agent.isolation_status | String | The isolation status of the agent. | 
| TrendMicroApex.Agent.capabilities | String | Lists the API actions that can be performed on the agent. | 


#### Command Example
```!trendmicro-apex-security-agents-list```

#### Context Example
```
{
    "TrendMicroApex": {
        "Agent": {
            "ad_domain": "",
            "capabilities": [
                "cmd_restore_isolated_agent",
                "cmd_isolate_agent",
                "cmd_relocate_agent",
                "cmd_uninstall_agent"
            ],
            "entity_id": "b59e624c-2cf0-4180-83d7-e08abbf9ad54",
            "folder_path": "Workgroup",
            "host_name": "TRENDMICROAPEX-",
            "ip_address_list": [
                "10.128.0.11"
            ],
            "isolation_status": "normal",
            "mac_address_list": "42-01-0A-80-00-0B",
            "managing_server_id": "B220EB61-6240-44B4-9B94-4AC3F22E6A62",
            "product": "SLF_PRODUCT_OFFICESCAN_CE"
        }
    }
}
```

#### Human Readable Output

>### Trend Micro Apex Agents List
>|Capabilities|Entity Id|Folder Path|Host Name|Ip Address List|Isolation Status|Mac Address List|Managing Server Id|Product|
>|---|---|---|---|---|---|---|---|---|
>| cmd_restore_isolated_agent,<br/>cmd_isolate_agent,<br/>cmd_relocate_agent,<br/>cmd_uninstall_agent | b59e624c-2cf0-4180-83d7-e08abbf9ad54 | Workgroup | TRENDMICROAPEX- | 8.8.8.8 | normal | 42-01-0A-80-00-0B | B220EB61-6240-44B4-9B94-4AC3F22E6A62 | SLF_PRODUCT_OFFICESCAN_CE |


### trendmicro-apex-endpoint-sensors-list
***
Retrieves a list of Security Agents with the Endpoint Sensor feature enabled.


#### Base Command

`trendmicro-apex-endpoint-sensors-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of records to retrieve. Default is 50. | Optional | 
| offset | The page from which to start retrieving records. Default is 0. | Optional | 
| filter_by_endpoint_name | Filter the agents by endpoint name (partial string match). | Optional | 
| filter_by_endpoint_type | Filter the agents by endpoint type. Can be "Desktop" or "Server". | Optional | 
| filter_by_ip_address | Filter the agents by endpoint IP address range represented by comma separated ranges list. Example: "Starting_IP_Address,Ending_IP_Address" | Optional | 
| filter_by_operating_system | Filter the agents by operating system. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.EndpointSensorSecurityAgent.agentGuid | String | The GUID of the agent. | 
| TrendMicroApex.EndpointSensorSecurityAgent.serverGuid | String | The GUID of the server that manages the agent. | 
| TrendMicroApex.EndpointSensorSecurityAgent.machineName | String | The hostname of the endpoint. | 
| TrendMicroApex.EndpointSensorSecurityAgent.isImportant | Boolean | Whether the agent is tagged as important. | 
| TrendMicroApex.EndpointSensorSecurityAgent.isOnline | Boolean | Whether the agent is online. | 
| TrendMicroApex.EndpointSensorSecurityAgent.ip | String | The IP address of the agent. | 
| TrendMicroApex.EndpointSensorSecurityAgent.machineGuid | String | The GUID of the endpoint. | 
| TrendMicroApex.EndpointSensorSecurityAgent.machineType | String | The endpoint type. | 
| TrendMicroApex.EndpointSensorSecurityAgent.machineLabels | Number | The machine labels. | 
| TrendMicroApex.EndpointSensorSecurityAgent.machineOS | String | The operating system of the endpoint. | 
| TrendMicroApex.EndpointSensorSecurityAgent.isolateStatus | String | The isolation status of the agent. | 
| TrendMicroApex.EndpointSensorSecurityAgent.isEnable | Boolean | Whether the agent is enabled. | 
| TrendMicroApex.EndpointSensorSecurityAgent.userName | String | The user name of the agent. | 
| TrendMicroApex.EndpointSensorSecurityAgent.userGuid | String | The GUID of the user. | 
| TrendMicroApex.EndpointSensorSecurityAgent.productType | Number | The Trend Micro product type on the server instance. | 


#### Command Example
```!trendmicro-apex-endpoint-sensors-list```

#### Context Example
```
{
    "TrendMicroApex": {
        "EndpointSensorSecurityAgent": {
            "agentGuid": "b59e624c-2cf0-4180-83d7-e08abbf9ad54",
            "ip": "8.8.8.8",
            "isEnable": true,
            "isImportant": false,
            "isOnline": true,
            "isolateStatus": 0,
            "machineGuid": "4C80331A-E39E-4584-A1B7-5237B3F0F239",
            "machineLabels": null,
            "machineName": "TRENDMICROAPEX-",
            "machineOS": "Windows Server 2019",
            "machineType": "Server",
            "productType": 15,
            "serverGuid": "B220EB61-6240-44B4-9B94-4AC3F22E6A62",
            "userGuid": "DC15EA904-03CC-E3A2-9CC0-BA57D814772",
            "userName": "TRENDMICROAPEX-\\admin"
        }
    }
}
```

#### Human Readable Output

>### Trend Micro Apex Security Agents with Endpoint Sensor enabled
>|agentGuid|ip|isEnable|isImportant|isOnline|isolateStatus|machineGuid|machineName|machineOS|machineType|productType|serverGuid|userGuid|userName|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| b59e624c-2cf0-4180-83d7-e08abbf9ad54 | 8.8.8.8 | true | false | true | 0 | 4C80331A-E39E-4584-A1B7-5237B3F0F239 | TRENDMICROAPEX- | Windows Server 2019 | Server | 15 | B220EB61-6240-44B4-9B94-4AC3F22E6A62 | DC15EA904-03CC-E3A2-9CC0-BA57D814772 | TRENDMICROAPEX-\admin |


### trendmicro-apex-historical-investigation-create
***
Creates a new historical investigation on all Security Agents with Endpoint Sensor enabled using the specified criteria, search operator, and match condition.


#### Base Command

`trendmicro-apex-historical-investigation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name_contains | Filter by file name (partial string match). | Optional | 
| file_name_is | Filter by file name (exact match). Supports comma-separated values. | Optional | 
| file_path_is | Filter by file path (exact match). Supports comma separated values. | Optional | 
| account_contains | Filter by account (partial string match). Supports comma separated values. | Optional | 
| account_is | Filter by account (exact match). Supports comma separated values. | Optional | 
| command_line_contains | Filter by command line (partial string match). Supports comma separated values. | Optional | 
| command_line_is | Filter by command line (exact match). Supports comma separated values. list. | Optional | 
| registry_key_contains | Filter by registry key (partial string match). Supports comma separated values. | Optional | 
| registry_key_is | Filter by registry key (exact match). Supports comma separated values. list. | Optional | 
| registry_name_contains | Filter by registry name (partial string match). Supports comma separated values. | Optional | 
| registry_name_is | Filter by registry name (exact match). Supports comma separated values. list. | Optional | 
| registry_data_contains | Filter by registry data (partial string match). Supports comma separated values. | Optional | 
| registry_data_is | Filter by registry data (exact match). Supports comma separated values. list. | Optional | 
| host_name_contains | Filter by host name (partial string match). Supports comma separated values. | Optional | 
| host_name_is | Filter by host name - (exact match). Supports comma separated values. | Optional | 
| file_path_contains | Filter by file path (partial string match). Supports comma separated values. | Optional | 
| operator | Operator used in the investigation. 'AND' - return endpoints that match all the criteria specified. 'OR' - return endpoints that match one of the specified criteria. | Required | 
| criteria_kvp | Criteria string to show in the auditing log. | Optional | 
| criteria_source | The source of criteria used to store the record in BIF. The default value is 0 (UNKNOWN). | Optional | 
| search_period | Scope of the search results. For example, if the value is Three months, perform assessment on data within the last 90 days only. Can be "Default", "All", "One month", "Three months", "Six months", or "Twelve months". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.HistoricalInvestigation.taskId | String | Task ID received from the investigation creation request. | 
| TrendMicroApex.HistoricalInvestigation.lastContentId | String | ID used to retrieve the next set of results. | 
| TrendMicroApex.HistoricalInvestigation.hasMore | Boolean | Whether the source has more results. | 
| TrendMicroApex.HistoricalInvestigation.serverName | String | The name of the server. | 
| TrendMicroApex.HistoricalInvestigation.serverGuid | String | The GUID of the server. | 


#### Command Example
```!trendmicro-apex-historical-investigation-create operator=OR file_name_is=notepad.exe criteria_kvp="File name: notepad.exe" criteria_source=56 search_period="Twelve months"```

#### Context Example
```
{
    "TrendMicroApex": {
        "HistoricalInvestigation": {
            "content": [],
            "hasMore": false,
            "lastContentId": "",
            "serverGuid": "B220EB61-6240-44B4-9B94-4AC3F22E6A62",
            "serverName": "Apex One as a Service",
            "taskId": "16545889-7708-48BF-BDFC-53A9E2A6942A"
        }
    }
}
```

#### Human Readable Output

>### The historical investigation was created successfully
>|taskId|serverName|serverGuid|
>|---|---|---|
>| 16545889-7708-48BF-BDFC-53A9E2A6942A | Apex One as a Service | B220EB61-6240-44B4-9B94-4AC3F22E6A62 |


### trendmicro-apex-investigation-result-list
***
Retrieves a list of all investigation results.


#### Base Command

`trendmicro-apex-investigation-result-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of records to retrieve. Default is 50. | Optional | 
| offset | The page from which to start retrieving records. Default is 0. | Optional | 
| scan_schedule_id | The scan schedule ID of the investigation to retrieve. | Optional | 
| filter_by_task_name | Filter the results by task name (partial string match). | Optional | 
| filter_by_creator_name | Filter the results by creator name (partial string match). | Optional | 
| filter_by_scan_type | Filter the results by the scan method type. Can be "Search Windows registry", "Memory scan using YARA", or "Disk scan using OpenIOC". | Optional | 
| filter_by_criteria_name | Filter the results by criteria name (partial string match). | Optional | 
| scan_type | The method used for the investigation. Supports comma-separated values. Possible values are: "Windows registry", "YARA rule file", "IOC rule file", and "Disk IOC rule file". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TrendMicroApex.InvestigationResult.scanSummaryId | Number | The ID of the investigation. | 
| TrendMicroApex.InvestigationResult.scanSummaryGuid | String | The GUID of the investigation. | 
| TrendMicroApex.InvestigationResult.status | Number | Status of the investigation. | 
| TrendMicroApex.InvestigationResult.statusForUI | Number | Status of the investigation shown in the web console. | 
| TrendMicroApex.InvestigationResult.scanType | String | Method used for the investigation. | 
| TrendMicroApex.InvestigationResult.submitTime | Date | Date and time when the investigation was submitted. | 
| TrendMicroApex.InvestigationResult.finishTime | Date | Date and time when the investigation was finished. | 
| TrendMicroApex.InvestigationResult.specificAgentType | Number | Indicates how targets were selected for the investigation. 0-All, 1-Specific. | 
| TrendMicroApex.InvestigationResult.progressInfo.safeCount | Number | Number of agents with "No match" status. | 
| TrendMicroApex.InvestigationResult.progressInfo.riskCount | Number | Number of agents with "Matched" status. | 
| TrendMicroApex.InvestigationResult.progressInfo.pendingCount | Number | Number of agents with "Pending" status. | 
| TrendMicroApex.InvestigationResult.progressInfo.timeoutCount | Number | Number of agents with "Timeout" status. | 
| TrendMicroApex.InvestigationResult.progressInfo.noneCount | Number | Number of agents with "None" status. | 
| TrendMicroApex.InvestigationResult.progressInfo.processingCount | Number | Number of agents with "Processing" status. | 
| TrendMicroApex.InvestigationResult.progressInfo.errorCount | Number | Number of agents with errors. | 
| TrendMicroApex.InvestigationResult.progressInfo.abortCount | Number | Number of aborted agents. | 
| TrendMicroApex.InvestigationResult.progressInfo.connectionFailCount | Number | Number of agents that fail to connect. | 
| TrendMicroApex.InvestigationResult.name | String | The name of the investigation. | 
| TrendMicroApex.InvestigationResult.agentCount | Number | The number of agents in the investigation. | 
| TrendMicroApex.InvestigationResult.matchedAgentCount | Number | The number of matched agents in the investigation. | 
| TrendMicroApex.InvestigationResult.serverGuidList | String | Trend Micro GUID list of the servers. | 
| TrendMicroApex.InvestigationResult.creator | String | The name of the user who created the investigation. | 
| TrendMicroApex.InvestigationResult.scanCriteriaEntity.criteriaId | Number | Unique identifier used by the server to store the criteria. | 
| TrendMicroApex.InvestigationResult.scanCriteriaEntity.criteriaName | String | The name of the criteria. | 
| TrendMicroApex.InvestigationResult.scanCriteriaEntity.criteriaContent | String | The the criteria used to perform "registry" investigation. | 
| TrendMicroApex.InvestigationResult.errorServers | String | Error response if server communication is unsuccessful. | 


#### Command Example
```!trendmicro-apex-investigation-result-list scan_status=All scan_type="YARA rule file"```

#### Context Example
```
{
    "TrendMicroApex": {
        "InvestigationResult": {
            "agentCount": 1,
            "creator": "Demisto-PANW",
            "errorServers": "[]",
            "finishTime": "1969-12-31T23:59:59+00:00",
            "matchedAgentCount": 0,
            "name": "this is a test",
            "progressInfo": {
                "abortCount": 0,
                "connectionFailCount": 0,
                "errorCount": 0,
                "noneCount": 0,
                "pendingCount": 0,
                "processingCount": 1,
                "riskCount": 0,
                "safeCount": 0,
                "timeoutCount": 0
            },
            "scanCriteriaEntity": {
                "criteriaContent": "",
                "criteriaId": 2,
                "criteriaName": "test.yar"
            },
            "scanSummaryGuid": "6161bf10-f073-4762-bd10-088b0f68ad1d",
            "scanSummaryId": 3,
            "scanType": "YARA rule file",
            "serverGuidList": [
                "B220EB61-6240-44B4-9B94-4AC3F22E6A62"
            ],
            "specificAgentType": 1,
            "status": "Running",
            "statusForUI": "Running",
            "submitTime": "2020-09-13T12:24:05+00:00"
        }
    }
}
```

#### Human Readable Output

>### Investigation result list:
>|name|scanSummaryId|scanSummaryGuid|submitTime|serverGuidList|creator|
>|---|---|---|---|---|---|
>| this is a test | 3 | 6161bf10-f073-4762-bd10-088b0f68ad1d | 2020-09-13T12:24:05+00:00 | B220EB61-6240-44B4-9B94-4AC3F22E6A62 | Demisto-PANW |

