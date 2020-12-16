The unified console for managing Sophos products
This integration was integrated and tested with version xx of sophos_central
## Configure sophos_central on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for sophos_central.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Sophos account ID | True |
| isFetch | Fetch incidents | False |
| fetch_severity | Fetch Severity | False |
| fetch_category | Fetch Category | False |
| max_fetch | Fetch Limit | False |
| fetch_time | First Fetch Time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sophos-central-alert-list
***
List alerts.


#### Base Command

`sophos-central-alert-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return. Default is "50". Maximum is "100". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.Alert.allowedActions | String | Actions that you can perform on these alerts. | 
| SophosCentral.Alert.category | String | Alert category. | 
| SophosCentral.Alert.description | String | Alert description. | 
| SophosCentral.Alert.groupKey | String | Alert group key. | 
| SophosCentral.Alert.id | String | The alert ID. | 
| SophosCentral.Alert.managedAgentId | String | The alert source ID. | 
| SophosCentral.Alert.managedAgentType | String | The source that triggered the Alert. | 
| SophosCentral.Alert.person | String | The ID of the referenced person object. | 
| SophosCentral.Alert.product | String | Product type. | 
| SophosCentral.Alert.raisedAt | Date | When the alert was triggered. | 
| SophosCentral.Alert.severity | String | Severity level for the alert. | 
| SophosCentral.Alert.tenantId | String | Tenant ID for the alert. | 
| SophosCentral.Alert.tenantName | String | Tenant name. | 
| SophosCentral.Alert.type | String | Alert type. | 


#### Command Example
```!sophos-central-alert-list limit=50```

#### Context Example
```json
{
    "SophosCentral": {
        "Alert": [
            {
                "allowedActions": [
                    "clearThreat"
                ],
                "category": "malware",
                "description": "Manual cleanup required: 'EICAR-AV-Test' at 'C:\\Users\\Lior\\Downloads\\eicarcom2.zip'",
                "groupKey": "MSxFdmVudDo6RW5kcG9pbnQ6OlRocmVhdDo6Q2xlYW51cEZhaWxlZCwxNixFSUNBUi1BVi1UZXN0",
                "id": "8e879165-81cb-4747-8608-1cc4e630a017",
                "managedAgentId": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
                "managedAgentType": "computer",
                "person": "5d407889-8659-46ab-86c5-4f227302df78",
                "product": "endpoint",
                "raisedAt": "2020-11-25T09:19:18.936Z",
                "severity": "high",
                "tenantId": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
                "tenantName": "Cortex XSOAR",
                "type": "Event::Endpoint::Threat::CleanupFailed"
            },
            {
                "allowedActions": [
                    "clearThreat"
                ],
                "category": "runtimeDetections",
                "description": "Malicious connection detected: 'C2/Generic-B' at 'C:\\Windows\\System32\\wscript.exe' (Technical Support reference: 277413403)",
                "groupKey": "MSxFdmVudDo6RW5kcG9pbnQ6OlRocmVhdDo6Q29tbWFuZEFuZENvbnRyb2xEZXRlY3RlZCwxNixDMiUyRkdlbmVyaWMtQg",
                "id": "9641ba6e-3254-4726-962d-b2bc11e04131",
                "managedAgentId": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
                "managedAgentType": "computer",
                "person": "5d407889-8659-46ab-86c5-4f227302df78",
                "product": "endpoint",
                "raisedAt": "2020-11-25T10:36:31.603Z",
                "severity": "high",
                "tenantId": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
                "tenantName": "Cortex XSOAR",
                "type": "Event::Endpoint::Threat::CommandAndControlDetected"
            },
            {
                "allowedActions": [
                    "acknowledge"
                ],
                "category": "updating",
                "description": "Thunderbox is out of date.",
                "groupKey": "MSxFdmVudDo6RW5kcG9pbnQ6Ok91dE9mRGF0ZSw1MTMs",
                "id": "ee527ca8-cb54-4e11-b59f-2197910176f3",
                "managedAgentId": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
                "managedAgentType": "computer",
                "person": "5d407889-8659-46ab-86c5-4f227302df78",
                "product": "endpoint",
                "raisedAt": "2020-11-25T10:42:09.083Z",
                "severity": "medium",
                "tenantId": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
                "tenantName": "Cortex XSOAR",
                "type": "Event::Endpoint::OutOfDate"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed Alerts:
>|id|description|severity|raisedAt|allowedActions|managedAgentId|category|type|
>|---|---|---|---|---|---|---|---|
>| 8e879165-81cb-4747-8608-1cc4e630a017 | Manual cleanup required: 'EICAR-AV-Test' at 'C:\Users\Lior\Downloads\eicarcom2.zip' | high | 2020-11-25T09:19:18.936Z | clearThreat | 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | malware | Event::Endpoint::Threat::CleanupFailed |
>| 9641ba6e-3254-4726-962d-b2bc11e04131 | Malicious connection detected: 'C2/Generic-B' at 'C:\Windows\System32\wscript.exe' (Technical Support reference: 277413403) | high | 2020-11-25T10:36:31.603Z | clearThreat | 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | runtimeDetections | Event::Endpoint::Threat::CommandAndControlDetected |
>| ee527ca8-cb54-4e11-b59f-2197910176f3 | Thunderbox is out of date. | medium | 2020-11-25T10:42:09.083Z | acknowledge | 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | updating | Event::Endpoint::OutOfDate |
>Results on this page: 3.Maximum number of results allowed in a page: 100

### sophos-central-alert-get
***
Get a single alert by ID.


#### Base Command

`sophos-central-alert-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.Alert.allowedActions | String | Actions that you can perform on these alerts. | 
| SophosCentral.Alert.category | String | Alert category. | 
| SophosCentral.Alert.description | String | Alert description. | 
| SophosCentral.Alert.groupKey | String | Alert group key. | 
| SophosCentral.Alert.id | String | The alert ID. | 
| SophosCentral.Alert.managedAgentId | String | The alert source ID. | 
| SophosCentral.Alert.managedAgentType | String | The source that triggered the alert. | 
| SophosCentral.Alert.person | String | The ID of the referenced person object. | 
| SophosCentral.Alert.product | String | Product type. | 
| SophosCentral.Alert.raisedAt | Date | When the alert was triggered. | 
| SophosCentral.Alert.severity | String | Severity level for the alert. | 
| SophosCentral.Alert.tenantId | String | Tenant ID for the alert. | 
| SophosCentral.Alert.tenantName | String | Tenant name. | 
| SophosCentral.Alert.type | String | Alert type. | 


#### Command Example
```!sophos-central-alert-get alert_id=8e879165-81cb-4747-8608-1cc4e630a017```

#### Context Example
```json
{
    "SophosCentral": {
        "Alert": {
            "allowedActions": [
                "clearThreat"
            ],
            "category": "malware",
            "description": "Manual cleanup required: 'EICAR-AV-Test' at 'C:\\Users\\Lior\\Downloads\\eicarcom2.zip'",
            "groupKey": "MSxFdmVudDo6RW5kcG9pbnQ6OlRocmVhdDo6Q2xlYW51cEZhaWxlZCwxNixFSUNBUi1BVi1UZXN0",
            "id": "8e879165-81cb-4747-8608-1cc4e630a017",
            "managedAgentId": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
            "managedAgentType": "computer",
            "person": "5d407889-8659-46ab-86c5-4f227302df78",
            "product": "endpoint",
            "raisedAt": "2020-11-25T09:19:18.936Z",
            "severity": "high",
            "tenantId": "11f104c5-cc4a-4a9f-bb9c-632c936dfb9f",
            "tenantName": "Cortex XSOAR",
            "type": "Event::Endpoint::Threat::CleanupFailed"
        }
    }
}
```

#### Human Readable Output

>### Found Alert:
>|id|description|severity|raisedAt|allowedActions|managedAgentId|category|type|
>|---|---|---|---|---|---|---|---|
>| 8e879165-81cb-4747-8608-1cc4e630a017 | Manual cleanup required: 'EICAR-AV-Test' at 'C:\Users\Lior\Downloads\eicarcom2.zip' | high | 2020-11-25T09:19:18.936Z | clearThreat | 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | malware | Event::Endpoint::Threat::CleanupFailed |


### sophos-central-alert-action
***
Take an action against alerts.


#### Base Command

`sophos-central-alert-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id |Comma-separated list of alert IDs. | Required | 
| action | Actions to perform on the alerts. Possible values are: "acknowledge", "cleanPua", "cleanVirus", "authPua", "clearThreat", "clearHmpa", "sendMsgPua", and "sendMsgThreat". | Required | 
| message | Message to send for the action. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.AlertAction.action | String | Actions that you can perform on the alert. | 
| SophosCentral.AlertAction.alertId | String | Alert ID. | 
| SophosCentral.AlertAction.completedAt | Date | Time when the action was completed. | 
| SophosCentral.AlertAction.id | String | Alert action ID. | 
| SophosCentral.AlertAction.requestedAt | Date | Time when the action was requested. | 
| SophosCentral.AlertAction.result | String | The result of the action. | 
| SophosCentral.AlertAction.startedAt | Date | Time when the action was started. | 
| SophosCentral.AlertAction.status | String | Status of an alert action. | 


#### Command Example
```!sophos-central-alert-action action=clearThreat alert_id=8e879165-81cb-4747-8608-1cc4e630a017 message=testmessage```

#### Context Example
```json
{
    "SophosCentral": {
        "AlertAction": {
            "action": "clearThreat",
            "alertId": "8e879165-81cb-4747-8608-1cc4e630a017",
            "completedAt": null,
            "id": "c75b1e4d-c62c-4b3a-8ca5-dea658a18c1b",
            "requestedAt": "2020-11-25T10:47:14.639Z",
            "result": "success",
            "startedAt": null,
            "status": "requested"
        }
    }
}
```

#### Human Readable Output

>### Alerts Acted Against:
>|id|action|alertId|result|requestedAt|status|
>|---|---|---|---|---|---|
>| c75b1e4d-c62c-4b3a-8ca5-dea658a18c1b | clearThreat | 8e879165-81cb-4747-8608-1cc4e630a017 | success | 2020-11-25T10:47:14.639Z | requested |


### sophos-central-alert-search
***
Get alerts matching request.


#### Base Command

`sophos-central-alert-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_key | Alert group key. | Optional | 
| start | Time on which or after the alerts were raised. Use ISO time format (YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| end | Time before which alerts were raised. Use ISO time format (YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| date_range | The date range in which to search from the current time instead of a start/end time in the format (`<number> <time unit>`, e.g., 12 hours, 7 days). date_range will overwrite the start and end arguments if defined. | Optional | 
| product | Alerts for a product(s). Possible values are: "other", "endpoint", "server", "mobile", "encryption", "emailGateway", "webGateway", "phishThreat", "wireless", "iaas", and "firewall". | Optional | 
| category | Alert category(s). | Optional | 
| severity | Alerts for a specific severity level(s). Possible values are: "high", "medium", and "low". | Optional | 
| ids | List of IDs. | Optional | 
| limit | The maximum number of items to return. Default is "50". Maximum is "100". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.Alert.allowedActions | String | Actions that you can perform on these alerts. | 
| SophosCentral.Alert.category | String | Alert category. | 
| SophosCentral.Alert.description | String | Alert description. | 
| SophosCentral.Alert.groupKey | String | Alert group key. | 
| SophosCentral.Alert.id | String | The alert ID. | 
| SophosCentral.Alert.managedAgentId | String | The alert source ID. | 
| SophosCentral.Alert.managedAgentType | String | The source that triggered the alert. | 
| SophosCentral.Alert.person | String | The ID of the referenced person object. | 
| SophosCentral.Alert.product | String | Product type. | 
| SophosCentral.Alert.raisedAt | Date | When the alert was triggered. | 
| SophosCentral.Alert.severity | String | Severity level for the alert. | 
| SophosCentral.Alert.tenantId | String | Tenant ID for the alert. | 
| SophosCentral.Alert.tenantName | String | Tenant name. | 
| SophosCentral.Alert.type | String | Alert type. | 


#### Command Example
```!sophos-central-alert-search category=general product=endpoint```

#### Context Example
```json
{
    "SophosCentral": {
        "Alert": null
    }
}
```

#### Human Readable Output

>### Found Alerts:
>**No entries.**
>Results on this page: 0.Maximum number of results allowed in a page: 100

### sophos-central-endpoint-list
***
List all endpoints for a tenant.


#### Base Command

`sophos-central-endpoint-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| health_status | Match endpoints that have any of the specified health statuses. Possible values are: "bad", "good", "suspicious", and "unknown". | Optional | 
| endpoint_type | Match endpoints that have any of the specified endpoint types. Possible values are: "computer", "server", and "securityVm". | Optional | 
| tamper_protection_enabled | Whether tamper protection is enabled. Possible values are: "true" and "false". | Optional | 
| lockdown_status | Match endpoints that have any of the specified lockdown statuses. Possible values are: "creatingWhitelist", "installing", "locked", "notInstalled", "registering", "starting", "stopping", "unavailable", "uninstalled", and "unlocked". | Optional | 
| last_seen_before | The datetime before which the endpoints were last seen (UTC). | Optional | 
| last_seen_after | The datetime on or after which the endpoints were last seen (UTC). | Optional | 
| ids | List of IDs. | Optional | 
| view | Type of view to be returned in the response. Possible values are: "basic", "summary", and "full". | Optional | 
| limit | The maximum number of items to return. Default is "50". Maximum is "100". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.Endpoint.assignedProductCodes | String | Code of a product assigned to the endpoint. | 
| SophosCentral.Endpoint.associatedPersonId | String | The unique ID for the person associated with the endpoint. | 
| SophosCentral.Endpoint.associatedPersonName | String | Name of the person associated with the endpoint. | 
| SophosCentral.Endpoint.associatedPersonViaLogin | String | The login of the person associated with the endpoint. | 
| SophosCentral.Endpoint.groupId | String | The unique ID for the endpoint group. | 
| SophosCentral.Endpoint.groupName | String | Endpoint group name. | 
| SophosCentral.Endpoint.hostname | String | The hostname of the endpoint. | 
| SophosCentral.Endpoint.id | String | The unique ID for the endpoint. | 
| SophosCentral.Endpoint.health | String | Health status of the endpoint. | 
| SophosCentral.Endpoint.ipv4Addresses | String | IPv4 address of the endpoint. | 
| SophosCentral.Endpoint.ipv6Addresses | String | IPv6 address of the endpoint. | 
| SophosCentral.Endpoint.macAddresses | String | MAC address of the endpoint. | 
| SophosCentral.Endpoint.osBuild | String | Operating system build. | 
| SophosCentral.Endpoint.osIsServer | Boolean | Whether the operating system is a server operating system. | 
| SophosCentral.Endpoint.osName | String | Operating system name as reported by the endpoint. | 
| SophosCentral.Endpoint.osPlatform | String | Operating system platform type. | 
| SophosCentral.Endpoint.tamperProtectionEnabled | Boolean | Whether tamper protection is enabled. | 
| SophosCentral.Endpoint.type | String | The endpoint type. | 
| SophosCentral.Endpoint.online | Boolean | Whether the endpoint is online. | 


#### Command Example
```!sophos-central-endpoint-list```

#### Context Example
```json
{
    "SophosCentral": {
        "Endpoint": [
            {
                "assignedProductCodes": [
                    "endpointProtection",
                    "coreAgent"
                ],
                "associatedPersonId": null,
                "associatedPersonName": null,
                "associatedPersonViaLogin": "THUNDERBOX\\Lior",
                "health": "bad",
                "hostname": "Thunderbox",
                "id": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
                "ipv4Addresses": [
                    "1.1.1.1"
                ],
                "ipv6Addresses": [
                    "fe80::9905:5b42:6605:5e93"
                ],
                "macAddresses": [
                    "00:00:00:B0:00:BA"
                ],
                "online": null,
                "osBuild": 18363,
                "osIsServer": false,
                "osName": "Windows 10 Pro",
                "osPlatform": "windows",
                "tamperProtectionEnabled": false,
                "type": "computer"
            },
            {
                "assignedProductCodes": [
                    "coreAgent",
                    "endpointProtection"
                ],
                "associatedPersonId": null,
                "associatedPersonName": null,
                "associatedPersonViaLogin": "WIN-CEAESQ7V08E\\Administrator",
                "health": "good",
                "hostname": "WIN-CEAESQ7V08E",
                "id": "a24b74a2-68e3-4fa5-8119-95744e0ab421",
                "ipv4Addresses": [
                    "1.1.1.1"
                ],
                "ipv6Addresses": [
                    "fe80::9905:5b42:6605:5e93"
                ],
                "macAddresses": [
                    "00:00:00:B0:00:BA"
                ],
                "online": null,
                "osBuild": 17763,
                "osIsServer": true,
                "osName": "Windows Server 2019 Standard Evaluation",
                "osPlatform": "windows",
                "tamperProtectionEnabled": false,
                "type": "server"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed Endpoints:
>|id|hostname|ipv4Addresses|ipv6Addresses|macAddresses|type|tamperProtectionEnabled|
>|---|---|---|---|---|---|---|
>| 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | Thunderbox | 1.1.1.1 | fe80::9905:5b42:6605:5e93 | 00:00:00:B0:00:BA | computer | false |
>| a24b74a2-68e3-4fa5-8119-95744e0ab421 | WIN-CEAESQ7V08E | 1.1.1.1 | fe80::9905:5b42:6605:5e93 | 00:00:00:B0:00:BA | server | false |
>Results on this page: 2.Maximum number of results allowed in a page: 500

### sophos-central-endpoint-scan
***
Scan endpoints of a tenant.


#### Base Command

`sophos-central-endpoint-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID(s). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.EndpointScan.id | String | Identifies a request to perform or configure the endpoint scan. | 
| SophosCentral.EndpointScan.requestedAt | Date | Time when the scan was requested. | 
| SophosCentral.EndpointScan.status | String | The status of an endpoint scan. | 


#### Command Example
```!sophos-central-endpoint-scan endpoint_id=6e9567ea-bb50-40c5-9f12-42eb308e4c9b```

#### Context Example
```json
{
    "SophosCentral": {
        "EndpointScan": {
            "id": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
            "requestedAt": "2020-11-25T10:47:20.343Z",
            "status": "requested"
        }
    }
}
```

#### Human Readable Output

>### Scanning Endpoints:
>|id|status|requestedAt|
>|---|---|---|
>| 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | requested | 2020-11-25T10:47:20.343Z |


### sophos-central-endpoint-tamper-get
***
Get tamper protection information for one or more endpoints. Potentially harmful because of the password.


#### Base Command

`sophos-central-endpoint-tamper-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID(s). | Required | 
| get_password | Whether to return the tamper protection password. Possible values are: "true" and "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.EndpointTamper.endpointId | String | ID of the endpoint in regards to the tamper settings. | 
| SophosCentral.EndpointTamper.enabled | String | Whether tamper protection should be turned on for the endpoint. | 
| SophosCentral.EndpointTamper.password | String | Current tamper protection password. | 


#### Command Example
```!sophos-central-endpoint-tamper-get endpoint_id=6e9567ea-bb50-40c5-9f12-42eb308e4c9b```

#### Context Example
```json
{
    "SophosCentral": {
        "EndpointTamper": {
            "enabled": false,
            "endpointId": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
            "password": null
        }
    }
}
```

#### Human Readable Output

>### Listed Endpoints Tamper Protection:
>|endpointId|enabled|
>|---|---|
>| 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | false |


### sophos-central-endpoint-tamper-update
***
Update tamper protection information for one or more endpoints. Potentially Harmful because of the password.


#### Base Command

`sophos-central-endpoint-tamper-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID(s). | Required | 
| enabled | Whether tamper protection should be turned on for the endpoint. Possible values are: "true" and "false". | Required | 
| get_password | Whether to return the tamper protection password. Possible values are: "true" and "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.EndpointTamper.endpointId | String | ID of the endpoint in regards to the tamper settings. | 
| SophosCentral.EndpointTamper.enabled | String | Whether tamper protection should be turned on for the endpoint.  | 
| SophosCentral.EndpointTamper.password | String | Current tamper protection password. | 


#### Command Example
```!sophos-central-endpoint-tamper-update enabled=true endpoint_id=6e9567ea-bb50-40c5-9f12-42eb308e4c9b```

#### Context Example
```json
{
    "SophosCentral": {
        "EndpointTamper": {
            "enabled": true,
            "endpointId": "6e9567ea-bb50-40c5-9f12-42eb308e4c9b",
            "password": null
        }
    }
}
```

#### Human Readable Output

>### Updated Endpoints Tamper Protection:
>|endpointId|enabled|
>|---|---|
>| 6e9567ea-bb50-40c5-9f12-42eb308e4c9b | true |


### sophos-central-allowed-item-list
***
List all allowed items.


#### Base Command

`sophos-central-allowed-item-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | he maximum size of the page requested. Default is "50". Maximum is "100". | Optional | 
| page | Page number to return. Default is "1". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.AllowedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.AllowedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.AllowedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.AllowedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.AllowedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.AllowedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.AllowedItem.fileName | String | The file name. | 
| SophosCentral.AllowedItem.path | String | The path for the application. | 
| SophosCentral.AllowedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.AllowedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.AllowedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.AllowedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.AllowedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.AllowedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-allowed-item-list page=1 page_size=50```

#### Context Example
```json
{
    "SophosCentral": {
        "AllowedItem": [
            {
                "certificateSigner": null,
                "comment": "hello world1",
                "createdAt": "2020-11-25T10:19:37.608Z",
                "fileName": null,
                "id": "b2148cc0-6ee8-440e-9c4b-cd5486b36c3c",
                "path": "/root/helloaworld/1/1",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-25T10:19:37.608Z"
            },
            {
                "certificateSigner": "notme",
                "comment": "fordemo",
                "createdAt": "2020-11-10T12:10:49.384Z",
                "fileName": null,
                "id": "718e991d-a99f-4193-b263-4eeebcac46fe",
                "path": null,
                "sha256": null,
                "type": "certificateSigner",
                "updatedAt": "2020-11-10T12:10:49.384Z"
            },
            {
                "certificateSigner": null,
                "comment": "Test-Noam",
                "createdAt": "2020-11-08T14:00:18.574Z",
                "fileName": null,
                "id": "f047c584-949a-4a59-aebd-9999ce323c1d",
                "path": "c:\\test2.exe",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-08T14:00:18.574Z"
            },
            {
                "certificateSigner": null,
                "comment": "Test",
                "createdAt": "2020-11-08T10:44:39.279Z",
                "fileName": null,
                "id": "345b4588-b843-45b1-9319-e529ddd741e6",
                "path": "c:\\1.txt",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-08T10:58:14.622Z"
            },
            {
                "certificateSigner": "hello",
                "comment": "chaaned",
                "createdAt": "2020-11-03T10:14:25.914Z",
                "fileName": null,
                "id": "6a2e26fb-6eb4-42ff-8201-6f7051757595",
                "path": null,
                "sha256": null,
                "type": "certificateSigner",
                "updatedAt": "2020-11-03T10:15:32.819Z"
            },
            {
                "certificateSigner": null,
                "comment": "chaaned",
                "createdAt": "2020-11-03T09:13:04.380Z",
                "fileName": null,
                "id": "2f804138-9632-4500-a13f-33342868e434",
                "path": "root/hello/worldrsaard",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-03T10:15:08.159Z"
            },
            {
                "certificateSigner": null,
                "comment": "hello world1",
                "createdAt": "2020-11-01T13:26:03.890Z",
                "fileName": null,
                "id": "73e555e9-3eee-42e1-879e-65d5ba968236",
                "path": "/root/helloaworld/1",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-01T13:26:03.890Z"
            },
            {
                "certificateSigner": null,
                "comment": "hello world",
                "createdAt": "2020-11-01T11:50:02.567Z",
                "fileName": null,
                "id": "595b2e6d-36b3-45bd-b94f-99a98a0a53f7",
                "path": "/root/helloaworld",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-01T11:50:02.567Z"
            },
            {
                "certificateSigner": null,
                "comment": "helloworld",
                "createdAt": "2020-11-01T11:00:47.441Z",
                "fileName": null,
                "id": "3533f7be-5064-44b6-9579-e4d7fa542444",
                "path": "/root/what",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-11-01T11:00:47.441Z"
            },
            {
                "certificateSigner": null,
                "comment": "bad comment",
                "createdAt": "2020-11-01T10:48:49.312Z",
                "fileName": "zxdfzd",
                "id": "85465c57-e598-4c8b-9c08-093c6f5eb239",
                "path": "/root/hello/word",
                "sha256": "C6F4DB9B3191E6E693CE938BD74FAB37AEE71372C8B034F5040362D8C69E4DE5",
                "type": "path",
                "updatedAt": "2020-11-01T10:48:49.312Z"
            },
            {
                "certificateSigner": "xcvxcv",
                "comment": "bad comment",
                "createdAt": "2020-11-01T10:47:24.473Z",
                "fileName": "xzcvxz",
                "id": "cffaaae7-0b3a-4ec7-84a4-fee88d297abc",
                "path": "/root",
                "sha256": null,
                "type": "certificateSigner",
                "updatedAt": "2020-11-01T10:47:24.473Z"
            },
            {
                "certificateSigner": null,
                "comment": "changedcomment",
                "createdAt": "2020-10-29T13:31:40.963Z",
                "fileName": null,
                "id": "c598b3b5-c9d9-4ff2-af9b-4d656deaa4f7",
                "path": "/root/hello",
                "sha256": null,
                "type": "path",
                "updatedAt": "2020-10-29T13:32:41.421Z"
            },
            {
                "comment": "uh",
                "createdAt": "2020-10-28T13:57:53.235Z",
                "id": "41a56d0d-5272-4be4-92dc-1c2dd42c218a",
                "type": "path",
                "updatedAt": "2020-10-28T13:58:07.906Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed Allowed Items:
>|id|comment|fileName|sha256|path|certificateSigner|createdAt|type|updatedAt|
>|---|---|---|---|---|---|---|---|---|
>| b2148cc0-6ee8-440e-9c4b-cd5486b36c3c | hello world1 |  |  | /root/helloaworld/1/1 |  | 2020-11-25T10:19:37.608Z | path | 2020-11-25T10:19:37.608Z |
>| 718e991d-a99f-4193-b263-4eeebcac46fe | fordemo |  |  |  | notme | 2020-11-10T12:10:49.384Z | certificateSigner | 2020-11-10T12:10:49.384Z |
>| f047c584-949a-4a59-aebd-9999ce323c1d | Test-Noam |  |  | c:\test2.exe |  | 2020-11-08T14:00:18.574Z | path | 2020-11-08T14:00:18.574Z |
>| 345b4588-b843-45b1-9319-e529ddd741e6 | Test |  |  | c:\1.txt |  | 2020-11-08T10:44:39.279Z | path | 2020-11-08T10:58:14.622Z |
>| 6a2e26fb-6eb4-42ff-8201-6f7051757595 | chaaned |  |  |  | hello | 2020-11-03T10:14:25.914Z | certificateSigner | 2020-11-03T10:15:32.819Z |
>| 2f804138-9632-4500-a13f-33342868e434 | chaaned |  |  | root/hello/worldrsaard |  | 2020-11-03T09:13:04.380Z | path | 2020-11-03T10:15:08.159Z |
>| 73e555e9-3eee-42e1-879e-65d5ba968236 | hello world1 |  |  | /root/helloaworld/1 |  | 2020-11-01T13:26:03.890Z | path | 2020-11-01T13:26:03.890Z |
>| 595b2e6d-36b3-45bd-b94f-99a98a0a53f7 | hello world |  |  | /root/helloaworld |  | 2020-11-01T11:50:02.567Z | path | 2020-11-01T11:50:02.567Z |
>| 3533f7be-5064-44b6-9579-e4d7fa542444 | helloworld |  |  | /root/what |  | 2020-11-01T11:00:47.441Z | path | 2020-11-01T11:00:47.441Z |
>| 85465c57-e598-4c8b-9c08-093c6f5eb239 | bad comment | zxdfzd | C6F4DB9B3191E6E693CE938BD74FAB37AEE71372C8B034F5040362D8C69E4DE5 | /root/hello/word |  | 2020-11-01T10:48:49.312Z | path | 2020-11-01T10:48:49.312Z |
>| cffaaae7-0b3a-4ec7-84a4-fee88d297abc | bad comment | xzcvxz |  | /root | xcvxcv | 2020-11-01T10:47:24.473Z | certificateSigner | 2020-11-01T10:47:24.473Z |
>| c598b3b5-c9d9-4ff2-af9b-4d656deaa4f7 | changedcomment |  |  | /root/hello |  | 2020-10-29T13:31:40.963Z | path | 2020-10-29T13:32:41.421Z |
>| 41a56d0d-5272-4be4-92dc-1c2dd42c218a | uh |  |  |  |  | 2020-10-28T13:57:53.235Z | path | 2020-10-28T13:58:07.906Z |
>Current page: 1.
>Results on this page: 13.
>Maximum number of results allowed in a page: 100.

### sophos-central-allowed-item-get
***
Get a single allowed item by ID.


#### Base Command

`sophos-central-allowed-item-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| allowed_item_id | The ID of the allowed item. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.AllowedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.AllowedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.AllowedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.AllowedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.AllowedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.AllowedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.AllowedItem.fileName | String | The file name. | 
| SophosCentral.AllowedItem.path | String | The path for the application. | 
| SophosCentral.AllowedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.AllowedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.AllowedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.AllowedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.AllowedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.AllowedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-allowed-item-get allowed_item_id=b2148cc0-6ee8-440e-9c4b-cd5486b36c3c```

#### Context Example
```json
{
    "SophosCentral": {
        "AllowedItem": {
            "certificateSigner": null,
            "comment": "hello world1",
            "createdAt": "2020-11-25T10:19:37.608Z",
            "fileName": null,
            "id": "b2148cc0-6ee8-440e-9c4b-cd5486b36c3c",
            "path": "/root/helloaworld/1/1",
            "sha256": null,
            "type": "path",
            "updatedAt": "2020-11-25T10:19:37.608Z"
        }
    }
}
```

#### Human Readable Output

>### Found Allowed Item:
>|id|comment|path|createdAt|type|updatedAt|
>|---|---|---|---|---|---|
>| b2148cc0-6ee8-440e-9c4b-cd5486b36c3c | hello world1 | /root/helloaworld/1/1 | 2020-11-25T10:19:37.608Z | path | 2020-11-25T10:19:37.608Z |


### sophos-central-allowed-item-add
***
Add a new allowed item.


#### Base Command

`sophos-central-allowed-item-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Comment indicating why the item should be allowed. | Required | 
| certificate_signer | The value saved for the certificateSigner. | Optional | 
| file_name | The file name. | Optional | 
| path | The path for the application. | Optional | 
| sha256 | The SHA256 value for the application. | Optional | 
| item_type | The property by which an item is allowed. Note that the specified item type requires the matching argument filled. For example, the item type "path" requires the path argument. Possible values are: "path", "sha256", and "certificateSigner". | Required | 
| origin_endpoint_id | The endpoint where the item to be allowed was last seen. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.AllowedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.AllowedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.AllowedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.AllowedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.AllowedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.AllowedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.AllowedItem.fileName | String | The file name. | 
| SophosCentral.AllowedItem.path | String | The path for the application. | 
| SophosCentral.AllowedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.AllowedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.AllowedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.AllowedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.AllowedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.AllowedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-allowed-item-add comment="hello world1" item_type=path path=/root/helloaworld/12```

#### Context Example
```json
{
    "SophosCentral": {
        "AllowedItem": {
            "certificateSigner": null,
            "comment": "hello world1",
            "createdAt": "2020-11-25T10:47:32.082Z",
            "fileName": null,
            "id": "c68f1abc-986d-43eb-b050-d9113959207a",
            "path": "/root/helloaworld/12",
            "sha256": null,
            "type": "path",
            "updatedAt": "2020-11-25T10:47:32.082Z"
        }
    }
}
```

#### Human Readable Output

>### Added Allowed Item:
>|id|comment|path|createdAt|type|updatedAt|
>|---|---|---|---|---|---|
>| c68f1abc-986d-43eb-b050-d9113959207a | hello world1 | /root/helloaworld/12 | 2020-11-25T10:47:32.082Z | path | 2020-11-25T10:47:32.082Z |


### sophos-central-allowed-item-update
***
Update an existing allowed item.


#### Base Command

`sophos-central-allowed-item-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| allowed_item_id | The allowed item ID. | Required | 
| comment | Comment indicating why the item should be allowed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.AllowedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.AllowedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.AllowedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.AllowedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.AllowedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.AllowedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.AllowedItem.fileName | String | The file name. | 
| SophosCentral.AllowedItem.path | String | The path for the application. | 
| SophosCentral.AllowedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.AllowedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.AllowedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.AllowedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.AllowedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.AllowedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-allowed-item-update allowed_item_id=b2148cc0-6ee8-440e-9c4b-cd5486b36c3c comment=changedcomment```

#### Context Example
```json
{
    "SophosCentral": {
        "AllowedItem": {
            "certificateSigner": null,
            "comment": "changedcomment",
            "createdAt": "2020-11-25T10:19:37.608Z",
            "fileName": null,
            "id": "b2148cc0-6ee8-440e-9c4b-cd5486b36c3c",
            "path": "/root/helloaworld/1/1",
            "sha256": null,
            "type": "path",
            "updatedAt": "2020-11-25T10:47:39.104Z"
        }
    }
}
```

#### Human Readable Output

>### Updated Allowed Item:
>|id|comment|path|createdAt|type|updatedAt|
>|---|---|---|---|---|---|
>| b2148cc0-6ee8-440e-9c4b-cd5486b36c3c | changedcomment | /root/helloaworld/1/1 | 2020-11-25T10:19:37.608Z | path | 2020-11-25T10:47:39.104Z |


### sophos-central-allowed-item-delete
***
Delete an existing allowed item.


#### Base Command

`sophos-central-allowed-item-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| allowed_item_id | The allowed item ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.DeletedAllowedItem.deletedItemId | String | The ID of the deleted item. | 


#### Command Example
```!sophos-central-allowed-item-delete allowed_item_id=b2148cc0-6ee8-440e-9c4b-cd5486b36c3c```

#### Context Example
```json
{
    "SophosCentral": {
        "DeletedAllowedItem": {
            "deletedItemId": "b2148cc0-6ee8-440e-9c4b-cd5486b36c3c"
        }
    }
}
```

#### Human Readable Output

>Success deleting allowed item: b2148cc0-6ee8-440e-9c4b-cd5486b36c3c

### sophos-central-blocked-item-list
***
Get all blocked items.


#### Base Command

`sophos-central-blocked-item-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size |  The maximum size of the page requested. Default is "50". Maximum is "100". | Optional | 
| page | Page number to return. Default is "1" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.BlockedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.BlockedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.BlockedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.BlockedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.BlockedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.BlockedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.BlockedItem.fileName | String | The file name. | 
| SophosCentral.BlockedItem.path | String | The path for the application. | 
| SophosCentral.BlockedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.BlockedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.BlockedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.BlockedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.BlockedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.BlockedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-blocked-item-list page=1 page_size=50```

#### Context Example
```json
{
    "SophosCentral": {
        "BlockedItem": [
            {
                "certificateSigner": null,
                "comment": "hello 2world",
                "createdAt": "2020-11-25T10:19:54.523Z",
                "fileName": null,
                "id": "9b44086b-95bd-43e5-b84b-82b91725f02b",
                "path": null,
                "sha256": "c7f4db9b3191e6e693ce938bd74fab37aee71372c8a034f50b0a62d8c69e4de1",
                "type": "sha256",
                "updatedAt": null
            },
            {
                "certificateSigner": null,
                "comment": "hello world",
                "createdAt": "2020-11-01T12:55:47.476Z",
                "fileName": null,
                "id": "fd0f08db-966b-4979-8cbb-876a2bbd29c9",
                "path": null,
                "sha256": "c6f4db9b3191e6e693ce938bd74fab37aee71372c8a034f5040362d8c69e4de4",
                "type": "sha256",
                "updatedAt": null
            },
            {
                "certificateSigner": null,
                "comment": "It's just a test",
                "createdAt": "2020-11-01T10:22:55.556Z",
                "fileName": null,
                "id": "f15f7b34-e1c4-4fd2-bbcb-f5c64e6e9994",
                "path": null,
                "sha256": "b424f1cb9f1c11a4251ebbf28cd032e6267673e899dce7ac6b7deccde49917af",
                "type": "sha256",
                "updatedAt": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed Blocked Items:
>|id|comment|sha256|createdAt|type|
>|---|---|---|---|---|
>| 9b44086b-95bd-43e5-b84b-82b91725f02b | hello 2world | c7f4db9b3191e6e693ce938bd74fab37aee71372c8a034f50b0a62d8c69e4de1 | 2020-11-25T10:19:54.523Z | sha256 |
>| fd0f08db-966b-4979-8cbb-876a2bbd29c9 | hello world | c6f4db9b3191e6e693ce938bd74fab37aee71372c8a034f5040362d8c69e4de4 | 2020-11-01T12:55:47.476Z | sha256 |
>| f15f7b34-e1c4-4fd2-bbcb-f5c64e6e9994 | It's just a test | b424f1cb9f1c11a4251ebbf28cd032e6267673e899dce7ac6b7deccde49917af | 2020-11-01T10:22:55.556Z | sha256 |
>Current page: 1.
>Results on this page: 3.
>Maximum number of results allowed in a page: 100.

### sophos-central-blocked-item-get
***
Get a single blocked item by ID.


#### Base Command

`sophos-central-blocked-item-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| blocked_item_id | The blocked item ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.BlockedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.BlockedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.BlockedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.BlockedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.BlockedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.BlockedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.BlockedItem.fileName | String | The file name. | 
| SophosCentral.BlockedItem.path | String | The path for the application. | 
| SophosCentral.BlockedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.BlockedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.BlockedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.BlockedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.BlockedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.BlockedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-blocked-item-get blocked_item_id=9b44086b-95bd-43e5-b84b-82b91725f02b```

#### Context Example
```json
{
    "SophosCentral": {
        "BlockedItem": {
            "certificateSigner": null,
            "comment": "hello 2world",
            "createdAt": "2020-11-25T10:19:54.523Z",
            "fileName": null,
            "id": "9b44086b-95bd-43e5-b84b-82b91725f02b",
            "path": null,
            "sha256": "c7f4db9b3191e6e693ce938bd74fab37aee71372c8a034f50b0a62d8c69e4de1",
            "type": "sha256",
            "updatedAt": null
        }
    }
}
```

#### Human Readable Output

>### Found Blocked Item:
>|id|comment|sha256|createdAt|type|
>|---|---|---|---|---|
>| 9b44086b-95bd-43e5-b84b-82b91725f02b | hello 2world | c7f4db9b3191e6e693ce938bd74fab37aee71372c8a034f50b0a62d8c69e4de1 | 2020-11-25T10:19:54.523Z | sha256 |


### sophos-central-blocked-item-add
***
Add a new blocked item.


#### Base Command

`sophos-central-blocked-item-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Comment indicating why the item should be blocked. | Required | 
| certificate_signer | The value saved for the certificateSigner. | Optional | 
| file_name | The file name. | Optional | 
| path | The path for the application. | Optional | 
| sha256 | The SHA256 value for the application. | Required | 
| item_type | The property by which an item is blocked. Possible value is sha256. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.BlockedItem.comment | String | A comment indicating why the item was allowed. | 
| SophosCentral.BlockedItem.createdAt | Date | Date and time \(UTC\) when the allowed application was created. | 
| SophosCentral.BlockedItem.createdById | String | The unique ID for the user who created the item. | 
| SophosCentral.BlockedItem.createdByName | String | The name for the user who created the item. | 
| SophosCentral.BlockedItem.id | String | The unique ID for the allowed application. | 
| SophosCentral.BlockedItem.certificateSigner | String | The value saved for the certificateSigner. | 
| SophosCentral.BlockedItem.fileName | String | The file name. | 
| SophosCentral.BlockedItem.path | String | The path for the application. | 
| SophosCentral.BlockedItem.sha256 | String | The SHA256 value for the application. | 
| SophosCentral.BlockedItem.type | String | The property by which an item is allowed. | 
| SophosCentral.BlockedItem.updatedAt | Date | Date and time \(UTC\) when the allowed application was updated. | 
| SophosCentral.BlockedItem.originEndpointId | String | ID of the originating endpoint. | 
| SophosCentral.BlockedItem.originPersonId | String | ID of the originating person. | 
| SophosCentral.BlockedItem.originPersonName | String | Name of the originating person. | 


#### Command Example
```!sophos-central-blocked-item-add comment="hello 2world" item_type=sha256 sha256=CAF4DB9B3191E6E693CE938BD74FAB37AEE71372C8A034F5040362D8C69E4DE4```

#### Context Example
```json
{
    "SophosCentral": {
        "BlockedItem": {
            "certificateSigner": null,
            "comment": "hello 2world",
            "createdAt": "2020-11-25T10:47:46.428Z",
            "fileName": null,
            "id": "9535be44-40f3-4704-94df-6afa1e563f9c",
            "path": null,
            "sha256": "caf4db9b3191e6e693ce938bd74fab37aee71372c8a034f5040362d8c69e4de4",
            "type": "sha256",
            "updatedAt": null
        }
    }
}
```

#### Human Readable Output

>### Added Blocked Item:
>|id|comment|sha256|createdAt|type|
>|---|---|---|---|---|
>| 9535be44-40f3-4704-94df-6afa1e563f9c | hello 2world | caf4db9b3191e6e693ce938bd74fab37aee71372c8a034f5040362d8c69e4de4 | 2020-11-25T10:47:46.428Z | sha256 |


### sophos-central-blocked-item-delete
***
Delete an existing blocked item.


#### Base Command

`sophos-central-blocked-item-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| blocked_item_id | The blocked item ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.DeletedBlockedItem.deletedItemId | String | The ID of the deleted item. | 


#### Command Example
```!sophos-central-blocked-item-delete blocked_item_id=9b44086b-95bd-43e5-b84b-82b91725f02b```

#### Context Example
```json
{
    "SophosCentral": {
        "DeletedBlockedItem": {
            "deletedItemId": "9b44086b-95bd-43e5-b84b-82b91725f02b"
        }
    }
}
```

#### Human Readable Output

>Success deleting blocked item: 9b44086b-95bd-43e5-b84b-82b91725f02b

### sophos-central-scan-exclusion-list
***
List all scan exclusions.


#### Base Command

`sophos-central-scan-exclusion-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_type | Scan exclusion type. Possible values are: "path", "posixPath", "virtualPath", "process", "web", "pua", "exploitMitigation", "amsi", "behavioral" | Optional | 
| page_size | The maximum size of the page requested. Default is "50". Maximum is "100". | Optional | 
| page | The page number to fetch. Default is "1" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ScanExclusion.comment | String | A comment indicating why the exclusion was updated. | 
| SophosCentral.ScanExclusion.description | String | The exclusion description added by the system. | 
| SophosCentral.ScanExclusion.id | String | The unique ID for the scanning exclusion setting. | 
| SophosCentral.ScanExclusion.scanMode | String | The scan mode. Default is "onDemandAndOnAccess" for exclusions of type path, posixPath, and virtualPath and "onAccess" for process, web, pua, amsi. Behavioral and Detected Exploits (exploitMitigation) type exclusions do not support a scan mode. | 
| SophosCentral.ScanExclusion.type | String | The scanning exclusion type. | 
| SophosCentral.ScanExclusion.value | String | The exclusion value. | 


#### Command Example
```!sophos-central-scan-exclusion-list```

#### Context Example
```json
{
    "SophosCentral": {
        "ScanExclusion": [
            {
                "comment": "Sophos temporary exclusion see KBA 133945",
                "description": "Sophos temporary exclusion see KBA 133945",
                "id": "369b0956-a7b6-44fc-b1cc-bd7b3279c663",
                "scanMode": "onDemandAndOnAccess",
                "type": "path",
                "value": "%programfiles(x86)%\\Sophos\\Sophos Anti-Virus\\"
            },
            {
                "comment": null,
                "description": null,
                "id": "6868151e-4eac-4d0a-8985-5db9bff9d6f2",
                "scanMode": "onDemandAndOnAccess",
                "type": "path",
                "value": "testpathhzh"
            },
            {
                "comment": "changed before demo",
                "description": null,
                "id": "16bac29f-17a4-4c3a-9370-8c5968c5ac7d",
                "scanMode": "onAccess",
                "type": "process",
                "value": "changedvirus.exe"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed Scan Exclusions:
>|id|value|type|description|comment|scanMode|
>|---|---|---|---|---|---|
>| 369b0956-a7b6-44fc-b1cc-bd7b3279c663 | %programfiles(x86)%\Sophos\Sophos Anti-Virus\ | path | Sophos temporary exclusion see KBA 133945 | Sophos temporary exclusion see KBA 133945 | onDemandAndOnAccess |
>| 6868151e-4eac-4d0a-8985-5db9bff9d6f2 | testpathhzh | path |  |  | onDemandAndOnAccess |
>| 16bac29f-17a4-4c3a-9370-8c5968c5ac7d | changedvirus.exe | process |  | changed before demo | onAccess |
>Current page: 1.
>Results on this page: 3.
>Maximum number of results allowed in a page: 100.

### sophos-central-scan-exclusion-get
***
Get a single scan exclusion by ID.


#### Base Command

`sophos-central-scan-exclusion-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_id | The exclusion ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ScanExclusion.comment | String | A comment indicating why the exclusion was updated. | 
| SophosCentral.ScanExclusion.description | String | The exclusion description added by the system. | 
| SophosCentral.ScanExclusion.id | String | The unique ID for the scanning exclusion setting. | 
| SophosCentral.ScanExclusion.scanMode | String | The scan mode. Default is "onDemandAndOnAccess" for exclusions of type path, posixPath, and virtualPath and "onAccess" for process, web, pua, amsi. Behavioral and Detected Exploits (exploitMitigation) type exclusions do not support a scan mode. | 
| SophosCentral.ScanExclusion.type | String | The scanning exclusion type. | 
| SophosCentral.ScanExclusion.value | String | The exclusion value. | 


#### Command Example
```!sophos-central-scan-exclusion-get exclusion_id=6868151e-4eac-4d0a-8985-5db9bff9d6f2```

#### Context Example
```json
{
    "SophosCentral": {
        "ScanExclusion": {
            "comment": null,
            "description": null,
            "id": "6868151e-4eac-4d0a-8985-5db9bff9d6f2",
            "scanMode": "onDemandAndOnAccess",
            "type": "path",
            "value": "testpathhzh"
        }
    }
}
```

#### Human Readable Output

>### Found Scan Exclusion:
>|id|value|type|scanMode|
>|---|---|---|---|
>| 6868151e-4eac-4d0a-8985-5db9bff9d6f2 | testpathhzh | path | onDemandAndOnAccess |


### sophos-central-scan-exclusion-add
***
Add a new scan exclusion.


#### Base Command

`sophos-central-scan-exclusion-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | A comment indicating why the exclusion was created. | Optional | 
| scan_mode | The scan mode. Possible values are: "onDemand", "onAccess", and "onDemandAndOnAccess". Default is "onDemandAndOnAccess" for exclusions of type path, posixPath and virtualPath, "onAccess" for process, web, pua, amsi. Behavioral and Detected Exploits (exploitMitigation) type exclusions do not support a scan mode. | Optional | 
| exclusion_type | The scanning exclusion type. Possible values are: "path", "posixPath", "virtualPath", "process", "web", "pua", "exploitMitigation", "amsi", "behavioral". | Required | 
| value | The exclusion value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ScanExclusion.comment | String | A comment indicating why the exclusion was updated. | 
| SophosCentral.ScanExclusion.description | String | The exclusion description added by the system. | 
| SophosCentral.ScanExclusion.id | String | The unique ID for the scanning exclusion setting. | 
| SophosCentral.ScanExclusion.scanMode | String | The scan mode. Default is "onDemandAndOnAccess" for exclusions of type path, posixPath, and virtualPath and "onAccess" for process, web, pua, amsi. Behavioral and Detected Exploits (exploitMitigation) type exclusions do not support a scan mode. | 
| SophosCentral.ScanExclusion.type | String | The scanning exclusion type. | 
| SophosCentral.ScanExclusion.value | String | The exclusion value. | 


#### Command Example
```!sophos-central-scan-exclusion-add exclusion_type=path value=avsdfasdfaa```

#### Context Example
```json
{
    "SophosCentral": {
        "ScanExclusion": {
            "comment": null,
            "description": null,
            "id": "be7b05bf-368b-4621-8131-0776486e1c7b",
            "scanMode": "onDemandAndOnAccess",
            "type": "path",
            "value": "avsdfasdfaa"
        }
    }
}
```

#### Human Readable Output

>### Added Scan Exclusion:
>|id|value|type|scanMode|
>|---|---|---|---|
>| be7b05bf-368b-4621-8131-0776486e1c7b | avsdfasdfaa | path | onDemandAndOnAccess |


### sophos-central-scan-exclusion-update
***
Update an existing scan exclusion.


#### Base Command

`sophos-central-scan-exclusion-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | A comment indicating why the exclusion was created. | Optional | 
| scan_mode | The default value of scan mode is "onDemandAndOnAccess" for exclusions of type path, posixPath and virtualPath, "onAccess" for process, web, pua, amsi. Behavioral and Detected Exploits (exploitMitigation) type exclusions do not support a scan mode. | Optional | 
| exclusion_id | The exclusion ID. | Required | 
| value | The exclusion value. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ScanExclusion.comment | String | A comment indicating why the exclusion was updated. | 
| SophosCentral.ScanExclusion.description | String | The exclusion description added by the system. | 
| SophosCentral.ScanExclusion.id | String | The unique ID for the scanning exclusion setting. | 
| SophosCentral.ScanExclusion.scanMode | String | The scan mode. Default is "onDemandAndOnAccess" for exclusions of type path, posixPath, and virtualPath and "onAccess" for process, web, pua, amsi. Behavioral and Detected Exploits (exploitMitigation) type exclusions do not support a scan mode. | 
| SophosCentral.ScanExclusion.type | String | The scanning exclusion type. | 
| SophosCentral.ScanExclusion.value | String | The exclusion value. | 


#### Command Example
```!sophos-central-scan-exclusion-update exclusion_id=6868151e-4eac-4d0a-8985-5db9bff9d6f2```

#### Context Example
```json
{
    "SophosCentral": {
        "ScanExclusion": {
            "comment": null,
            "description": null,
            "id": "6868151e-4eac-4d0a-8985-5db9bff9d6f2",
            "scanMode": "onDemandAndOnAccess",
            "type": "path",
            "value": "testpathhzh"
        }
    }
}
```

#### Human Readable Output

>### Updated Scan Exclusion:
>|id|value|type|scanMode|
>|---|---|---|---|
>| 6868151e-4eac-4d0a-8985-5db9bff9d6f2 | testpathhzh | path | onDemandAndOnAccess |


### sophos-central-scan-exclusion-delete
***
Delete an existing scan exclusion.


#### Base Command

`sophos-central-scan-exclusion-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_id | The exclusion ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ScanExclusion.deletedExclusionId | String | The ID of the deleted exclusion. | 


#### Command Example
```!sophos-central-scan-exclusion-delete exclusion_id=6868151e-4eac-4d0a-8985-5db9bff9d6f2```

#### Context Example
```json
{
    "SophosCentral": {
        "DeletedScanExclusion": {
            "deletedExclusionId": "6868151e-4eac-4d0a-8985-5db9bff9d6f2"
        }
    }
}
```

#### Human Readable Output

>Success deleting scan exclusion: 6868151e-4eac-4d0a-8985-5db9bff9d6f2

### sophos-central-exploit-mitigation-list
***
List exploit mitigation settings for all protected applications.


#### Base Command

`sophos-central-exploit-mitigation-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_type | Exploit mitigation type. Possible values are: "detected" and "custom". | Optional | 
| page_size | The maximum size of the page requested. Default is "50". Maximum is "100". | Optional | 
| page | The page number to fetch. Default is "1". | Optional | 
| modified | Whether the Exploit Mitigation application has been customized. Possible values are: "true" and "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ExploitMitigation.category | String | The Exploit Mitigation category ID. | 
| SophosCentral.ExploitMitigation.name | String | The name given to this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.id | String | The ID of this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.paths | String | Paths included in this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.type | String | Whether the application was detected by the system or created by the user. | 


#### Command Example
```!sophos-central-exploit-mitigation-list```

#### Context Example
```json
{
    "SophosCentral": {
        "ExploitMitigation": [
            {
                "category": "other",
                "id": "ff9d87d0-c944-4ca5-9f76-c5efd1f89ded",
                "name": "3bf6f110-48d8-4114-95e3-a286ac50d722",
                "paths": [
                    "newnewnewnewnew"
                ],
                "type": "custom"
            },
            {
                "category": "browsers",
                "id": "06aefe81-7f83-4768-9cec-59d86d7ee133",
                "name": "Firefox",
                "paths": [
                    "$programfiles\\Mozilla Firefox\\firefox.exe"
                ],
                "type": "detected"
            },
            {
                "category": "browsers",
                "id": "b07c6cd2-ee1b-4cf4-8bd2-d3be05e461cf",
                "name": "Google Chrome",
                "paths": [
                    "$programfiles\\Google\\Chrome\\Application\\chrome.exe"
                ],
                "type": "detected"
            },
            {
                "category": "browsers",
                "id": "df7c2b63-dda4-4dc4-a12d-471cad799dbd",
                "name": "Internet Explorer",
                "paths": [
                    "$programfiles\\Internet Explorer\\iexplore.exe"
                ],
                "type": "detected"
            },
            {
                "category": "java",
                "id": "f5d5ba2d-d905-4e7b-b3b7-abb0f30f38b3",
                "name": "Java(TM) Platform SE binary",
                "paths": [
                    "$programfiles\\java\\jre1.8.0_271\\bin\\java.exe",
                    "$programfiles\\java\\jre1.8.0_271\\bin\\javaw.exe"
                ],
                "type": "detected"
            },
            {
                "category": "java",
                "id": "9ddf4b33-9f65-4422-898e-d5b5b450e8d8",
                "name": "Java(TM) Web Launcher",
                "paths": [
                    "$programfiles\\java\\jre1.8.0_271\\bin\\jp2launcher.exe"
                ],
                "type": "detected"
            },
            {
                "category": "java",
                "id": "b44f50e0-0332-444a-bdb0-cfec43fc2def",
                "name": "Java(TM) Web Start Launcher",
                "paths": [
                    "$programfiles\\java\\jre1.8.0_271\\bin\\javaws.exe"
                ],
                "type": "detected"
            },
            {
                "category": "other",
                "id": "a49af552-55e1-4dcd-a909-2310bcb8016f",
                "name": "KeePass",
                "paths": [
                    "$programfiles\\KeePass Password Safe 2\\KeePass.exe"
                ],
                "type": "detected"
            },
            {
                "category": "browsers",
                "id": "4178130a-0d4e-435d-b4bb-db594810a43a",
                "name": "Microsoft Edge",
                "paths": [
                    "$programfiles\\Microsoft\\Edge\\Application\\msedge.exe",
                    "$windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\MicrosoftEdge.exe"
                ],
                "type": "detected"
            },
            {
                "category": "office",
                "id": "ecbcd6a5-73d5-4060-b49f-b9de2e0587fc",
                "name": "Microsoft Excel",
                "paths": [
                    "$programfiles\\Microsoft Office\\Root\\Office16\\EXCEL.EXE"
                ],
                "type": "detected"
            },
            {
                "category": "office",
                "id": "7907eaf2-b4f0-40e3-9dd8-f7e452ffc7cf",
                "name": "Microsoft Outlook",
                "paths": [
                    "$programfiles\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"
                ],
                "type": "detected"
            },
            {
                "category": "office",
                "id": "6cadbe94-8e1c-4648-aa9e-b0b39e1cb1fb",
                "name": "Microsoft PowerPoint",
                "paths": [
                    "$programfiles\\Microsoft Office\\Root\\Office16\\POWERPNT.EXE"
                ],
                "type": "detected"
            },
            {
                "category": "office",
                "id": "417fd1be-fafa-4e3b-9a9b-589f7f20b72c",
                "name": "Microsoft Word",
                "paths": [
                    "$programfiles\\Microsoft Office\\Root\\Office16\\WINWORD.EXE"
                ],
                "type": "detected"
            },
            {
                "category": "browsers",
                "id": "68026667-ca17-473d-b797-ccebe2d9da87",
                "name": "MicrosoftEdgeCP.exe",
                "paths": [
                    "$windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\MicrosoftEdgeCP.exe"
                ],
                "type": "detected"
            },
            {
                "category": "java",
                "id": "01e26718-ddf3-4aad-b465-d7279b755c32",
                "name": "OpenJDK Platform binary",
                "paths": [
                    "$programfiles\\JetBrains\\PyCharm Community Edition 2020.1.2\\jbr\\bin\\java.exe"
                ],
                "type": "detected"
            },
            {
                "category": "office",
                "id": "9e378d93-4b62-4976-9a7c-5fdbbafa0b79",
                "name": "Pick an app",
                "paths": [
                    "$system32\\OpenWith.exe"
                ],
                "type": "detected"
            },
            {
                "category": "plugins",
                "id": "a0b96b54-6895-408c-ac68-f84ca81c248a",
                "name": "Plugin Container for Firefox",
                "paths": [
                    "$programfiles\\Mozilla Firefox\\plugin-container.exe"
                ],
                "type": "detected"
            },
            {
                "category": "other",
                "id": "3ac3fd9b-5b30-4e19-a9a4-303f553a4500",
                "name": "Skype for Business",
                "paths": [
                    "$programfiles\\Microsoft Office\\Root\\Office16\\lync.exe"
                ],
                "type": "detected"
            },
            {
                "category": "media",
                "id": "dbedc673-218a-4814-99f0-33642a65b1fd",
                "name": "Windows Media Player",
                "paths": [
                    "$programfiles\\Windows Media Player\\wmplayer.exe"
                ],
                "type": "detected"
            },
            {
                "category": "office",
                "id": "fd4f1dc8-4b4a-429e-ac27-bd757352f52c",
                "name": "Windows Wordpad Application",
                "paths": [
                    "$programfiles\\Windows NT\\Accessories\\WORDPAD.EXE"
                ],
                "type": "detected"
            },
            {
                "category": "other",
                "id": "563f4022-0a28-47f8-9bb6-7774aa7794e3",
                "name": "b2477368-4e58-4868-af90-554f948f4077",
                "paths": [
                    "wooba"
                ],
                "type": "custom"
            },
            {
                "category": "other",
                "id": "b19800cf-a98a-43dc-8efc-6de1f2a7321e",
                "name": "cde78059-3164-46c6-903f-c27b9103ef37",
                "paths": [
                    "testpathhhh"
                ],
                "type": "custom"
            },
            {
                "category": "other",
                "id": "91fff008-3609-46f3-9fc7-44713635b775",
                "name": "ce697cb7-06da-4e02-bcde-21f73b81d5ee",
                "paths": [
                    "changed\\path"
                ],
                "type": "custom"
            }
        ]
    }
}
```

#### Human Readable Output

>### Listed Exploit Mitigations:
>|id|name|type|category|paths|
>|---|---|---|---|---|
>| ff9d87d0-c944-4ca5-9f76-c5efd1f89ded | 3bf6f110-48d8-4114-95e3-a286ac50d722 | custom | other | newnewnewnewnew |
>| 06aefe81-7f83-4768-9cec-59d86d7ee133 | Firefox | detected | browsers | $programfiles\Mozilla Firefox\firefox.exe |
>| b07c6cd2-ee1b-4cf4-8bd2-d3be05e461cf | Google Chrome | detected | browsers | $programfiles\Google\Chrome\Application\chrome.exe |
>| df7c2b63-dda4-4dc4-a12d-471cad799dbd | Internet Explorer | detected | browsers | $programfiles\Internet Explorer\iexplore.exe |
>| f5d5ba2d-d905-4e7b-b3b7-abb0f30f38b3 | Java(TM) Platform SE binary | detected | java | $programfiles\java\jre1.8.0_271\bin\java.exe,<br/>$programfiles\java\jre1.8.0_271\bin\javaw.exe |
>| 9ddf4b33-9f65-4422-898e-d5b5b450e8d8 | Java(TM) Web Launcher | detected | java | $programfiles\java\jre1.8.0_271\bin\jp2launcher.exe |
>| b44f50e0-0332-444a-bdb0-cfec43fc2def | Java(TM) Web Start Launcher | detected | java | $programfiles\java\jre1.8.0_271\bin\javaws.exe |
>| a49af552-55e1-4dcd-a909-2310bcb8016f | KeePass | detected | other | $programfiles\KeePass Password Safe 2\KeePass.exe |
>| 4178130a-0d4e-435d-b4bb-db594810a43a | Microsoft Edge | detected | browsers | $programfiles\Microsoft\Edge\Application\msedge.exe,<br/>$windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe |
>| ecbcd6a5-73d5-4060-b49f-b9de2e0587fc | Microsoft Excel | detected | office | $programfiles\Microsoft Office\Root\Office16\EXCEL.EXE |
>| 7907eaf2-b4f0-40e3-9dd8-f7e452ffc7cf | Microsoft Outlook | detected | office | $programfiles\Microsoft Office\root\Office16\OUTLOOK.EXE |
>| 6cadbe94-8e1c-4648-aa9e-b0b39e1cb1fb | Microsoft PowerPoint | detected | office | $programfiles\Microsoft Office\Root\Office16\POWERPNT.EXE |
>| 417fd1be-fafa-4e3b-9a9b-589f7f20b72c | Microsoft Word | detected | office | $programfiles\Microsoft Office\Root\Office16\WINWORD.EXE |
>| 68026667-ca17-473d-b797-ccebe2d9da87 | MicrosoftEdgeCP.exe | detected | browsers | $windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe |
>| 01e26718-ddf3-4aad-b465-d7279b755c32 | OpenJDK Platform binary | detected | java | $programfiles\JetBrains\PyCharm Community Edition 2020.1.2\jbr\bin\java.exe |
>| 9e378d93-4b62-4976-9a7c-5fdbbafa0b79 | Pick an app | detected | office | $system32\OpenWith.exe |
>| a0b96b54-6895-408c-ac68-f84ca81c248a | Plugin Container for Firefox | detected | plugins | $programfiles\Mozilla Firefox\plugin-container.exe |
>| 3ac3fd9b-5b30-4e19-a9a4-303f553a4500 | Skype for Business | detected | other | $programfiles\Microsoft Office\Root\Office16\lync.exe |
>| dbedc673-218a-4814-99f0-33642a65b1fd | Windows Media Player | detected | media | $programfiles\Windows Media Player\wmplayer.exe |
>| fd4f1dc8-4b4a-429e-ac27-bd757352f52c | Windows Wordpad Application | detected | office | $programfiles\Windows NT\Accessories\WORDPAD.EXE |
>| 563f4022-0a28-47f8-9bb6-7774aa7794e3 | b2477368-4e58-4868-af90-554f948f4077 | custom | other | wooba |
>| b19800cf-a98a-43dc-8efc-6de1f2a7321e | cde78059-3164-46c6-903f-c27b9103ef37 | custom | other | testpathhhh |
>| 91fff008-3609-46f3-9fc7-44713635b775 | ce697cb7-06da-4e02-bcde-21f73b81d5ee | custom | other | changed\path |
>Current page: 1.
>Results on this page: 23.
>Maximum number of results allowed in a page: 100.

### sophos-central-exploit-mitigation-get
***
Get exploit mitigation settings for a single application.


#### Base Command

`sophos-central-exploit-mitigation-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_id | The Exploit Mitigation application ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ExploitMitigation.cateory | String | The Exploit Mitigation category ID. | 
| SophosCentral.ExploitMitigation.name | String | The name given to this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.id | String | The ID of this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.paths | String | Paths included in this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.type | String | Whether the application was detected by the system or created by the user. | 


#### Command Example
```!sophos-central-exploit-mitigation-get mitigation_id=ff9d87d0-c944-4ca5-9f76-c5efd1f89ded```

#### Context Example
```json
{
    "SophosCentral": {
        "ExploitMitigation": {
            "category": "other",
            "id": "ff9d87d0-c944-4ca5-9f76-c5efd1f89ded",
            "name": "3bf6f110-48d8-4114-95e3-a286ac50d722",
            "paths": [
                "newnewnewnewnew"
            ],
            "type": "custom"
        }
    }
}
```

#### Human Readable Output

>### Found Exploit Mitigation:
>|id|name|type|category|paths|
>|---|---|---|---|---|
>| ff9d87d0-c944-4ca5-9f76-c5efd1f89ded | 3bf6f110-48d8-4114-95e3-a286ac50d722 | custom | other | newnewnewnewnew |


### sophos-central-exploit-mitigation-add
***
Exclude a set of file paths from exploit mitigation.


#### Base Command

`sophos-central-exploit-mitigation-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | An absolute path to an application file to exclude. You may use HitmanPro.Alert expansion variables (e.g., $desktop, $programfiles). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ExploitMitigation.cateory | String | The Exploit Mitigation category ID. | 
| SophosCentral.ExploitMitigation.name | String | The name given to this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.id | String | The ID of this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.paths | String | Paths included in this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.type | String | Whether the application was detected by the system or created by the user. | 


#### Command Example
```!sophos-central-exploit-mitigation-add path=testestesteset```

#### Context Example
```json
{
    "SophosCentral": {
        "ExploitMitigation": {
            "category": "other",
            "id": "755ec991-c04f-498f-ab8e-20ef1a187b52",
            "name": "d082226b-0c17-4959-a3ed-a6957f39c9bc",
            "paths": [
                "testestesteset"
            ],
            "type": "custom"
        }
    }
}
```

#### Human Readable Output

>### Added Exploit Mitigation:
>|id|name|type|category|paths|
>|---|---|---|---|---|
>| 755ec991-c04f-498f-ab8e-20ef1a187b52 | d082226b-0c17-4959-a3ed-a6957f39c9bc | custom | other | testestesteset |


### sophos-central-exploit-mitigation-update
***
Update exploit mitigation settings for an application.


#### Base Command

`sophos-central-exploit-mitigation-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_id | The Exploit Mitigation application ID. | Required | 
| path | An absolute path to an application file to exclude. You may use HitmanPro.Alert expansion variables (e.g., $desktop, $programfiles). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ExploitMitigation.cateory | String | The Exploit Mitigation category ID. | 
| SophosCentral.ExploitMitigation.name | String | The name given to this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.id | String | The ID of this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.paths | String | Paths included in this Exploit Mitigation Application. | 
| SophosCentral.ExploitMitigation.type | String | Whether the application was detected by the system or created by the user. | 


#### Command Example
```!sophos-central-exploit-mitigation-update mitigation_id=ff9d87d0-c944-4ca5-9f76-c5efd1f89ded path=changed```

#### Context Example
```json
{
    "SophosCentral": {
        "ExploitMitigation": {
            "category": "other",
            "id": "ff9d87d0-c944-4ca5-9f76-c5efd1f89ded",
            "name": "3bf6f110-48d8-4114-95e3-a286ac50d722",
            "paths": [
                "changed"
            ],
            "type": "custom"
        }
    }
}
```

#### Human Readable Output

>### Updated Exploit Mitigation:
>|id|name|type|category|paths|
>|---|---|---|---|---|
>| ff9d87d0-c944-4ca5-9f76-c5efd1f89ded | 3bf6f110-48d8-4114-95e3-a286ac50d722 | custom | other | changed |


### sophos-central-exploit-mitigation-delete
***
Delete a custom (user-defined) exploit mitigation application by ID.


#### Base Command

`sophos-central-exploit-mitigation-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_id | The Exploit Mitigation application ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.ExploitMitigation.deletedMitigationId | String | The ID of the deleted mitigation. | 


#### Command Example
```!sophos-central-exploit-mitigation-delete mitigation_id=ff9d87d0-c944-4ca5-9f76-c5efd1f89ded```

#### Context Example
```json
{
    "SophosCentral": {
        "DeletedExploitMitigation": {
            "deletedMitigationId": "ff9d87d0-c944-4ca5-9f76-c5efd1f89ded"
        }
    }
}
```

#### Human Readable Output

>Success deleting exploit mitigation: ff9d87d0-c944-4ca5-9f76-c5efd1f89ded

### sophos-central-detected-exploit-list
***
List all detected exploits.


#### Base Command

`sophos-central-detected-exploit-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The maximum size of the page requested. Default is "50". Maximum is "100". | Optional | 
| page | The page number to fetch. Default is "1". | Optional | 
| thumbprint_not_in | Filter out detected exploits with these thumbprints. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.DetectedExploit.count | Number | The number of times the same exploit has been detected, potentially across multiple endpoints. | 
| SophosCentral.DetectedExploit.description | String | The English description of the exploit detected event. | 
| SophosCentral.DetectedExploit.id | String | The ID of this Exploit Mitigation Application. | 
| SophosCentral.DetectedExploit.firstSeenAt | Date | When the exploit was first seen. | 
| SophosCentral.DetectedExploit.lastSeenAt | Date | When the exploit was last seen. | 
| SophosCentral.DetectedExploit.lastEndpointHostname | String | The endpoint hostname. | 
| SophosCentral.DetectedExploit.lastEndpointId | String | The unique endpoint ID. | 
| SophosCentral.DetectedExploit.lastUserName | String | Person's name. | 
| SophosCentral.DetectedExploit.lastUserId | String | The unique ID for the user. | 
| SophosCentral.DetectedExploit.thumbprint | String | Matches \[0-9a-zA-Z\]\{64\}. | 


#### Command Example
```!sophos-central-detected-exploit-list```

#### Context Example
```json
{
    "SophosCentral": {
        "DetectedExploit": null
    }
}
```

#### Human Readable Output

>### Listed Detected Exploits:
>**No entries.**
>Current page: 1.
>Results on this page: 0.
>Maximum number of results allowed in a page: 100.

### sophos-central-detected-exploit-get
***
Get a single detected exploit.


#### Base Command

`sophos-central-detected-exploit-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detected_exploit_id | The ID of a previously detected exploit. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SophosCentral.DetectedExploit.count | Number | The number of times the same exploit has been detected, potentially across multiple endpoints. | 
| SophosCentral.DetectedExploit.description | String | The English description of the exploit detected event. | 
| SophosCentral.DetectedExploit.id | String | The ID of this Exploit Mitigation application. | 
| SophosCentral.DetectedExploit.firstSeenAt | Date | When the exploit was first seen. | 
| SophosCentral.DetectedExploit.lastSeenAt | Date | When the exploit was last seen. | 
| SophosCentral.DetectedExploit.lastEndpointHostname | String | The endpoint hostname. | 
| SophosCentral.DetectedExploit.lastEndpointId | String | The unique endpoint ID. | 
| SophosCentral.DetectedExploit.lastUserName | String | Person's name. | 
| SophosCentral.DetectedExploit.lastUserId | String | The unique ID for the user. | 
| SophosCentral.DetectedExploit.thumbprint | String | Matches \[0-9a-zA-Z\]\{64\}. | 


#### Command Example
``` ```

#### Human Readable Output


