Use FortiSIEM v2 to fetch and update incidents, search events and manage FortiSIEM watchlists.
This integration was integrated and tested with FortiSIEMV2 version 6.3.2.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

Changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-fortisiem-v2).

## Configure FortiSIEM v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | For example: https://192.168.1.1 | True |
| Username |  | True |
| Password |  | True |
| Maximum incidents per fetch. | Default is 20. Maximum is 200. Setting a value greater than 20 may harm performance, if used with 'Fetch With Events' mode. | False |
| First fetch timestamp (number, time unit. e.g., 12 hours, 7 days). |  | False |
| Filter incidents by status. |  | False |
| Fetch Mode | Fetch With Events mode is currently available only for FortiSiem version 6.6 and earlier. Note that using Fetch With Events mode may affect performance. | False |
| Maximum events to fetch per incident. | Default is 20. Maximum is 50. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortisiem-event-search
***
Initiate search process on events. Events are retrieved according to a constraint determined either by the query argument or by the filtering arguments. When using filtering arguments, an 'AND' operator is used between them. If the query argument is provided, it overrides the values in the filtering arguments.


#### Base Command

`fortisiem-event-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query for filtering the relevant events. For example, "eventId=9071234812319593968 AND eventType='type'". You can retrieve the attributes' names using the command's filtering arguments or using the event attributes returned in the context output. | Optional | 
| extended_data | Whether to extend the data. This affects the number of attributes returned. Possible values are: false, true. Default is true. | Optional | 
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it's ready. Possible values are: true, false. Default is false. | Optional | 
| search_id | The ID of the search query to retrieve its results. Intended for use by the polling process; does not need to be provided by the user. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| interval_in_seconds | How long to wait between command executions (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 10. | Optional | 
| timeout_in_seconds | The time in seconds until the polling sequence timeouts. Default is 60. | Optional | 
| from_time | Start of the time filter for events. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Required | 
| to_time | End of the time filter for events. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Required | 
| eventId | Event ID. Filtering argument. | Optional | 
| eventType | Event type. Filtering argument. | Optional | 
| reptDevIpAddr | Reporting IP address. Filtering argument. | Optional | 
| destAction | Destination action. Filtering argument. | Optional | 
| destDomain | Destination domain. Filtering argument. | Optional | 
| destIpAddr | Destination IP address. | Optional | 
| destUser | Destination user. Filtering argument. | Optional | 
| srcDomain | Source domain. Filtering argument. | Optional | 
| srcGeoCountry | Source geo country. Filtering argument. | Optional | 
| srcIpAddr | Source IP address. | Optional | 
| user | The involved user in the event. Filtering argument. | Optional | 
| destMACAddr | Destination MAC address. Filtering argument. | Optional | 
| srcMACAddr | Source MAC address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.EventsSearchInit.search_id | String | The ID of the search query that executed against the events. | 
#### Command Example
```!fortisiem-event-search query="eventType='ASA-Built-Conn'" from_time=2022-02-10 to_time=2022-02-14```

#### Context Example
```json
{
    "FortiSIEM": {
        "EventsSearchInit": {
            "search_id": "46367,1644934487413"
        }
    }
}
```

#### Human Readable Output

>### Successfully Initiated search query
>|Search Id|
>|---|
>| 46367,1644934487413 |


### fortisiem-incident-update
***
Update attributes of the specified incident. Only the provided attributes are overwritten.


#### Base Command

`fortisiem-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to update. | Required | 
| comment | Override incident's comment. | Optional | 
| status | Update incident status. Possible values are: Active, Auto Cleared, Manually Cleared, System Cleared. | Optional | 
| external_ticket_type | The type assigned to the incident ticket in an external ticket handling system. Possible values are: Low, Medium, High. | Optional | 
| external_ticket_id | The ID of the incident in an external ticket handling system. | Optional | 
| external_ticket_state | The state of the incident ticket in an external ticket handling system. Possible values are: New, Assigned, In Progress, Closed. | Optional | 
| external_assigned_user | The user that the external ticket is assigned to. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortisiem-incident-update incident_id=102 comment=demo-comment```

#### Human Readable Output

>The incident: 102 was successfully updated.

### fortisiem-cmdb-devices-list
***
List CMDB (Centralized Management Database) devices with short information for each device. If you provide one of the exclude arguments, their values are excluded from the provided include arguments. For example, to list all devices in the range 192.168.20.1-192.168.20.100, but exclude 192.168.20.20, 192.168.20.25, use include_ip_range='192.168.20.1-192.168.20.100' and exclude_ip='192.168.20.20, 192.168.20.25'. If no argument is provided, the command retrieves all devices.


#### Base Command

`fortisiem-cmdb-devices-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_ip | Comma-separated list of IP addresses to include. For example: 1.1.1.1,2.2.2.2. | Optional | 
| exclude_ip | Comma-separated list of IP addresses to exclude. For example: 1.1.1.1,2.2.2.2. | Optional | 
| include_ip_range | Range of IP addresses to include. For example: 1.1.1.1-1.1.1.255. | Optional | 
| exclude_ip_rage | Range of IP addresses to exclude.  For example: 1.1.1.1-1.1.1.255. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Device.accessIp | String | Device Access IP. | 
| FortiSIEM.Device.name | String | Device name. | 
| FortiSIEM.Device.naturalId | String | Device unique ID. | 
| FortiSIEM.Device.approved | Unknown | Whether or not the device is approved. | 
| FortiSIEM.Device.unmanaged | Unknown | Whether or not the device is unmanaged. | 
| FortiSIEM.Device.deviceType | Unknown | Device type. | 


#### Command Example
```!fortisiem-cmdb-devices-list limit=2 page=1```

#### Context Example
```json
{
    "FortiSIEM": {
        "Device": [
            {
                "accessIp": "192.168.30.124",
                "approved": "true",
                "deviceType": {
                    "model": "FortiSIEM",
                    "vendor": "Fortinet",
                    "version": "ANY"
                },
                "name": "fortisiem.demo.co",
                "naturalId": "fortisiem.demo.co",
                "organization": {
                    "@id": "1",
                    "@name": "Super"
                },
                "unmanaged": "false"
            },
            {
                "accessIp": "192.168.30.254",
                "approved": "true",
                "deviceType": {
                    "model": "PAN-OS",
                    "vendor": "Palo Alto",
                    "version": "ANY"
                },
                "name": "Palo Alto",
                "naturalId": "HOST%2d192.168.30.254",
                "organization": {
                    "@id": "1",
                    "@name": "Super"
                },
                "unmanaged": "false"
            }
        ]
    }
}
```

#### Human Readable Output

>### List CMDB devices 
>Showing page 1 out of 1 total pages. Current page size: 2.
>
>|Name|Access Ip|Approved|Unmanaged|Device Type|
>|---|---|---|---|---|
>| fortisiem.demo.co | 192.168.30.124 | true | false | vendor: Fortinet<br/>model: FortiSIEM<br/>version: ANY |
>| Palo Alto | 192.168.30.254 | true | false | vendor: Palo Alto<br/>model: PAN-OS<br/>version: ANY |


### fortisiem-cmdb-device-get
***
Retrieve full information of the specified devices.


#### Base Command

`fortisiem-cmdb-device-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | Comma-separated list of devices IP addresses. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Device.accessIp | String | Device access IP. | 
| FortiSIEM.Device.name | String | Device name. | 
| FortiSIEM.Device.naturalId | String | Device unique ID. | 
| FortiSIEM.Device.approved | Unknown | Whether or not the device is approved. | 
| FortiSIEM.Device.unmanaged | Unknown | Whether or not the device is unmanaged. | 
| FortiSIEM.Device.deviceType | Unknown | Device type. | 
| FortiSIEM.Device.discoverMethod | String | Device discover method. | 
| FortiSIEM.Device.discoverTime | Date | When the device was discovered. | 
| FortiSIEM.Device.unmanaged | Unknown | Whether or not the device is unmanaged. | 
| FortiSIEM.Device.updateMethod | Unknown | The update method of the device. | 



#### Command Example
```!fortisiem-cmdb-device-get ips=192.168.30.254```

#### Context Example
```json
{
    "FortiSIEM": {
        "Device": {
            "accessIp": "192.168.30.254",
            "approved": "true",
            "creationMethod": "LOG",
            "deviceType": {
                "accessProtocols": "TELNET,SSH",
                "category": "Appliance",
                "jobWeight": "10",
                "model": "PAN-OS",
                "vendor": "Palo Alto",
                "version": "ANY"
            },
            "discoverMethod": "LOG",
            "discoverTime": "2021-11-23T07:58:48",
            "eventParserList": "0",
            "name": "Palo Alto",
            "naturalId": "HOST%2d192.168.30.254",
            "organization": {
                "@id": "1",
                "@name": "Super"
            },
            "primaryContactUser": "0",
            "secondaryContactUser": "0",
            "status": "2",
            "unmanaged": "false",
            "updateMethod": "MANUAL",
            "version": "ANY",
            "winMachineGuid": null
        }
    }
}
```

#### Human Readable Output

>### CMDB device 192.168.30.254
>|Name|Access Ip|Approved|Unmanaged|Device Type|Discover Time|Discover Method|
>|---|---|---|---|---|---|---|
>| Palo Alto | 192.168.30.254 | true | false | accessProtocols: TELNET,SSH<br/>category: Appliance<br/>jobWeight: 10<br/>model: PAN-OS<br/>vendor: Palo Alto<br/>version: ANY | 2021-11-23T07:58:48 | LOG |


### fortisiem-monitored-organizations-list
***
List of monitored organizations in service provider deployments.


#### Base Command

`fortisiem-monitored-organizations-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of organizations to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Organization.id | String | Organization ID. | 
| FortiSIEM.Organization.name | String | Organization name. | 
| FortiSIEM.Organization.disabled | String | Whether or not the organization is disabled. | 
| FortiSIEM.Organization.domainId | String | Domain ID of the organization. | 
| FortiSIEM.Organization.initialized | Unknown | Whether or not the organization is initialized. | 

#### Command Example
```!fortisiem-monitored-organizations-list limit=2 page=1```

#### Context Example
```json
{
    "FortiSIEM": {
        "Organization": {
            "collectors": {
                "collector": [
                    "EventCollector$null",
                    "EventCollector$null"
                ]
            },
            "creationTime": "2021-11-23T06:58:49",
            "custId": "0",
            "custProperties": null,
            "disabled": "false",
            "domainId": "1",
            "entityVersion": "1",
            "id": "500003",
            "initialized": "true",
            "lastModified": "2021-11-23T06:59:01",
            "name": "Super",
            "ownerId": "0",
            "xmlId": "Domain$Super"
        }
    }
}
```

#### Human Readable Output

>### List Monitored Organizations 
>Showing page 1 out of 1 total pages. Current page size: 2.
>
>|Domain Id|Name|Cust Id|Creation Time|Last Modified|Disabled|
>|---|---|---|---|---|---|
>| 1 | Super | 0 | 2021-11-23T06:58:49 | 2021-11-23T06:59:01 | false |


### fortisiem-event-list-by-incident

***
Lists events by the specified incident ID. Available for FortiSiem version 6.6 and earlier.

#### Base Command

`fortisiem-event-list-by-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| incident_id | The incident ID from which the events were triggered. | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Event.eventType | String | FortiSIEM event type. | 
| FortiSIEM.Event.id | String | Event ID. | 
| FortiSIEM.Event.receiveTime | Date | The date when the event was received by FortiSIEM. | 
| FortiSIEM.Event.attributes | Unknown | Additional attributes of the event. | 
| FortiSIEM.Event.nid | String | Event natural ID. | 
| FortiSIEM.Event.index | Number | Event index in the list. | 
| FortiSIEM.Event.custId | Number | The customer ID the event is related to. | 

#### Command Example
```!fortisiem-event-list-by-incident incident_id=102 limit=1 page=1```

#### Context Example
```json
{
    "FortiSIEM": {
        "Event": {
            "attributes": {
                "Connection Id": "0",
                "Destination Interface SNMP Index": 29034,
                "Destination TCP/UDP Port": 53,
                "Event ID": 9071234812238931000,
                "Event Parse Status": 1,
                "Event Receive Time": 1640085152000,
                "Event Type": "ASA-Built-Conn",
                "External Event Receive Protocol": "NetFlow",
                "IP Protocol": 17,
                "Organization ID": 1,
                "Received Bytes64": 136,
                "Received Packets64": 1,
                "Relaying IP": "192.168.30.254",
                "Reporting Device": "Palo Alto",
                "Reporting IP": "192.168.30.254",
                "Reporting Model": "ASA",
                "Reporting Vendor": "Cisco",
                "Source IP": "192.168.1.1",
                "Source Interface SNMP Index": 29054,
                "Source TCP/UDP Port": 52377,
                "System Event Category": 4,
                "Total Bytes64": 136,
                "Total Flows": 0,
                "Total Packets64": 1
            },
            "custId": 1,
            "dataStr": {},
            "eventAttributes": [],
            "eventType": "ASA-Built-Conn",
            "id": 9071234812238931000,
            "incidentId": "102",
            "index": 0,
            "nid": "9071234812238930440",
            "rawMessage": null,
            "receiveTime": "2021-12-21T11:12:32"
        }
    }
}
```

#### Human Readable Output

>### List Events Of incident: 102 
>Showing page 1 out of others that may exist. Current page size: 1.
> 
>|Id|Cust Id|Index|Event Type|Receive Time|
>|---|---|---|---|---|
>| 9071234812238930440 | 1 | 0 | ASA-Built-Conn | 2021-12-21T11:12:32 || 

### fortisiem-watchlist-list
***
List all watchlists from FortiSIEM database.


#### Base Command

`fortisiem-watchlist-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of watchlists to return. Default is 50. | Optional | 
| entry_value | The entry value. For example, IP address, username, URL, etc. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Watchlist.isCaseSensitive | Boolean | Whether or not watchlist is considered case sensitive. | 
| FortiSIEM.Watchlist.naturalId | String | Watchlist unique ID. | 
| FortiSIEM.Watchlist.displayName | String | Display name. | 
| FortiSIEM.Watchlist.description | String | Watchlist description. | 
| FortiSIEM.Watchlist.valuePattern | String | The value pattern of the watchlist. | 
| FortiSIEM.Watchlist.ageOut | Date | Watchlist expiration time. | 
| FortiSIEM.Watchlist.topGroup | Boolean | Whether or not the watchlist is top group. | 
| FortiSIEM.Watchlist.entries | Unknown | The entries in the watchlist group. | 
| FortiSIEM.Watchlist.dataCreationType | String | Watchlist data creation type. | 
| FortiSIEM.Watchlist.valueType | String | The type of the values of the entries that reside in the watchlist. | 
| FortiSIEM.Watchlist.name | String | Watchlist name. | 
| FortiSIEM.Watchlist.id | Number | Watchlist ID. | 

#### Command Example
```!fortisiem-watchlist-list limit=1 page=1```

#### Context Example
```json
{
    "FortiSIEM": {
        "Watchlist": {
            "ageOut": "1w",
            "custId": 0,
            "dataCreationType": null,
            "description": "Accounts that lock out frequently",
            "displayName": "Accounts Locked",
            "entries": [
                {
                    "ageOut": "Never",
                    "count": null,
                    "custId": 1,
                    "dataCreationType": null,
                    "description": null,
                    "entryValue": "PVVol_A001_A000356_POWER23",
                    "expiredTime": 0,
                    "firstSeen": null,
                    "id": 1059255,
                    "lastSeen": null,
                    "naturalId": "PVVol_A001_A000356_POWER23_1641924540972",
                    "state": "Enabled",
                    "triggeringRules": "Datastore Space Warning"
                }
            ],
            "id": 500496,
            "isCaseSensitive": false,
            "name": "PH_DYNLIST_ACCT_LOCKOUT",
            "naturalId": "PH_DYNLIST_ACCT_LOCKOUT",
            "topGroup": false,
            "valuePattern": null,
            "valueType": "STRING"
        }
    }
}
```

#### Human Readable Output

>### List Watchlist Groups 
>Showing page 1 out of 34 total pages. Current page size: 1.
> >
>|Id|Name|Display Name|Description|Value Type|
>|---|---|---|---|---|
>| 500496 | PH_DYNLIST_ACCT_LOCKOUT | Accounts Locked | Accounts that lock out frequently | STRING |


### fortisiem-watchlist-get
***
Get watchlist by the specified watchlist or entry ID.


#### Base Command

`fortisiem-watchlist-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_ids | Comma-separated list of watchlist group IDs. | Optional | 
| entry_id | Comma-separated list of entry IDs that reside in the watchlist. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Watchlist.isCaseSensitive | Boolean | Whether or not watchlist is considered case sensitive. | 
| FortiSIEM.Watchlist.naturalId | String | Watchlist unique ID. | 
| FortiSIEM.Watchlist.displayName | String | Watchlist display name. | 
| FortiSIEM.Watchlist.description | String | Watchlist description. | 
| FortiSIEM.Watchlist.valuePattern | Unknown | Watchlist entries value pattern. | 
| FortiSIEM.Watchlist.ageOut | Date | Watchlist expiration date. | 
| FortiSIEM.Watchlist.topGroup | Boolean | Whether or not the watchlist is top group. | 
| FortiSIEM.Watchlist.entries | Unknown | Watchlist entries. | 
| FortiSIEM.Watchlist.dataCreationType | Unknown | Data creation type of watchlist. | 
| FortiSIEM.Watchlist.valueType | String | Watchlist entries value type. | 
| FortiSIEM.Watchlist.name | String | Watchlist name. | 
| FortiSIEM.Watchlist.id | Number | Watchlist ID. | 

#### Command Example
```!fortisiem-watchlist-get watchlist_ids=500504```

#### Context Example
```json
{
    "FortiSIEM": {
        "Watchlist": {
            "ageOut": "1w",
            "custId": 0,
            "dataCreationType": null,
            "description": "End nodes that are triggered violations - like visiting unauthorized websites, failed Anti-virus updates, P2P traffic etc",
            "displayName": "Policy Violators",
            "entries": [
                {
                    "ageOut": "Never",
                    "count": 2,
                    "custId": 1,
                    "dataCreationType": "USER",
                    "description": "test-add-entry",
                    "entryValue": "10.10.10.10",
                    "expiredTime": 0,
                    "firstSeen": "2022-01-01T00:00:00",
                    "id": 1576443,
                    "lastSeen": "2022-01-10T00:00:00",
                    "naturalId": "10.10.10.10_1641772800000",
                    "state": "Enabled",
                    "triggeringRules": null
                },
                {
                    "ageOut": "Never",
                    "count": null,
                    "custId": 1,
                    "dataCreationType": null,
                    "description": null,
                    "entryValue": "1.1.1.1",
                    "expiredTime": 0,
                    "firstSeen": null,
                    "id": 1334351,
                    "lastSeen": null,
                    "naturalId": "1.1.1.1_1642502059988",
                    "state": "Enabled",
                    "triggeringRules": "Datastore Space Warning"
                },
                {
                    "ageOut": "Never",
                    "count": null,
                    "custId": 1,
                    "dataCreationType": null,
                    "description": null,
                    "entryValue": "1.1.1.2",
                    "expiredTime": 0,
                    "firstSeen": null,
                    "id": 1334352,
                    "lastSeen": null,
                    "naturalId": "1.1.1.2_1642502188543",
                    "state": "Enabled",
                    "triggeringRules": "Datastore Space Warning"
                },
                {
                    "ageOut": "Never",
                    "count": null,
                    "custId": 1,
                    "dataCreationType": null,
                    "description": null,
                    "entryValue": "169.254.230.24",
                    "expiredTime": 0,
                    "firstSeen": null,
                    "id": 1236150,
                    "lastSeen": null,
                    "naturalId": "169.254.230.24_1642502028914",
                    "state": "Enabled",
                    "triggeringRules": "Datastore Space Warning"
                },
                {
                    "ageOut": "Never",
                    "count": 10,
                    "custId": 1,
                    "dataCreationType": "USER",
                    "description": null,
                    "entryValue": "7.1.1.10",
                    "expiredTime": 0,
                    "firstSeen": "2021-10-07T10:09:29",
                    "id": 1236141,
                    "lastSeen": "2021-10-07T10:09:29",
                    "naturalId": "7.1.1.10_1633601369215",
                    "state": "Enabled",
                    "triggeringRules": "Datastore Space Warning"
                }
            ],
            "id": 500504,
            "isCaseSensitive": false,
            "name": "PH_DYNLIST_POL_VIOLATION_ISSUE",
            "naturalId": "PH_DYNLIST_POL_VIOLATION_ISSUE",
            "topGroup": false,
            "valuePattern": null,
            "valueType": "IP"
        }
    }
}
```

#### Human Readable Output

>### Get Watchlist 500504
>|Id|Name|Display Name|Description|Value Type|
>|---|---|---|---|---|
>| 500504 | PH_DYNLIST_POL_VIOLATION_ISSUE | Policy Violators | End nodes that are triggered violations - such as visiting unauthorized websites, failed Anti-Virus updates, P2P traffic, etc. | IP |
>
>### Watchlist Entries
>|Id|State|Entry Value|Triggering Rules|Count|First Seen|Last Seen|
>|---|---|---|---|---|---|---|
>| 1576443 | Enabled | 10.10.10.10 |  | 2 | 2022-01-01T00:00:00 | 2022-01-10T00:00:00 |
>| 1334351 | Enabled | 1.1.1.1 | Datastore Space Warning |  |  |  |
>| 1334352 | Enabled | 1.1.1.2 | Datastore Space Warning |  |  |  |
>| 1236150 | Enabled | 169.254.230.24 | Datastore Space Warning |  |  |  |
>| 1236141 | Enabled | 7.1.1.10 | Datastore Space Warning | 10 | 2021-10-07T10:09:29 | 2021-10-07T10:09:29 |


### fortisiem-watchlist-add
***
Add a watchlist group. You can also add an entry to the watchlist.


#### Base Command

`fortisiem-watchlist-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Watchlist description. | Optional | 
| display_name | Display name for watchlist group. | Required | 
| is_case_sensitive | Whether entry values are case sensitive. Possible values are: false, true. Default is false. | Optional | 
| data_creation_type | Which entity created the data. Possible values are: USER, SYSTEM. Default is USER. | Optional | 
| value_type | Entries value type. Possible values are: STRING, IP, NUMBER, DATE. Default is STRING. | Optional | 
| age_out | The time period after which items expire from the watchlist group if there is no activity during that time. For example, "3 days", "in 2 weeks", "1 month". By default, items never expire from the watchlist. | Optional | 
| entry_inclusive | Whether the entry is active. Possible values are: false, true. Default is true. | Optional | 
| entry_value | Entry value. | Optional | 
| entry_age_out | The time period after which entries expire from the watchlist group if there is no activity during that time. For example, "3 days", "in 2 weeks", "1 month". By default, entries never expire from the watchlist. | Optional | 
| entry_count | Entry count. | Optional | 
| entry_first_seen | The first time the entry was seen (number, time unit. e.g., 12 hours, 7 days). | Optional | 
| entry_last_seen | The last time the entry was seen. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Optional | 
| entry_trigger_rules | The triggering rules associates with the entry. Should be a comma-separated list of rule names. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Watchlist.isCaseSensitive | Boolean | Whether or not watchlist is considered case sensitive. | 
| FortiSIEM.Watchlist.naturalId | String | Watchlist unique ID. | 
| FortiSIEM.Watchlist.displayName | String | Watchlist display name. | 
| FortiSIEM.Watchlist.description | String | Watchlist description. | 
| FortiSIEM.Watchlist.valuePattern | String | Entries value pattern. | 
| FortiSIEM.Watchlist.ageOut | String | Watchlist expiration date. | 
| FortiSIEM.Watchlist.topGroup | Boolean | Whether or not the watchlist is top group. | 
| FortiSIEM.Watchlist.entries | Unknown | Watchlist entries. | 
| FortiSIEM.Watchlist.dataCreationType | String | The entity that created the watchlist. | 
| FortiSIEM.Watchlist.valueType | String | The value type of the entries in the watchlist. | 
| FortiSIEM.Watchlist.name | String | Watchlist name. | 
| FortiSIEM.Watchlist.id | Number | Watchlist ID. | 

#### Command Example
```!fortisiem-watchlist-add display_name=readme-demo data_creation_type=SYSTEM description="readme-watchlist" value_type=IP```

#### Context Example
```json
{
    "FortiSIEM": {
        "Watchlist": {
            "ageOut": null,
            "custId": 1,
            "dataCreationType": "USER",
            "description": "readme-watchlist",
            "displayName": "readme-demo",
            "entries": null,
            "id": 1244296,
            "isCaseSensitive": false,
            "name": "PH_SYS_Group_DyWatchList_1644929683070",
            "naturalId": "PH_SYS_Group_DyWatchList_1644929683070",
            "topGroup": false,
            "valuePattern": null,
            "valueType": "IP"
        }
    }
}
```

#### Human Readable Output

>### Added new Watchlist group: readme-demo
>|id|name|displayName|description|valueType|
>|---|---|---|---|---|
>| 1244296 | PH_SYS_Group_DyWatchList_1644929683070 | readme-demo | readme-watchlist | IP |


### fortisiem-watchlist-entry-add
***
Add watchlist entry to one or more watchlist groups.


#### Base Command

`fortisiem-watchlist-entry-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID to add the entry to. | Required | 
| inclusive | Whether or not the entry is active. Possible values are: false, true. Default is true. | Optional | 
| count | Entry count. | Optional | 
| triggering_rules | The triggering rules associated with the entry. Should be a comma-separated list of rules names. | Optional | 
| value | The entry value. | Required | 
| age_out | The time period after which the entry expires from the watchlist group if there is no activity during that time. For example, "3 days", "in 2 weeks", "1 month". By default, entries never expire from the watchlist. | Optional | 
| last_seen | The last time the entry was seen. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Optional | 
| first_seen | The first time the entry was seen. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Optional | 
| data_creation_type | Which entity created the data. Possible values are: USER, SYSTEM. Default is USER. | Optional | 
| description | Entry description. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortisiem-watchlist-entry-add value=10.10.10.10 watchlist_id=500504 count=2 description=test-add-entry first_seen=2022-01-01 last_seen=2022-01-10```

#### Human Readable Output

>Successfully added Entry: 10.10.10.10 to Watchlist: 500504.

### fortisiem-watchlist-entry-update
***
Update watchlist entry. This command overrides all existing values in the entry's attribute. Fill in all relevant arguments to avoid deletion of data.


#### Base Command

`fortisiem-watchlist-entry-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data_creation_type | Which entity created the data. Possible values are: USER, SYSTEM. Default is USER. | Optional | 
| first_seen | The first time the entry was seen. For example, "3 days ago", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Optional | 
| count | Entry count. | Optional | 
| triggering_rules | The triggering rules associated with the entry. Should be a comma-separated list of rules names. | Optional | 
| description | Entry description. | Optional | 
| entry_id | The ID of the entry to update. | Required | 
| inclusive | Whether the entry is active. Possible values are: false, true. Default is true. | Optional | 
| value | The entry value. | Required | 
| expired_time | When the entry was expired (number, time unit. e.g, 12 hours, 7 days). | Optional | 
| age_out | The time period after which the entry expires from the watchlist group if there is no activity during that time. For example, "3 days ago", "in 2 weeks", "1 month". By default, the item never expires from the watchlist. | Optional | 
| last_seen | The first time the entry was seen. For example, "3 days", "1 month", "2019-10-10T12:22:00", "2019-10-10". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.WatchlistEntry.lastSeen | Date | The last time the entry was seen. | 
| FortiSIEM.WatchlistEntry.naturalId | String | Entry unique ID. | 
| FortiSIEM.WatchlistEntry.dataCreationType | String | Entry data creation type. | 
| FortiSIEM.WatchlistEntry.firstSeen | Date | The first time the entry was seen. | 
| FortiSIEM.WatchlistEntry.count | Number | The number of times the entry was seen. | 
| FortiSIEM.WatchlistEntry.triggeringRules | String | The triggering rules associated with the entry. | 
| FortiSIEM.WatchlistEntry.description | String | Entry description. | 
| FortiSIEM.WatchlistEntry.id | Number | Entry ID. | 
| FortiSIEM.WatchlistEntry.state | String | Entry state. | 
| FortiSIEM.WatchlistEntry.entryValue | String | Entry value. | 
| FortiSIEM.WatchlistEntry.expiredTime | Date | When the entry was expired. | 
| FortiSIEM.WatchlistEntry.ageOut | String | Expiration date of the entry. | 

#### Command Example
```!fortisiem-watchlist-entry-update entry_id=1488255 value=5.5.5.7 count=5```

#### Context Example
```json
{
    "FortiSIEM": {
        "WatchlistEntry": {
            "ageOut": "Never",
            "count": 5,
            "custId": 1,
            "dataCreationType": "USER",
            "description": null,
            "entryValue": "5.5.5.7",
            "expiredTime": 0,
            "firstSeen": null,
            "id": 1488255,
            "lastSeen": null,
            "naturalId": "5.5.5.7_1644916470062",
            "state": "Enabled",
            "triggeringRules": null
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Entry: 1488255.
>|Id|State|Entry Value|Triggering Rules|Count|First Seen|Last Seen|
>|---|---|---|---|---|---|---|
>| 1488255 | Enabled | 5.5.5.7 |  | 5 |  |  |


### fortisiem-watchlist-entry-delete
***
Delete entry of watchlist.


#### Base Command

`fortisiem-watchlist-entry-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_ids | Comma-separated list of entry IDs to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortisiem-watchlist-entry-delete entry_ids=1488255```

#### Human Readable Output

>The entry 1488255 were deleted successfully.

### fortisiem-watchlist-delete
***
Delete watchlist.


#### Base Command

`fortisiem-watchlist-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | Comma-separated list of watchlist IDs to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!fortisiem-watchlist-delete watchlist_id=1244273```

#### Human Readable Output

>The watchlist 1244273 was deleted successfully.

### fortisiem-watchlist-entry-get
***
Get entry by the specified entry ID.


#### Base Command

`fortisiem-watchlist-entry-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_ids | Comma-separated list of entry IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.WatchlistEntry.lastSeen | Date | The last time the entry was seen. | 
| FortiSIEM.WatchlistEntry.naturalId | String | Entry unique ID. | 
| FortiSIEM.WatchlistEntry.dataCreationType | String | Entry data creation type. | 
| FortiSIEM.WatchlistEntry.firstSeen | Date | The first time the entry was seen. | 
| FortiSIEM.WatchlistEntry.count | Number | The number of times the entry was seen. | 
| FortiSIEM.WatchlistEntry.triggeringRules | String | The triggering rules associated with the entry. | 
| FortiSIEM.WatchlistEntry.description | String | Entry description. | 
| FortiSIEM.WatchlistEntry.id | Number | Entry ID. | 
| FortiSIEM.WatchlistEntry.state | String | Entry state. | 
| FortiSIEM.WatchlistEntry.entryValue | String | Entry value. | 
| FortiSIEM.WatchlistEntry.expiredTime | Date | When the entry was expired. | 
| FortiSIEM.WatchlistEntry.ageOut | String | Expiration date of the entry. | 

#### Command Example
```!fortisiem-watchlist-entry-get entry_ids=1576423```

#### Context Example
```json
{
    "FortiSIEM": {
        "WatchlistEntry": {
            "ageOut": "1w",
            "count": 1,
            "custId": 1,
            "dataCreationType": null,
            "description": null,
            "entryValue": "192.168.91.3",
            "expiredTime": "2022-02-20T10:42:30",
            "firstSeen": "2022-01-04T12:43:00",
            "id": 1576423,
            "lastSeen": "2022-02-13T10:42:30",
            "naturalId": "192.168.91.3_1644748950000",
            "state": "Enabled",
            "triggeringRules": "Sudden Increase in ICMP Requests From A Host"
        }
    }
}
```

#### Human Readable Output

>### Get Watchlist Entry: 1576423
>|Id|State|Entry Value|Triggering Rules|Count|First Seen|Last Seen|
>|---|---|---|---|---|---|---|
>| 1576423 | Enabled | 192.168.91.3 | Sudden Increase in ICMP Requests From A Host | 1 | 2022-01-04T12:43:00 | 2022-02-13T10:42:30 |


### fortisiem-event-search-results
***
The results of the specified search ID.


#### Base Command

`fortisiem-event-search-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The ID of the search query to retrieve its results. | Required | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The page number to retrieve. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiSIEM.Event.custId | Number | The customer ID the event is related to. | 
| FortiSIEM.Event.index | Number | The position number of the event in the results. | 
| FortiSIEM.Event.id | String | Event ID. | 
| FortiSIEM.Event.eventType | String | The event type. | 
| FortiSIEM.Event.receiveTime | Date | When the event was received in UTC time. | 
| FortiSIEM.Event.nid | String | The event ID. | 
| FortiSIEM.Event.attributes | Unknown | Additional attributes of the event. | 


## Breaking changes from the previous version of this integration - FortiSIEM v2
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
***fortisiem-get-events-by-incident*** - this command was replaced by ***fortisiem-event-list-by-incident***.
***fortisiem-clear-incident*** - this command was replaced by ***fortisiem-incident-update***.
***fortisiem-get-events-by-filter*** - this command was replaced by ***fortisiem-event-search-status***.
***fortisiem-get-cmdb-devices*** - this command was replaced by ***fortisiem-cmdb-devices-list***.
***fortisiem-get-events-by-query*** - this command was replaced by ***fortisiem-event-search-status***.
***fortisiem-get-lists*** .
***fortisiem-add-item-to-resource-list***.
***fortisiem-remove-item-from-resource-list***.
***fortisiem-get-resource-list***.

## Additional Considerations for this version
#### The following commands were added in this version:
***fortisiem-watchlist-list***
***fortisiem-watchlist-get***
***fortisiem-watchlist-add***
***fortisiem-watchlist-entry-add***
***fortisiem-watchlist-entry-update***
***fortisiem-watchlist-delete***
***fortisiem-watchlist-entry-delete***
***fortisiem-watchlist-entry-get***

#### The fetch incidents command can also fetch triggered events.