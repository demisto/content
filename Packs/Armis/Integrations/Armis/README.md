Use the Armis integration to search alerts and devices, tag and untag devices, and set alert statuses.
This integration was integrated and tested with the latest version of Armis.
## Configure Armis in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of incidents per fetch |  | False |
| Fetch alerts with status (UNHANDLED, SUPPRESSED, RESOLVED) |  | False |
| Fetch alerts with type | The type of alerts are Policy Violation, System Policy Violation, Anomaly Detection If no type is chosen, all types will be fetched. | False |
| Minimum severity of alerts to fetch |  | True |
| First fetch time |  | False |
| Trust any certificate (not secure) |  | False |
| Secret API Key |  | True |
| Fetch Alerts AQL | Use this parameter to fetch incidents using a free AQL string rather than the simpler alert type, severity, etc. | False |
| Proxy | Whether to use the System proxy | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### armis-search-alerts
***
Search Armis Alerts.


#### Base Command

`armis-search-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | The maximum number of results to get. Default is 50. | Optional | 
| time_frame | Filter by start time. <br/>Examples:<br/>  "3 days ago"<br/>  "1 month"<br/>  "2019-10-10T12:22:00"<br/>  "2019-10-10". Default is 3 days. | Optional | 
| alert_id | The ID of the alert. | Optional | 
| severity | A comma-separated list of alert severity levels by which to filter the search results. Possible values: "Low", "Medium", and "High". | Optional | 
| status | A comma-separated list of alert statuses by which to filter the search results. Possible values: "UNHANDLED", "SUPPRESSED", and "RESOLVED". | Optional | 
| alert_type | A comma-separated list of alert types by which to filter the search results. Possible values: "Policy Violation", "System Policy Violation", and "Anomaly Detection" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Armis.Alert.activityIds | Number | The activity IDs of the alert. | 
| Armis.Alert.activityUUIDs | String | The activity UUIDs of the alert. | 
| Armis.Alert.alertId | Number | The ID of the alert. | 
| Armis.Alert.connectionIds | Number | The connection IDs of the alert. | 
| Armis.Alert.description | String | A text description of the alert. | 
| Armis.Alert.deviceIds | Number | The device IDs of the alert | 
| Armis.Alert.severity | String | The severity of the alert. | 
| Armis.Alert.status | String | The status of the alert. | 
| Armis.Alert.time | Date | The date and time the alert occurred. | 
| Armis.Alert.title | String | The title of the alert. | 
| Armis.Alert.type | String | The type of the alert. | 


#### Command Example
```!armis-search-alerts status=RESOLVED max_results=10```

#### Context Example
```json
{
    "Armis": {
        "Alert": {
            "activityIds": [
                23314066,
                23316462,
                23317202,
                23326470,
                23341779,
                23342441
            ],
            "activityUUIDs": [
                "enyZFHgBAAAC-vCT9nJG",
                "0Hy2FHgBAAAC-vCTGnJB",
                "3Hy_FHgBAAAC-vCTp3Kz",
                "v3wSFXgBAAAC-vCTFnNL",
                "_nxOGHgBAAAC-vCTUnc2",
                "2HxpGHgBAAAC-vCT03jo"
            ],
            "alertId": 3984,
            "connectionIds": [
                923419,
                923501,
                924451
            ],
            "description": "Smart TV started connection to Corporate Network",
            "deviceIds": [
                165722,
                532
            ],
            "severity": "Medium",
            "status": "Resolved",
            "time": "2021-03-09T01:28:44.032944+00:00",
            "title": "Smart TV connected to Corporate network",
            "type": "System Policy Violation"
        }
    }
}
```

#### Human Readable Output

>### Alerts
>|Severity|Type|Time|Status|Title|Description|Activity Ids|Activity UUI Ds|Alert Id|Connection Ids|Device Ids|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Medium | System Policy Violation | 2021-03-09T01:28:44.032944+00:00 | Resolved | Smart TV connected to Corporate network | Smart TV started connection to Corporate Network | 23314066,<br/>23316462,<br/>23317202,<br/>23326470,<br/>23341779,<br/>23342441 | enyZFHgBAAAC-vCT9nJG,<br/>0Hy2FHgBAAAC-vCTGnJB,<br/>3Hy_FHgBAAAC-vCTp3Kz,<br/>v3wSFXgBAAAC-vCTFnNL,<br/>_nxOGHgBAAAC-vCTUnc2,<br/>2HxpGHgBAAAC-vCT03jo | 3984 | 923419,<br/>923501,<br/>924451 | 165722,<br/>532 |


### armis-update-alert-status
***
Updates the status for an alert.


#### Base Command

`armis-update-alert-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to update. | Required | 
| status | New status of the alert. Possible values are: UNHANDLED, RESOLVED, SUPPRESSED. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### armis-search-alerts-by-aql-string
***
Searches the alerts with a raw AQL string.


#### Base Command

`armis-search-alerts-by-aql-string`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| aql_string | The AQL string to by which to search. | Required | 
| max_results | The maximum number of results to get. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Armis.Alert.activityIds | Number | The activity IDs of the alert. | 
| Armis.Alert.activityUUIDs | String | The activity UUIDs of the alert. | 
| Armis.Alert.alertId | Number | The ID of the alert. | 
| Armis.Alert.connectionIds | Number | The connection IDs of the alert. | 
| Armis.Alert.description | String | The description of the alert. | 
| Armis.Alert.deviceIds | Number | The device IDs of the alert. | 
| Armis.Alert.severity | String | The severity of the alert. | 
| Armis.Alert.status | String | The status of the alert. | 
| Armis.Alert.time | Date | The date and time the alert occurred. | 
| Armis.Alert.title | String | The title of the alert. | 
| Armis.Alert.type | String | The type of the alert. | 


#### Command Example
```!armis-search-alerts-by-aql-string aql_string="alertId:(3821)"```

#### Context Example
```json
{
    "Armis": {
        "Alert": {
            "activityIds": [
                22060159
            ],
            "activityUUIDs": [
                "nTiGqXcBAAAC-vCTfzPN"
            ],
            "alertId": 3821,
            "connectionIds": [],
            "description": "The Armis security platform has detected a violation of a policy and generated an alert.",
            "deviceIds": [
                199808
            ],
            "severity": "Medium",
            "status": "Resolved",
            "time": "2021-02-16T06:23:02.101479+00:00",
            "title": "Unencrypted Traffic: SMB",
            "type": "System Policy Violation"
        }
    }
}
```

#### Human Readable Output

>### Alerts
>|Alert Id|Description|Type|Title|Severity|Status|Time|Activity Ids|Activity UUI Ds|Device Ids|
>|---|---|---|---|---|---|---|---|---|---|
>| 3821 | The Armis security platform has detected a violation of a policy and generated an alert. | System Policy Violation | Unencrypted Traffic: SMB | Medium | Resolved | 2021-02-16T06:23:02.101479+00:00 | 22060159 | nTiGqXcBAAAC-vCTfzPN | 199808 |


### armis-tag-device
***
Adds a tag to a device.


#### Base Command

`armis-tag-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device to add a tag to. | Required | 
| tags | The tags to add to the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!armis-tag-device device_id=165722 tags=test```

#### Human Readable Output

>Successfully Tagged device: 165722 with tags: ['test']

### armis-untag-device
***
Removes a tag from a device.


#### Base Command

`armis-untag-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device to remove a tag from. | Required | 
| tags | The tags to remove from the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!armis-untag-device device_id=165722 tags=test```

#### Human Readable Output

>Successfully Untagged device: 165722 with tags: ['test']

### armis-search-devices
***
Search devices by identifiers.


#### Base Command

`armis-search-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the device to search for. | Optional | 
| device_id | The ID of the device to search for. | Optional | 
| mac_address | The MAC address of the device to search for. | Optional | 
| ip_address | The IP address of the device to search for. | Optional | 
| device_type | A comma-separated list of device types by which to filter the results. for example "Routers", "Laptops", "IP Cameras" (there are many device types. for a full list access your Armis instance). | Optional | 
| time_frame | The time frame of the device to search for. | Optional | 
| max_results | The maximum number of results to get. Default is 50. | Optional | 
| risk_level | A comma-separated list of device risk levels by which to filter the results. Possible values: "Low", "Medium", and "High". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Armis.Device.accessSwitch | String | The access switch of the device. | 
| Armis.Device.category | String | The category of the device. | 
| Armis.Device.firstSeen | Date | The first time the device was seen. | 
| Armis.Device.id | Number | The ID of the device. | 
| Armis.Device.ipaddress | String | The IP address of the device. | 
| Armis.Device.ipv6 | String | The IPv6 address of the device. | 
| Armis.Device.lastSeen | Date | The last time the device was seen. | 
| Armis.Device.macAddress | String | The MAC address of the device. | 
| Armis.Device.manufacturer | String | The manufacturer of the device. | 
| Armis.Device.model | String | The model of the device. | 
| Armis.Device.name | String | The name of the device. | 
| Armis.Device.operatingSystem | String | The operating system of the device. | 
| Armis.Device.operatingSystemVersion | String | The operating system version of the device. | 
| Armis.Device.purdueLevel | String | The purdue level of the device. | 
| Armis.Device.riskLevel | String | The risk level of the device. | 
| Armis.Device.sensor | String | The sensor of the device. | 
| Armis.Device.site | String | The site of the device. | 
| Armis.Device.tags | String | The tags of the device. | 
| Armis.Device.type | String | The type of the device. | 
| Armis.Device.user | String | The user of the device. | 
| Armis.Device.visibility | String | The visibility of the device. | 

#### Command example
```!armis-search-devices device_id=2172```
#### Context Example
```json
{
    "Armis": {
        "Device": {
            "accessSwitch": null,
            "boundaries": "Corporate",
            "category": "Computers",
            "customProperties": {},
            "dataSources": [
                {
                    "firstSeen": "2022-08-11T07:54:32.167939+00:00",
                    "lastSeen": "2022-11-28T14:56:36.198248+00:00",
                    "name": "Active Directory",
                    "types": [
                        "Asset & System Management",
                        "Identity Provider"
                    ]
                },
                {
                    "firstSeen": "2021-08-15T07:37:58.891683+00:00",
                    "lastSeen": "2022-11-28T21:02:20.208248+00:00",
                    "name": "CrowdStrike",
                    "types": [
                        "Agent Based",
                        "Endpoint Protection"
                    ]
                },
                {
                    "firstSeen": "2022-07-09T07:50:51.190248+00:00",
                    "lastSeen": "2022-11-28T20:02:52.190248+00:00",
                    "name": "MBAM (BitLocker)",
                    "types": [
                        "Asset & System Management"
                    ]
                },
                {
                    "firstSeen": "2022-11-16T13:55:23.190248+00:00",
                    "lastSeen": "2022-11-28T21:30:45.190248+00:00",
                    "name": "Palo Alto Networks GlobalProtect",
                    "types": [
                        "Firewall"
                    ]
                },
                {
                    "firstSeen": "2022-07-12T12:55:47.190248+00:00",
                    "lastSeen": "2022-11-28T23:42:41.190248+00:00",
                    "name": "Qualys",
                    "types": [
                        "Vulnerability Management"
                    ]
                },
                {
                    "firstSeen": "2022-07-09T07:50:51.190248+00:00",
                    "lastSeen": "2022-11-28T20:02:52.190248+00:00",
                    "name": "SCCM",
                    "types": [
                        "Asset & System Management",
                        "Patch Management"
                    ]
                },
                {
                    "firstSeen": "2022-07-22T06:36:52.190248+00:00",
                    "lastSeen": "2022-07-22T06:40:36.190248+00:00",
                    "name": "ServiceNow",
                    "types": [
                        "Asset & System Management"
                    ]
                },
                {
                    "firstSeen": "2022-11-21T17:00:00.360310+00:00",
                    "lastSeen": "2022-11-28T22:23:35.190248+00:00",
                    "name": "Traffic Inspection",
                    "types": [
                        "Traffic Inspection",
                        "Data Analysis"
                    ]
                },
                {
                    "firstSeen": "2022-06-13T07:10:57.686241+00:00",
                    "lastSeen": "2022-11-22T00:59:54.686241+00:00",
                    "name": "User",
                    "types": [
                        "Data Upload"
                    ]
                },
                {
                    "firstSeen": "2022-11-15T10:05:08.190248+00:00",
                    "lastSeen": "2022-11-28T21:30:45.190248+00:00",
                    "name": "Aruba WLC",
                    "types": [
                        "WLC"
                    ]
                }
            ],
            "firstSeen": "2022-11-21T16:59:58.360310+00:00",
            "id": 2172,
            "ipAddress": "10.77.27.183",
            "ipv6": "fe80::647b:ba0f:9628:6014",
            "lastSeen": "2022-11-29T18:42:50.190248+00:00",
            "macAddress": "50:76:AF:D3:3F:AB",
            "manufacturer": "Lenovo",
            "model": "ThinkPad X1 Yoga 3rd Gen",
            "name": "000000731194pc.corporate.acme.com",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10",
            "purdueLevel": 4,
            "riskLevel": 5,
            "sensor": {
                "name": "PALO_ALTO-IDF04-SW01:Gig1/0/44 Enterprise",
                "type": "Access Switch"
            },
            "site": {
                "location": "Palo Alto",
                "name": "Palo Alto Enterprise"
            },
            "tags": [
                "Corporate",
                "ServiceNow",
                "SCCM"
            ],
            "type": "Laptops",
            "userIds": [
                12
            ],
            "visibility": "Full"
        }
    }
}
```

#### Human Readable Output

### Devices
>|Risk Level|Id|Name|Type|Ip Address|Ipv 6|Mac Address|Operating System|Operating System Version|Manufacturer|Model|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 5 | 2172 | 000000731194pc.corporate.acme.com | Laptops | 10.77.27.183 | fe80::647b:ba0f:9628:6014 | 50:76:AF:D3:3F:AB | Windows | 10 | Lenovo | ThinkPad X1 Yoga 3rd Gen | Corporate,<br>ServiceNow,<br>SCCM |


### armis-search-devices-by-aql
***
Searches devices with a custom AQL search string.


#### Base Command

`armis-search-devices-by-aql`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| aql_string | The AQL string. | Required | 
| max_results | The maximum number of results to get. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Armis.Device.accessSwitch | String | The access switch of the device. | 
| Armis.Device.category | String | The category of the device. | 
| Armis.Device.firstSeen | Date | The first time the device was seen. | 
| Armis.Device.id | Number | The ID of the device. | 
| Armis.Device.ipaddress | String | The IP address of the device. | 
| Armis.Device.ipv6 | String | The IPv6 address of the device. | 
| Armis.Device.lastSeen | Date | The last time the device was seen. | 
| Armis.Device.macAddress | String | The MAC address of the device. | 
| Armis.Device.manufacturer | String | The manufacturer of the device. | 
| Armis.Device.model | String | The model of the device. | 
| Armis.Device.name | String | The name of the device. | 
| Armis.Device.operatingSystem | String | The operating system of the device. | 
| Armis.Device.operatingSystemVersion | String | The operating system version of the device. | 
| Armis.Device.purdueLevel | String | The purdue level of the device. | 
| Armis.Device.riskLevel | String | The risk level of the device. | 
| Armis.Device.sensor | String | The sensor of the device. | 
| Armis.Device.site | String | The site of the device. | 
| Armis.Device.tags | String | The tags of the device. | 
| Armis.Device.type | String | The type of the device. | 
| Armis.Device.user | String | The user of the device. | 
| Armis.Device.visibility | String | The visibility of the device. | 


#### Command Example
```!armis-search-devices-by-aql aql_string="macAddress:(a4:5d:36:c5:32:69)"```

#### Context Example
```json
{
    "Armis": {
        "Device": {
            "accessSwitch": "win-sw-hoc-01:po9",
            "category": "Computers",
            "dataSources": [
                {
                    "firstSeen": "2020-10-01T11:56:48+00:00",
                    "lastSeen": "2021-03-11T20:26:40+00:00",
                    "name": "Meraki",
                    "types": [
                        "WLC"
                    ]
                },
                {
                    "firstSeen": "2021-02-02T08:34:10.536715+00:00",
                    "lastSeen": "2021-03-11T20:21:22.374047+00:00",
                    "name": "Network Mapper",
                    "types": [
                        "Network Monitoring"
                    ]
                },
                {
                    "firstSeen": "2020-07-05T11:25:24.128383+00:00",
                    "lastSeen": "2021-03-11T20:32:33.494314+00:00",
                    "name": "Traffic Inspection",
                    "types": [
                        "Traffic Inspection",
                        "Data Analysis"
                    ]
                }
            ],
            "firstSeen": "2020-06-01T00:30:32.318087+00:00",
            "id": 74745,
            "ipAddress": "10.0.100.10",
            "ipv6": null,
            "lastSeen": "2021-03-11T20:32:33.494314+00:00",
            "macAddress": "a4:5d:36:c5:32:69",
            "manufacturer": "Hewlett Packard",
            "model": "Hewlett device",
            "name": "wc-shoretel.winslow.local",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "Server 2008 R2",
            "riskLevel": 10,
            "sensor": {
                "name": "win-wap-tfm-01",
                "type": "Access Point"
            },
            "site": {
                "location": "28 Merri Concourse, Campbellfield VIc 3061 Australia",
                "name": "Winslow Small Plant"
            },
            "tags": [
                "MERAKI_NETWORK=Winslow Campbellfield"
            ],
            "type": "Servers",
            "user": "",
            "visibility": "Full"
        }
    }
}
```

#### Human Readable Output

>### Devices
>|Risk Level|Name|Type|Ip Address|Tags|Id|
>|---|---|---|---|---|---|
>| 10 | wc-shoretel.winslow.local | Servers | 10.0.100.10 | MERAKI_NETWORK=Winslow Campbellfield | 74745 |