## Overview
---

Append HyperContext™ insights to your SIEM data and feed them into your orchestration workflows.
This integration was integrated and tested with version 1.0 of WootCloud
## WootCloud Playbook
---

## Configure WootCloud on XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for WootCloud.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Client ID__
    * __API Key__
    * __Time to retrieve the first fetch (number time unit, e.g., 12 hours, 7 days)__
    * __Alert Type__
    * __Severity Type__
    * __ Trust any certificate (not secure)__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. wootcloud-get-pkt-alerts
2. wootcloud-get-bt-alerts
3. wootcloud-get-anomaly-alerts
4. wootcloud-fetch-packet-alert
5. wootcloud-fetch-bluetooth-alert
6. wootcloud-fetch-anomaly-alert
### 1. wootcloud-get-pkt-alerts
---
list packet alerts generated in requested time span
##### Base Command

`wootcloud-get-pkt-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Examples are (2 hours, 4 minutes, 6 month, 1 day, etc.) | Required | 
| severity | severity with values of 'notice', 'warning', 'critical' | Optional | 
| skip | integer value for pagination. Default value: 0 | Optional | 
| limit | Integer value for pagination. Default value: 10. Max Value: 500 | Optional | 
| site_id | Array of site ids. Only entered if you want results for a particular site(s) (building, city, region) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.PacketAlert.id | String | ID of alert | 
| WootCloud.PacketAlert.address | String | Mac Address of device | 
| WootCloud.PacketAlert.timestamp | Date | Alert timestamp | 
| WootCloud.PacketAlert.severity | String | Severity level | 
| WootCloud.PacketAlert.category | String | Alert Category | 
| WootCloud.PacketAlert.signature | String | signature | 
| WootCloud.PacketAlert.source.city | String | source city | 
| WootCloud.PacketAlert.source.continent | String | source continent | 
| WootCloud.PacketAlert.source.country | String | source country | 
| WootCloud.PacketAlert.source.ip | String | source ip | 
| WootCloud.PacketAlert.source.latitude | Number | source latitude | 
| WootCloud.PacketAlert.source.longitude | Number | source longitude | 
| WootCloud.PacketAlert.source.mac | String | source mac address | 
| WootCloud.PacketAlert.source.network | String | source network | 
| WootCloud.PacketAlert.source.port | Number | source port | 
| WootCloud.PacketAlert.source.state | String | source state | 
| WootCloud.PacketAlert.source.subnet | String | source subnet | 
| WootCloud.PacketAlert.source.time_zone | String | source time zone | 
| WootCloud.PacketAlert.source.zip | String | source zip | 
| WootCloud.PacketAlert.source.inferred.device_id | String | source inferred device ID | 
| WootCloud.PacketAlert.source.inferred.asset | String | source inferred asset | 
| WootCloud.PacketAlert.source.inferred.managed | Number | source inferred managed | 
| WootCloud.PacketAlert.source.inferred.category | String | source inferred category | 
| WootCloud.PacketAlert.source.inferred.control | String | source inferred control | 
| WootCloud.PacketAlert.source.inferred.host_name | String | source inferred host name | 
| WootCloud.PacketAlert.source.inferred.os | String | source inferred OS | 
| WootCloud.PacketAlert.source.inferred.os_version | String | source inferred OS version | 
| WootCloud.PacketAlert.source.inferred.ownership | String | source inferred ownership | 
| WootCloud.PacketAlert.source.inferred.total_risk | Number | source inferred total risk score | 
| WootCloud.PacketAlert.source.inferred.type | String | source inferred type | 
| WootCloud.PacketAlert.source.inferred.username | String | source inferred username | 
| WootCloud.PacketAlert.source.inferred.managed_info.host_name | String | source inferred managed host name | 
| WootCloud.PacketAlert.destination.city | String | destination city | 
| WootCloud.PacketAlert.destination.continent | String | destination continent | 
| WootCloud.PacketAlert.destination.country | String | destination country | 
| WootCloud.PacketAlert.destination.ip | String | destination ip | 
| WootCloud.PacketAlert.destination.latitude | Number | destination latitude | 
| WootCloud.PacketAlert.destination.longitude | Number | destination longitude | 
| WootCloud.PacketAlert.destination.mac | String | destination mac address | 
| WootCloud.PacketAlert.destination.network | String | destination network | 
| WootCloud.PacketAlert.destination.port | Number | destination port | 
| WootCloud.PacketAlert.destination.state | String | destination state | 
| WootCloud.PacketAlert.destination.subnet | String | destination subnet | 
| WootCloud.PacketAlert.destination.time_zone | String | destination time zone | 
| WootCloud.PacketAlert.destination.zip | String | destination zip | 
| WootCloud.PacketAlert.destination.inferred.device_id | String | destination inferred device ID | 
| WootCloud.PacketAlert.destination.inferred.asset | String | destination inferred asset | 
| WootCloud.PacketAlert.destination.inferred.managed | Number | destination inferred managed | 
| WootCloud.PacketAlert.destination.inferred.category | String | destination inferred category | 
| WootCloud.PacketAlert.destination.inferred.control | String | destination inferred control | 
| WootCloud.PacketAlert.destination.inferred.host_name | String | destination inferred host name | 
| WootCloud.PacketAlert.destination.inferred.os | String | destination inferred OS | 
| WootCloud.PacketAlert.destination.inferred.os_version | String | destination inferred OS version | 
| WootCloud.PacketAlert.destination.inferred.ownership | String | destination inferred ownership | 
| WootCloud.PacketAlert.destination.inferred.total_risk | Number | destination inferred total risk score | 
| WootCloud.PacketAlert.destination.inferred.type | String | destination inferred type | 
| WootCloud.PacketAlert.destination.inferred.username | String | destination inferred username | 
| WootCloud.PacketAlert.destination.inferred.managed_info.host_name | String | destination inferred managed info hostname | 
| WootCloud.PacketAlert.payload | String | payload | 
| WootCloud.PacketAlert.http.hostname | String | http hostname | 
| WootCloud.PacketAlert.http.http_method | String | http methon | 
| WootCloud.PacketAlert.http.http_user_agent | String | http user agent | 
| WootCloud.PacketAlert.http.length | Number | http length | 
| WootCloud.PacketAlert.http.protocol | String | http protocol | 
| WootCloud.PacketAlert.http.redirect | String | http redirect | 
| WootCloud.PacketAlert.http.http_refer | String | http referal | 
| WootCloud.PacketAlert.http.status | Number | http status code | 
| WootCloud.PacketAlert.http.url | String | http url | 
| WootCloud.PacketAlert.type | String | http type | 
| WootCloud.PacketAlert.group | String | group | 
| WootCloud.PacketAlert.subtype | String | subtype | 
| WootCloud.PacketAlert.title | String | title | 
| WootCloud.PacketAlert.description | String | description | 
| WootCloud.PacketAlert.references | String | references | 


##### Command Example
```!wootcloud-get-pkt-alerts date_range="30 days" severity="info" limit="1"```

##### Context Example
```
{
    "WootCloud.PacketAlert": {
        "total": 936, 
        "packet_alerts": [
            {
                "category": "User Activity Detected", 
                "http": null, 
                "description": "ET POLICY Dropbox.com Offsite File Backup in Use", 
                "subtype": "policy-violation", 
                "timestamp": "2020-10-05T13:24:27Z", 
                "destination": {
                    "city": "Unknown", 
                    "network": "internal", 
                    "zip": "Unknown", 
                    "state": "Unknown", 
                    "ip": "10.10.10.10", 
                    "inferred": {
                        "category": "computer", 
                        "control": "user", 
                        "managed_info": {
                            "host_name": "DESKTOP-73OV7ML"
                        }, 
                        "managed": true, 
                        "type": "computer", 
                        "username": "7c67a2377751", 
                        "os_version": "10", 
                        "host_name": "DESKTOP-73OV7ML", 
                        "ownership": "corporate", 
                        "total_risk": 0, 
                        "device_id": "5b589f43e4b58d191f7e017c", 
                        "os": "windows", 
                        "asset": "managed"
                    }, 
                    "longitude": -1, 
                    "port": 50859, 
                    "mac": "7c:67:a2:37:77:51", 
                    "time_zone": "Unknown", 
                    "country": "Unknown", 
                    "latitude": -1, 
                    "subnet": "10.10.10.10/24", 
                    "continent": "Unknown"
                }, 
                "payload": "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", 
                "source": {
                    "city": "San Francisco", 
                    "network": "external", 
                    "zip": "94107", 
                    "state": "California", 
                    "ip": "4.4.4.4", 
                    "inferred": {
                        "category": "networking_equipment", 
                        "control": "auto", 
                        "managed_info": {
                            "host_name": ""
                        }, 
                        "managed": false, 
                        "type": "network infrastructure", 
                        "username": "", 
                        "os_version": "", 
                        "host_name": "", 
                        "ownership": "corporate-unmanaged", 
                        "total_risk": 0, 
                        "device_id": "5d73f6a3c250255491ce3839", 
                        "os": "linux", 
                        "asset": "unmanaged"
                    }, 
                    "longitude": -122.3933, 
                    "port": 443, 
                    "mac": "c4:24:56:87:ef:11", 
                    "time_zone": "America/Los_Angeles", 
                    "country": "United States", 
                    "latitude": 37.7697, 
                    "subnet": "", 
                    "continent": "North America"
                }, 
                "type": "pkt_alert", 
                "references": [], 
                "title": "User Activity Detected", 
                "address": "7c:12:a2:45:77:51", 
                "group": "alert", 
                "signature": "ET POLICY Dropbox.com Offsite File Backup in Use", 
                "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzQxMTYzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDUifQ==", 
                "severity": "info"
            }
        ]
    }
}
```

##### Human Readable Output
### Results for alerts
|id|severity|signature|timestamp|
|---|---|---|---|
| eyJpIjoiU05XT09UQVBQUFJPRDAxXzQxMTYzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDUifQ== | info | ET POLICY Dropbox.com Offsite File Backup in Use | 2020-10-05T13:24:27Z |


### 2. wootcloud-get-bt-alerts
---
list bluetooth alerts generated in requested time span

##### Base Command

`wootcloud-get-bt-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Examples are (2 hours, 4 minutes, 6 month, 1 day, etc.) | Required | 
| severity | severity with values of 'notice', 'warning', 'critical' | Optional | 
| skip | integer value for pagination. Default value: 0 | Optional | 
| limit | Integer value for pagination. Default value: 10. Max Value: 500 | Optional | 
| site_id | Array of site ids. Only entered if you want results for a particular site(s) (building, city, region) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.BluetoothAlert.id | String | ID | 
| WootCloud.BluetoothAlert.timestamp | Date | timestamp | 
| WootCloud.BluetoothAlert.severity | String | severity | 
| WootCloud.BluetoothAlert.signature | String | signature | 
| WootCloud.BluetoothAlert.description | String | description | 
| WootCloud.BluetoothAlert.address | String | address | 
| WootCloud.BluetoothAlert.inferred.device_id | String | inferred device ID | 
| WootCloud.BluetoothAlert.inferred.asset | String | inferred asset | 
| WootCloud.BluetoothAlert.inferred.managed | Number | inferred managed | 
| WootCloud.BluetoothAlert.inferred.category | String | inferred category | 
| WootCloud.BluetoothAlert.inferred.control | String | inferred control | 
| WootCloud.BluetoothAlert.inferred.host_name | String | inferred host name | 
| WootCloud.BluetoothAlert.inferred.os | String | inferred OS | 
| WootCloud.BluetoothAlert.inferred.os_version | String | inferred OS version | 
| WootCloud.BluetoothAlert.inferred.ownership | String | inferred ownership | 
| WootCloud.BluetoothAlert.inferred.total_risk | Number | inferred total risk score | 
| WootCloud.BluetoothAlert.inferred.type | String | inferred type | 
| WootCloud.BluetoothAlert.inferred.username | String | inferred username | 
| WootCloud.BluetoothAlert.inferred.managed_info.host_name | String | inferred managed info host name | 
| WootCloud.BluetoothAlert.type | String | type | 
| WootCloud.BluetoothAlert.group | String | group | 
| WootCloud.BluetoothAlert.subtype | String | subtype | 
| WootCloud.BluetoothAlert.title | String | title | 


##### Command Example
```!wootcloud-get-bt-alerts date_range="30 days" limit="1"```

##### Context Example
```
{
    "WootCloud.BluetoothAlert": {
        "total": 0, 
        "alerts": []
    }
}
```

##### Human Readable Output
### Results
|alerts|total|
|---|---|
|  | 0 |


### 3. wootcloud-get-anomaly-alerts
---
list anomaly alerts generated in requested time span

##### Base Command

`wootcloud-get-anomaly-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Examples are (2 hours, 4 minutes, 6 month, 1 day, etc.) | Required | 
| severity | severity with values of 'info, ''notice', 'warning', 'critical' | Optional | 
| skip | integer value for pagination. Default value: 0 | Optional | 
| limit | Integer value for pagination. Default value: 10. Max Value: 500 | Optional | 
| site_id | Array of site ids. Only entered if you want results for a particular site(s) (building, city, region) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.AnomalyAlert.id | String | ID | 
| WootCloud.AnomalyAlert.timestamp | Date | timestamp | 
| WootCloud.AnomalyAlert.anomaly_type | String | anomaly type | 
| WootCloud.AnomalyAlert.signature | String | signature | 
| WootCloud.AnomalyAlert.description | String | description | 
| WootCloud.AnomalyAlert.severity | String | severity | 
| WootCloud.AnomalyAlert.count | Number | count | 
| WootCloud.AnomalyAlert.average | Number | average | 
| WootCloud.AnomalyAlert.minimum | Number | minimum | 
| WootCloud.AnomalyAlert.maximum | Number | maximum | 
| WootCloud.AnomalyAlert.standard_deviation | Number | standard deviation | 
| WootCloud.AnomalyAlert.anomaly_score | Number | anomaly score | 
| WootCloud.AnomalyAlert.observed_value | Number | observed value | 
| WootCloud.AnomalyAlert.deviation_from_norm | String | deviation from the norm | 
| WootCloud.AnomalyAlert.units | String | units | 
| WootCloud.AnomalyAlert.address | String | address | 
| WootCloud.AnomalyAlert.type | String | type | 
| WootCloud.AnomalyAlert.group | String | group | 
| WootCloud.AnomalyAlert.subtype | String | subtype | 
| WootCloud.AnomalyAlert.title | String | title | 
| WootCloud.AnomalyAlert.device_details.device_id | String | device details device ID | 
| WootCloud.AnomalyAlert.device_details.asset | String | device details asset | 
| WootCloud.AnomalyAlert.device_details.managed | Number | device details managed | 
| WootCloud.AnomalyAlert.device_details.category | String | device details category | 
| WootCloud.AnomalyAlert.device_details.control | String | device details control | 
| WootCloud.AnomalyAlert.device_details.host_name | String | device details host name | 
| WootCloud.AnomalyAlert.device_details.os | String | device details OS | 
| WootCloud.AnomalyAlert.device_details.os_version | String | device details OS version | 
| WootCloud.AnomalyAlert.device_details.ownership | String | device details ownership | 
| WootCloud.AnomalyAlert.device_details.total_risk | Number | device details total risk score | 
| WootCloud.AnomalyAlert.device_details.type | String | device details type | 
| WootCloud.AnomalyAlert.device_details.username | String | device details username | 
| WootCloud.AnomalyAlert.device_details.managed_info.host_name | String | device details managed info host name | 
| WootCloud.AnomalyAlert.connections.ip | String | connections ip | 
| WootCloud.AnomalyAlert.connections.port | Number | connections port | 
| WootCloud.AnomalyAlert.connections.connection_count | Number | connections connection count | 


##### Command Example
```!wootcloud-get-anomaly-alerts date_range="30 days" limit="5"```

##### Context Example
```
{
    "WootCloud.AnomalyAlert": {
        "total": 11, 
        "alerts": [
            {
                "anomaly_type": "Connection", 
                "maximum": 0, 
                "connections": [
                    {
                        "ip": "2.2.2.2", 
                        "connection_count": 0, 
                        "port": 443
                    }, 
                    {
                        "ip": "3.3.3.3", 
                        "connection_count": 0, 
                        "port": 443
                    }, 
                    {
                        "ip": "4.4.4.4", 
                        "connection_count": 0, 
                        "port": 443
                    }
                ], 
                "deviation_from_norm": "2", 
                "minimum": 0, 
                "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxV4JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE3NDQ4OTcuNzg0NTg0LDI2ODkzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDMifQ==", 
                "group": "anomaly", 
                "severity": "low", 
                "title": "Connection Anomaly", 
                "standard_deviation": 0, 
                "units": "", 
                "type": "realtime-anomaly", 
                "observed_value": 0, 
                "description": "Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:\nnumber of connections:15 (normally:2.44+/-1.40)\nnumber of destination ips:14 (normally:1.93+/-1.05)\nnumber of destination ports:3 (normally:1.89+/-0.96)\nnormal is based on 26,893 observations.", 
                "timestamp": "2020-10-03T17:08:17Z", 
                "address": "3c:a9:f4:64:06:e0", 
                "count": 26893, 
                "average": 0, 
                "anomaly_score": 0.41364444218713525, 
                "subtype": "realtime_p002", 
                "device_details": {
                    "category": "computer", 
                    "control": "auto", 
                    "managed_info": {
                        "host_name": "DESKTOP-EV123JG"
                    }, 
                    "managed": true, 
                    "type": "computer", 
                    "username": "3ca9f46406e0", 
                    "os_version": "10", 
                    "host_name": "DESKTOP-EV123JG", 
                    "ownership": "corporate", 
                    "total_risk": 0, 
                    "device_id": "5b4c3c91072c98142d308b29", 
                    "os": "windows", 
                    "asset": "managed"
                }, 
                "signature": "realtime_p002:pktstats3|1-min|"
            }, 
            {
                "anomaly_type": "Connection", 
                "maximum": 0, 
                "connections": [
                    {
                        "ip": "4.4.4.4", 
                        "connection_count": 0, 
                        "port": 443
                    }, 
                    {
                        "ip": "3.3.3.3", 
                        "connection_count": 0, 
                        "port": 443
                    }
                ], 
                "deviation_from_norm": "2", 
                "minimum": 0, 
                "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE2NjM0MTIuNzQ4MiwyNTYzM18wMDAiLCJ4IjoiNWEwMGIxNzU5Yzc5NjQ4ODBmYTFjMWE2X2NfZDIwMjAxMDAyIn0=", 
                "group": "anomaly", 
                "severity": "low", 
                "title": "Connection Anomaly", 
                "standard_deviation": 0, 
                "units": "", 
                "type": "realtime-anomaly", 
                "observed_value": 0, 
                "description": "Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:\nnumber of connections:16 (normally:2.58+/-1.52)\nnumber of destination ips:14 (normally:2.03+/-1.14)\nnumber of destination ports:3 (normally:1.92+/-0.93)\nnormal is based on 25,633 observations.", 
                "timestamp": "2020-10-02T18:30:12Z", 
                "address": "3c:a9:f4:64:06:e0", 
                "count": 25633, 
                "average": 0, 
                "anomaly_score": 0.41364444218713525, 
                "subtype": "realtime_p002", 
                "device_details": {
                    "category": "computer", 
                    "control": "auto", 
                    "managed_info": {
                        "host_name": "DESKTOP-EV607JG"
                    }, 
                    "managed": true, 
                    "type": "computer", 
                    "username": "3ca9f46406e0", 
                    "os_version": "10", 
                    "host_name": "DESKTOP-EV607JG", 
                    "ownership": "corporate", 
                    "total_risk": 0, 
                    "device_id": "5b4c3c91072c98142d308b29", 
                    "os": "windows", 
                    "asset": "managed"
                }, 
                "signature": "realtime_p002:pktstats3|1-min|"
            }, 
            {
                "anomaly_type": "Connection", 
                "maximum": 0, 
                "connections": [
                    {
                        "ip": "8.8.8.8", 
                        "connection_count": 0, 
                        "port": 53
                    }, 
                    {
                        "ip": "2.2.2.2", 
                        "connection_count": 0, 
                        "port": 80
                    }, 
                    {
                        "ip": "3.3.3.3", 
                        "connection_count": 0, 
                        "port": 80
                    },
                ], 
                "deviation_from_norm": "4", 
                "minimum": 0, 
                "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDAwOjBjOjI5OjBjOjY0Ojk2LDE2MDE1NTkxODcuMTE1MjY1LDI1NTAyXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDEifQ==", 
                "group": "anomaly", 
                "severity": "medium", 
                "title": "Connection Anomaly", 
                "standard_deviation": 0, 
                "units": "", 
                "type": "realtime-anomaly", 
                "observed_value": 0, 
                "description": "Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:\nnumber of connections:28 (normally:1.67+/-1.88)\nnumber of destination ips:11 (normally:1.15+/-0.57)\nnumber of destination ports:3 (normally:1.07+/-0.27)\nnormal is based on 25,502 observations.", 
                "timestamp": "2020-10-01T13:33:07Z", 
                "address": "00:0c:29:0c:64:96", 
                "count": 25502, 
                "average": 0, 
                "anomaly_score": 0.7064193203972353, 
                "subtype": "realtime_p002", 
                "device_details": {
                    "category": "computer", 
                    "control": "user", 
                    "managed_info": {
                        "host_name": ""
                    }, 
                    "managed": false, 
                    "type": "computer", 
                    "username": "", 
                    "os_version": "", 
                    "host_name": "WOOTAPP", 
                    "ownership": "visiting", 
                    "total_risk": 0, 
                    "device_id": "5ea36ccd5c727ddfb1742471", 
                    "os": "windows", 
                    "asset": "unmanaged"
                }, 
                "signature": "realtime_p002:pktstats3|1-min|"
            }, 
            {
                "anomaly_type": "Connection", 
                "maximum": 0, 
                "connections": [
                    {
                        "ip": "3.3.3.3", 
                        "connection_count": 0, 
                        "port": 80
                    }, 
                    {
                        "ip": "8.8.4.4", 
                        "connection_count": 0, 
                        "port": 443
                    }, 
                    {
                        "ip": "8.8.8.8", 
                        "connection_count": 0, 
                        "port": 53
                    }
                ], 
                "deviation_from_norm": "2", 
                "minimum": 0, 
                "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDEzODg4NTAuMjQ0ODM5LDIzMjQzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDA5MjkifQ==", 
                "group": "anomaly", 
                "severity": "low", 
                "title": "Connection Anomaly", 
                "standard_deviation": 0, 
                "units": "", 
                "type": "realtime-anomaly", 
                "observed_value": 0, 
                "description": "Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:\nnumber of connections:17 (normally:2.70+/-1.43)\nnumber of destination ips:16 (normally:2.15+/-1.11)\nnumber of destination ports:3 (normally:2.09+/-0.97)\nnormal is based on 23,243 observations.", 
                "timestamp": "2020-09-29T14:14:10Z", 
                "address": "3c:a9:f4:64:06:e0", 
                "count": 23243, 
                "average": 0, 
                "anomaly_score": 0.41364444218713525, 
                "subtype": "realtime_p002", 
                "device_details": {
                    "category": "computer", 
                    "control": "auto", 
                    "managed_info": {
                        "host_name": "DESKTOP-EV607JG"
                    }, 
                    "managed": true, 
                    "type": "computer", 
                    "username": "3ca9f46406e0", 
                    "os_version": "10", 
                    "host_name": "DESKTOP-EV607JG", 
                    "ownership": "corporate", 
                    "total_risk": 0, 
                    "device_id": "5b4c3c91072c98142d308b29", 
                    "os": "windows", 
                    "asset": "managed"
                }, 
                "signature": "realtime_p002:pktstats3|1-min|"
            }, 
            {
                "anomaly_type": "Connection", 
                "maximum": 0, 
                "connections": [
                    {
                        "ip": "8.8.8.8", 
                        "connection_count": 0, 
                        "port": 53
                    }, 
                    {
                        "ip": "3.3.3.3", 
                        "connection_count": 0, 
                        "port": 80
                    }, 
                    {
                        "ip": "4.4.4.4", 
                        "connection_count": 0, 
                        "port": 80
                    }, 
                    {
                        "ip": "5.5.5.5", 
                        "connection_count": 0, 
                        "port": 80
                    }
                ], 
                "deviation_from_norm": "4", 
                "minimum": 0, 
                "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDAwOjBjOjI5OjFhOjdmOmU5LDE2MDEzMzQ1NzQuNTQ1MzAzLDQzMzgzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDA5MjgifQ==", 
                "group": "anomaly", 
                "severity": "medium", 
                "title": "Connection Anomaly", 
                "standard_deviation": 0, 
                "units": "", 
                "type": "realtime-anomaly", 
                "observed_value": 0, 
                "description": "Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:\nnumber of connections:48 (normally:4.17+/-1.60)\nnumber of destination ips:10 (normally:1.29+/-0.47)\nnumber of destination ports:4 (normally:1.29+/-0.46)\nnormal is based on 43,383 observations.", 
                "timestamp": "2020-09-28T23:09:34Z", 
                "address": "00:0c:29:1a:7f:e9", 
                "count": 43383, 
                "average": 0, 
                "anomaly_score": 0.7064193203972353, 
                "subtype": "realtime_p002", 
                "device_details": {
                    "category": "computer", 
                    "control": "user", 
                    "managed_info": {
                        "host_name": ""
                    }, 
                    "managed": false, 
                    "type": "computer", 
                    "username": "", 
                    "os_version": "", 
                    "host_name": "WOOTAPP", 
                    "ownership": "visiting", 
                    "total_risk": 0, 
                    "device_id": "5ecd43f95c727ddfb186fac0", 
                    "os": "windows", 
                    "asset": "unmanaged"
                }, 
                "signature": "realtime_p002:pktstats3|1-min|"
            }
        ]
    }
}
```

##### Human Readable Output
### Results for alerts
|id|severity|signature|timestamp|
|---|---|---|---|
| eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE3NDQ4OTcuNzg0NTg0LDI2ODkzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDMifQ== | low | realtime_p002:pktstats3\|1-min\| | 2020-10-03T17:08:17Z |
| eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE2NjM0MTIuNzQ4MiwyNTYzM18wMDAiLCJ4IjoiNWEwMGIxNzU5Yzc5NjQ4ODBmYTFjMWE2X2NfZDIwMjAxMDAyIn0= | low | realtime_p002:pktstats3\|1-min\| | 2020-10-02T18:30:12Z |
| eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDAwOjBjOjI5OjBjOjY0Ojk2LDE2MDE1NTkxODcuMTE1MjY1LDI1NTAyXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDEifQ== | medium | realtime_p002:pktstats3\|1-min\| | 2020-10-01T13:33:07Z |
| eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDEzODg4NTAuMjQ0ODM5LDIzMjQzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDA5MjkifQ== | low | realtime_p002:pktstats3\|1-min\| | 2020-09-29T14:14:10Z |
| eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDAwOjBjOjI5OjFhOjdmOmU5LDE2MDEzMzQ1NzQuNTQ1MzAzLDQzMzgzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDA5MjgifQ== | medium | realtime_p002:pktstats3\|1-min\| | 2020-09-28T23:09:34Z |


### 4. wootcloud-fetch-packet-alert
---
retrieve single packet alert given packet id
##### Base Command

`wootcloud-fetch-packet-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the ID of the packet alert | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.PacketAlert.id | String | ID of alert | 
| WootCloud.PacketAlert.address | String | Mac Address of device | 
| WootCloud.PacketAlert.timestamp | Date | Alert timestamp | 
| WootCloud.PacketAlert.severity | String | Severity level | 
| WootCloud.PacketAlert.category | String | Alert Category | 
| WootCloud.PacketAlert.signature | String | signature | 
| WootCloud.PacketAlert.source.city | String | source city | 
| WootCloud.PacketAlert.source.continent | String | source continent | 
| WootCloud.PacketAlert.source.country | String | source country | 
| WootCloud.PacketAlert.source.ip | String | source ip | 
| WootCloud.PacketAlert.source.latitude | Number | source latitude | 
| WootCloud.PacketAlert.source.longitude | Number | source longitude | 
| WootCloud.PacketAlert.source.mac | String | source mac address | 
| WootCloud.PacketAlert.source.network | String | source network | 
| WootCloud.PacketAlert.source.port | Number | source port | 
| WootCloud.PacketAlert.source.state | String | source state | 
| WootCloud.PacketAlert.source.subnet | String | source subnet | 
| WootCloud.PacketAlert.source.time_zone | String | source time zone | 
| WootCloud.PacketAlert.source.zip | String | source zip | 
| WootCloud.PacketAlert.source.inferred.device_id | String | source inferred device ID | 
| WootCloud.PacketAlert.source.inferred.asset | String | source inferred asset | 
| WootCloud.PacketAlert.source.inferred.managed | Number | source inferred managed | 
| WootCloud.PacketAlert.source.inferred.category | String | source inferred category | 
| WootCloud.PacketAlert.source.inferred.control | String | source inferred control | 
| WootCloud.PacketAlert.source.inferred.host_name | String | source inferred host name | 
| WootCloud.PacketAlert.source.inferred.os | String | source inferred OS | 
| WootCloud.PacketAlert.source.inferred.os_version | String | source inferred OS version | 
| WootCloud.PacketAlert.source.inferred.ownership | String | source inferred ownership | 
| WootCloud.PacketAlert.source.inferred.total_risk | Number | source inferred total risk score | 
| WootCloud.PacketAlert.source.inferred.type | String | source inferred type | 
| WootCloud.PacketAlert.source.inferred.username | String | source inferred username | 
| WootCloud.PacketAlert.source.inferred.managed_info.host_name | String | source inferred managed host name | 
| WootCloud.PacketAlert.destination.city | String | destination city | 
| WootCloud.PacketAlert.destination.continent | String | destination continent | 
| WootCloud.PacketAlert.destination.country | String | destination country | 
| WootCloud.PacketAlert.destination.ip | String | destination ip | 
| WootCloud.PacketAlert.destination.latitude | Number | destination latitude | 
| WootCloud.PacketAlert.destination.longitude | Number | destination longitude | 
| WootCloud.PacketAlert.destination.mac | String | destination mac address | 
| WootCloud.PacketAlert.destination.network | String | destination network | 
| WootCloud.PacketAlert.destination.port | Number | destination port | 
| WootCloud.PacketAlert.destination.state | String | destination state | 
| WootCloud.PacketAlert.destination.subnet | String | destination subnet | 
| WootCloud.PacketAlert.destination.time_zone | String | destination time zone | 
| WootCloud.PacketAlert.destination.zip | String | destination zip | 
| WootCloud.PacketAlert.destination.inferred.device_id | String | destination inferred device ID | 
| WootCloud.PacketAlert.destination.inferred.asset | String | destination inferred asset | 
| WootCloud.PacketAlert.destination.inferred.managed | Number | destination inferred managed | 
| WootCloud.PacketAlert.destination.inferred.category | String | destination inferred category | 
| WootCloud.PacketAlert.destination.inferred.control | String | destination inferred control | 
| WootCloud.PacketAlert.destination.inferred.host_name | String | destination inferred host name | 
| WootCloud.PacketAlert.destination.inferred.os | String | destination inferred OS | 
| WootCloud.PacketAlert.destination.inferred.os_version | String | destination inferred OS version | 
| WootCloud.PacketAlert.destination.inferred.ownership | String | destination inferred ownership | 
| WootCloud.PacketAlert.destination.inferred.total_risk | Number | destination inferred total risk score | 
| WootCloud.PacketAlert.destination.inferred.type | String | destination inferred type | 
| WootCloud.PacketAlert.destination.inferred.username | String | destination inferred username | 
| WootCloud.PacketAlert.destination.inferred.managed_info.host_name | String | destination inferred managed info hostname | 
| WootCloud.PacketAlert.payload | String | payload | 
| WootCloud.PacketAlert.http.hostname | String | http hostname | 
| WootCloud.PacketAlert.http.http_method | String | http methon | 
| WootCloud.PacketAlert.http.http_user_agent | String | http user agent | 
| WootCloud.PacketAlert.http.length | Number | http length | 
| WootCloud.PacketAlert.http.protocol | String | http protocol | 
| WootCloud.PacketAlert.http.redirect | String | http redirect | 
| WootCloud.PacketAlert.http.http_refer | String | http referal | 
| WootCloud.PacketAlert.http.status | Number | http status code | 
| WootCloud.PacketAlert.http.url | String | http url | 
| WootCloud.PacketAlert.type | String | http type | 
| WootCloud.PacketAlert.group | String | group | 
| WootCloud.PacketAlert.subtype | String | subtype | 
| WootCloud.PacketAlert.title | String | title | 
| WootCloud.PacketAlert.description | String | description | 
| WootCloud.PacketAlert.references | String | references | 


##### Command Example
```!wootcloud-fetch-packet-alert alert_id="eyJpIjoiU05XT09UQVBQUFJPRDAxXzI2MzY1XzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDQifQ=="```

##### Context Example
```
{
    "WootCloud.PacketAlert": {
        "category": "Generic Protocol Command Decode", 
        "http": {
            "redirect": "https://api-wootuno-1606049077.us-west-2.elb.amazonaws.com:443/wpad.dat", 
            "status": 301, 
            "http_user_agent": "WinHttp-Autoproxy-Service/5.1", 
            "protocol": "HTTP/1.1", 
            "http_refer": "", 
            "url": "/wpad.dat", 
            "hostname": "api-wootuno-1606049077.us-west-2.elb.amazonaws.com", 
            "length": 134, 
            "http_method": "GET"
        }, 
        "description": "ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel", 
        "subtype": "protocol-command-decode", 
        "timestamp": "2020-10-04T04:09:05Z", 
        "destination": {
            "city": "Boardman", 
            "network": "external", 
            "zip": "97818", 
            "state": "Oregon", 
            "ip": "3.3.3.3", 
            "inferred": {
                "category": "networking_equipment", 
                "control": "auto", 
                "managed_info": {
                    "host_name": ""
                }, 
                "managed": false, 
                "type": "network infrastructure", 
                "username": "", 
                "os_version": "", 
                "host_name": "", 
                "ownership": "corporate-unmanaged", 
                "total_risk": 0, 
                "device_id": "5d73f6a3c250255491ce3839", 
                "os": "linux", 
                "asset": "unmanaged"
            }, 
            "longitude": -119.688, 
            "port": 80, 
            "mac": "c4:24:56:87:ef:11", 
            "time_zone": "America/Los_Angeles", 
            "country": "United States", 
            "latitude": 45.8696, 
            "subnet": "", 
            "continent": "North America"
        }, 
        "payload": "R0VUIC93cGFkLmRhdCBIVFRQLzEuMQ0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KQWNjZXB0OiAqLyoNClVzZXItQWdlbnQ6IFdpbkh0dHAtQXV0b3Byb3h5LVNlcnZpY2UvNS4xDQpIb3N0OiBhcGktd29vdHVuby0xNjA2MDQ5MDc3LnVzLXdlc3QtMi5lbGIuYW1hem9uYXdzLmNvbQ0KDQo=", 
        "source": {
            "city": "Unknown", 
            "network": "internal", 
            "zip": "Unknown", 
            "state": "Unknown", 
            "ip": "10.10.10.10", 
            "inferred": {
                "category": "computer", 
                "control": "auto", 
                "managed_info": {
                    "host_name": "DESKTOP-EV607JG"
                }, 
                "managed": true, 
                "type": "computer", 
                "username": "3ca9f46406e0", 
                "os_version": "10", 
                "host_name": "DESKTOP-EV607JG", 
                "ownership": "corporate", 
                "total_risk": 0, 
                "device_id": "5b4c3c91072c98142d308b29", 
                "os": "windows", 
                "asset": "managed"
            }, 
            "longitude": -1, 
            "port": 63202, 
            "mac": "3c:a9:f4:64:06:e0", 
            "time_zone": "Unknown", 
            "country": "Unknown", 
            "latitude": -1, 
            "subnet": "10.10.10.10/24", 
            "continent": "Unknown"
        }, 
        "type": "pkt_alert", 
        "references": [], 
        "title": "Generic Protocol Command Decode", 
        "address": "3c:a9:f4:64:06:e0", 
        "group": "alert", 
        "signature": "ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel", 
        "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzI2MzY1XzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDQifQ==", 
        "severity": "info"
    }
}
```

##### Human Readable Output
### Results
|address|category|description|destination|group|http|id|payload|references|severity|signature|source|subtype|timestamp|title|type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 3c:a9:f4:64:06:e0 | Generic Protocol Command Decode | ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel | city: Boardman<br/>continent: North America<br/>country: United States<br/>ip: 3.3.3.3<br/>latitude: 45.8696<br/>longitude: -119.688<br/>mac: c4:24:56:87:ef:11<br/>network: external<br/>port: 80<br/>state: Oregon<br/>subnet: <br/>time_zone: America/Los_Angeles<br/>zip: 97818<br/>inferred: {"device_id": "5d73f6a3c250255491ce3839", "asset": "unmanaged", "managed": false, "category": "networking_equipment", "control": "auto", "host_name": "", "os": "linux", "os_version": "", "ownership": "corporate-unmanaged", "total_risk": 0, "type": "network infrastructure", "username": "", "managed_info": {"host_name": ""}} | alert | hostname: api-wootuno-1606049077.us-west-2.elb.amazonaws.com<br/>http_method: GET<br/>http_user_agent: WinHttp-Autoproxy-Service/5.1<br/>length: 134<br/>protocol: HTTP/1.1<br/>redirect: https://api-wootuno-1606049077.us-west-2.elb.amazonaws.com:443/wpad.dat<br/>http_refer: <br/>status: 301<br/>url: /wpad.dat | eyJpIjoiU05XT09UQVBQUFJPRDAxXzI2MzY1XzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDQifQ== | R0VUIC93cGFkLmRhdCBIVFRQLzEuMQ0KQ29ubmVjdGlvbjogS2VlcC1BbGl2ZQ0KQWNjZXB0OiAqLyoNClVzZXItQWdlbnQ6IFdpbkh0dHAtQXV0b3Byb3h5LVNlcnZpY2UvNS4xDQpIb3N0OiBhcGktd29vdHVuby0xNjA2MDQ5MDc3LnVzLXdlc3QtMi5lbGIuYW1hem9uYXdzLmNvbQ0KDQo= |  | info | ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel | city: Unknown<br/>continent: Unknown<br/>country: Unknown<br/>ip: 10.10.10.10<br/>latitude: -1<br/>longitude: -1<br/>mac: 3c:a9:f4:64:06:e0<br/>network: internal<br/>port: 63202<br/>state: Unknown<br/>subnet: 10.10.10.10/24<br/>time_zone: Unknown<br/>zip: Unknown<br/>inferred: {"device_id": "5b4c3c91072c98142d308b29", "asset": "managed", "managed": true, "category": "computer", "control": "auto", "host_name": "DESKTOP-EV607JG", "os": "windows", "os_version": "10", "ownership": "corporate", "total_risk": 0, "type": "computer", "username": "3ca9f46406e0", "managed_info": {"host_name": "DESKTOP-EV607JG"}} | protocol-command-decode | 2020-10-04T04:09:05Z | Generic Protocol Command Decode | pkt_alert |


### 5. wootcloud-fetch-bluetooth-alert
---
retrieve single bluetooth alert given packet id

##### Base Command

`wootcloud-fetch-bluetooth-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the ID of the bluetooth alert | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.BluetoothAlert.id | String | ID | 
| WootCloud.BluetoothAlert.timestamp | Date | timestamp | 
| WootCloud.BluetoothAlert.severity | String | severity | 
| WootCloud.BluetoothAlert.signature | String | signature | 
| WootCloud.BluetoothAlert.description | String | description | 
| WootCloud.BluetoothAlert.address | String | address | 
| WootCloud.BluetoothAlert.inferred.device_id | String | inferred device ID | 
| WootCloud.BluetoothAlert.inferred.asset | String | inferred asset | 
| WootCloud.BluetoothAlert.inferred.managed | Number | inferred managed | 
| WootCloud.BluetoothAlert.inferred.category | String | inferred category | 
| WootCloud.BluetoothAlert.inferred.control | String | inferred control | 
| WootCloud.BluetoothAlert.inferred.host_name | String | inferred host name | 
| WootCloud.BluetoothAlert.inferred.os | String | inferred OS | 
| WootCloud.BluetoothAlert.inferred.os_version | String | inferred OS version | 
| WootCloud.BluetoothAlert.inferred.ownership | String | inferred ownership | 
| WootCloud.BluetoothAlert.inferred.total_risk | Number | inferred total risk score | 
| WootCloud.BluetoothAlert.inferred.type | String | inferred type | 
| WootCloud.BluetoothAlert.inferred.username | String | inferred username | 
| WootCloud.BluetoothAlert.inferred.managed_info.host_name | String | inferred managed info host name | 
| WootCloud.BluetoothAlert.type | String | type | 
| WootCloud.BluetoothAlert.group | String | group | 
| WootCloud.BluetoothAlert.subtype | String | subtype | 
| WootCloud.BluetoothAlert.title | String | title | 


##### Command Example
```!wootcloud-fetch-bluetooth-alert alert_id="EXMP001"```

##### Human Readable Output


### 6. wootcloud-fetch-anomaly-alert
---
retrieve single anomaly alert given packet id

##### Base Command

`wootcloud-fetch-anomaly-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the ID of the anomaly alert | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.AnomalyAlert.id | String | ID | 
| WootCloud.AnomalyAlert.timestamp | Date | timestamp | 
| WootCloud.AnomalyAlert.anomaly_type | String | anomaly type | 
| WootCloud.AnomalyAlert.signature | String | signature | 
| WootCloud.AnomalyAlert.description | String | description | 
| WootCloud.AnomalyAlert.severity | String | severity | 
| WootCloud.AnomalyAlert.count | Number | count | 
| WootCloud.AnomalyAlert.average | Number | average | 
| WootCloud.AnomalyAlert.minimum | Number | minimum | 
| WootCloud.AnomalyAlert.maximum | Number | maximum | 
| WootCloud.AnomalyAlert.standard_deviation | Number | standard deviation | 
| WootCloud.AnomalyAlert.anomaly_score | Number | anomaly score | 
| WootCloud.AnomalyAlert.observed_value | Number | observed value | 
| WootCloud.AnomalyAlert.deviation_from_norm | String | deviation from the norm | 
| WootCloud.AnomalyAlert.units | String | units | 
| WootCloud.AnomalyAlert.address | String | address | 
| WootCloud.AnomalyAlert.type | String | type | 
| WootCloud.AnomalyAlert.group | String | group | 
| WootCloud.AnomalyAlert.subtype | String | subtype | 
| WootCloud.AnomalyAlert.title | String | title | 
| WootCloud.AnomalyAlert.device_details.device_id | String | device details device ID | 
| WootCloud.AnomalyAlert.device_details.asset | String | device details asset | 
| WootCloud.AnomalyAlert.device_details.managed | Number | device details managed | 
| WootCloud.AnomalyAlert.device_details.category | String | device details category | 
| WootCloud.AnomalyAlert.device_details.control | String | device details control | 
| WootCloud.AnomalyAlert.device_details.host_name | String | device details host name | 
| WootCloud.AnomalyAlert.device_details.os | String | device details OS | 
| WootCloud.AnomalyAlert.device_details.os_version | String | device details OS version | 
| WootCloud.AnomalyAlert.device_details.ownership | String | device details ownership | 
| WootCloud.AnomalyAlert.device_details.total_risk | Number | device details total risk score | 
| WootCloud.AnomalyAlert.device_details.type | String | device details type | 
| WootCloud.AnomalyAlert.device_details.username | String | device details username | 
| WootCloud.AnomalyAlert.device_details.managed_info.host_name | String | device details managed info host name | 
| WootCloud.AnomalyAlert.connections.ip | String | connections ip | 
| WootCloud.AnomalyAlert.connections.port | Number | connections port | 
| WootCloud.AnomalyAlert.connections.connection_count | Number | connections connection count | 


##### Command Example
```!wootcloud-fetch-anomaly-alert alert_id="eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE3NDQ4OTcuNzg0NTg0LDI2ODkzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDMifQ=="	"```

##### Context Example
```
{
    "WootCloud.AnomalyAlert": {
        "anomaly_type": "Connection", 
        "maximum": 0, 
        "connections": [
            {
                "ip": "2.2.2.2", 
                "connection_count": 0, 
                "port": 443
            }, 
            {
                "ip": "3.3.3.3", 
                "connection_count": 0, 
                "port": 443
            }, 
            {
                "ip": "4.4.4.4", 
                "connection_count": 0, 
                "port": 443
            }
        ], 
        "deviation_from_norm": "2", 
        "minimum": 0, 
        "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE3NDQ4OTcuNzg0NTg0LDI2ODkzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDMifQ==", 
        "group": "anomaly", 
        "severity": "low", 
        "title": "Connection Anomaly", 
        "standard_deviation": 0, 
        "units": "", 
        "type": "realtime-anomaly", 
        "observed_value": 0, 
        "description": "Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:\nnumber of connections:15 (normally:2.44+/-1.40)\nnumber of destination ips:14 (normally:1.93+/-1.05)\nnumber of destination ports:3 (normally:1.89+/-0.96)\nnormal is based on 26,893 observations.", 
        "timestamp": "2020-10-03T17:08:17Z", 
        "address": "3c:a9:f4:64:06:e0", 
        "count": 26893, 
        "average": 0, 
        "anomaly_score": 0.41364444218713525, 
        "subtype": "realtime_p002", 
        "device_details": {
            "category": "computer", 
            "control": "auto", 
            "managed_info": {
                "host_name": "DESKTOP-EV607JG"
            }, 
            "managed": true, 
            "type": "computer", 
            "username": "3ca9f46406e0", 
            "os_version": "10", 
            "host_name": "DESKTOP-EV607JG", 
            "ownership": "corporate", 
            "total_risk": 0, 
            "device_id": "5b4c3c91072c98142d308b29", 
            "os": "windows", 
            "asset": "managed"
        }, 
        "signature": "realtime_p002:pktstats3|1-min|"
    }
}
```

##### Human Readable Output
### Results
|address|anomaly_score|anomaly_type|average|connections|count|description|deviation_from_norm|device_details|group|id|maximum|minimum|observed_value|severity|signature|standard_deviation|subtype|timestamp|title|type|units|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 3c:a9:f4:64:06:e0 | 0.41364444218713525 | Connection | 0 | {'ip': '2.2.2.2', 'port': 443, 'connection_count': 0},<br/>{'ip': '3.3.3.3', 'port': 443, 'connection_count': 0},<br/>{'ip': '4.4.4.4', 'port': 443, 'connection_count': 0},<br/>{'ip': '2.2.2.2', 'port': 443, 'connection_count': 0} | 26893 | Realtime Connection anomaly (1-min) triggered based on combination of 3 attributes:<br/>number of connections:15 (normally:2.44+/-1.40)<br/>number of destination ips:14 (normally:1.93+/-1.05)<br/>number of destination ports:3 (normally:1.89+/-0.96)<br/>normal is based on 26,893 observations. | 2 | device_id: 5b4c3c91072c98142d308b29<br/>asset: managed<br/>managed: true<br/>category: computer<br/>control: auto<br/>host_name: DESKTOP-EV607JG<br/>os: windows<br/>os_version: 10<br/>ownership: corporate<br/>total_risk: 0<br/>type: computer<br/>username: 3ca9f46406e0<br/>managed_info: {"host_name": "DESKTOP-EV607JG"} | anomaly | eyJpIjoiU05XT09UQVBQUFJPRDAxX3JlYWx0aW1lX3AwMDIscGt0c3RhdHMzLDNjOmE5OmY0OjY0OjA2OmUwLDE2MDE3NDQ4OTcuNzg0NTg0LDI2ODkzXzAwMCIsIngiOiI1YTAwYjE3NTljNzk2NDg4MGZhMWMxYTZfY19kMjAyMDEwMDMifQ== | 0 | 0 | 0 | low | realtime_p002:pktstats3\|1-min\| | 0 | realtime_p002 | 2020-10-03T17:08:17Z | Connection Anomaly | realtime-anomaly |  |

