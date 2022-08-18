# Gigamon ThreatINSIGHT Integration for Cortex XSOAR

## Insight Overview

The Gigamon ThreatINSIGHT Cortex XSOAR integration enables security teams to utilize the features and functionality of the ThreatINSIGHT solution with their existing Cortex deployment. The integration leverages ThreatINSIGHT RESTful APIs to interact with the back end to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.

## Integration Overview

The Gigamon ThreatINSIGHT Cortex XSOAR integration enables security teams to utilize the features and functionality of the Insight solution with their existing Cortex XSOAR deployment. The integration leverages Insight’s fully RESTful APIs to interact with the Insight backend to introduce specific data sets into Cortex XSOAR. This document contains all the necessary information to configure, install, and use the integration.
For more information about the Cortex XSOAR integration visit the Insight help documentation here: https://insight.gigamon.com/help/api/apidocs-demisto

## Configure Gigamon ThreatINSIGHT on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Gigamon ThreatINSIGHT.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Token | True |
    | First Fetch Time | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Incident Filter: Account UUID (Optional) | False |
    | Maximum incidents in each fetch each run | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### insight-get-sensors
***
Get a list of all sensors.


#### Base Command

`insight-get-sensors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_uuid | UUID of account to filter by. | Optional | 
| account_code | Account code to fiilter by. | Optional | 
| sensor_id | ID of the sensor to filter by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Sensors.created | date | Date when the sensor was created | 
| Insight.Sensors.city | string | City where the sensor is located | 
| Insight.Sensors.subdivison | string | State/Province where the sensor is located | 
| Insight.Sensors.sensor_id | string | ID code of the sensor | 
| Insight.Sensors.location | string | Latitude and longitude where the sensor is located | 
| Insight.Sensors.tags | string | Labels added for this sensor | 
| Insight.Sensors.country | string | Country where the sensor is located | 
| Insight.Sensors.account_code | string | ID code of the customer account | 
| Insight.Sensors.updated | date | Date when the sensor was last updated | 
| Insight.Sensors.pcap_enabled | boolean | If PCAP is enabled on the sensor \(true/false\) | 

#### Command example
```!insight-get-sensors```
#### Context Example
```json
{
    "Insight": {
        "Sensors": [
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2021-12-17T20:40:54.348Z",
                "disabled": "2022-03-28T18:18:46.826Z",
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm1",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2021-12-17T20:40:54.348Z"
            },
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-03-28T18:17:37.696Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm2",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-03-28T18:17:37.696Z"
            },
            {
                "account_code": "tma",
                "admin": null,
                "city": "Santa Clara",
                "country": "US",
                "created": "2022-05-02T19:45:36.987Z",
                "disabled": null,
                "interfaces": null,
                "location": {
                    "latitude": 37.3541069,
                    "longitude": -121.955238
                },
                "pcap_enabled": false,
                "sensor_id": "tma2",
                "serial_number": null,
                "status": null,
                "subdivision": "CA",
                "tags": [
                    "Training Modern",
                    "ESXI 7.0"
                ],
                "updated": "2022-05-16T15:11:03.400Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_code|admin|city|country|created|disabled|interfaces|location|pcap_enabled|sensor_id|serial_number|status|subdivision|tags|updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gdm |  |  |  | 2021-12-17T20:40:54.348Z | 2022-03-28T18:18:46.826Z |  |  | false | gdm1 |  |  |  |  | 2021-12-17T20:40:54.348Z |
>| gdm |  |  |  | 2022-03-28T18:17:37.696Z |  |  |  | false | gdm2 |  |  |  |  | 2022-03-28T18:17:37.696Z |
>| tma |  | Santa Clara | US | 2022-05-02T19:45:36.987Z |  |  | latitude: 37.3541069<br/>longitude: -121.955238 | false | tma2 |  |  | CA | Training Modern,<br/>ESXI 7.0 | 2022-05-16T15:11:03.400Z |


#### Command example
```!insight-get-sensors account_uuid=0a7dae9g-6f74-4c75-78ef-856483763e1d4```
#### Context Example
```json
{
    "Insight": {
        "Sensors": [
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2021-12-17T20:40:54.348Z",
                "disabled": "2022-03-28T18:18:46.826Z",
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm1",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2021-12-17T20:40:54.348Z"
            },
            {
                "account_code": "gdm",
                "admin": null,
                "city": null,
                "country": null,
                "created": "2022-03-28T18:17:37.696Z",
                "disabled": null,
                "interfaces": null,
                "location": null,
                "pcap_enabled": false,
                "sensor_id": "gdm2",
                "serial_number": null,
                "status": null,
                "subdivision": null,
                "tags": [],
                "updated": "2022-03-28T18:17:37.696Z"
            },
            {
                "account_code": "tma",
                "admin": null,
                "city": "Santa Clara",
                "country": "US",
                "created": "2022-05-02T19:45:36.987Z",
                "disabled": null,
                "interfaces": null,
                "location": {
                    "latitude": 37.3541069,
                    "longitude": -121.955238
                },
                "pcap_enabled": false,
                "sensor_id": "tma2",
                "serial_number": null,
                "status": null,
                "subdivision": "CA",
                "tags": [
                    "Training Modern",
                    "ESXI 7.0"
                ],
                "updated": "2022-05-16T15:11:03.400Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_code|admin|city|country|created|disabled|interfaces|location|pcap_enabled|sensor_id|serial_number|status|subdivision|tags|updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| gdm |  |  |  | 2021-12-17T20:40:54.348Z | 2022-03-28T18:18:46.826Z |  |  | false | gdm1 |  |  |  |  | 2021-12-17T20:40:54.348Z |
>| gdm |  |  |  | 2022-03-28T18:17:37.696Z |  |  |  | false | gdm2 |  |  |  |  | 2022-03-28T18:17:37.696Z |
>| tma |  | Santa Clara | US | 2022-05-02T19:45:36.987Z |  |  | latitude: 37.3541069<br/>longitude: -121.955238 | false | tma2 |  |  | CA | Training Modern,<br/>ESXI 7.0 | 2022-05-16T15:11:03.400Z |


### insight-get-devices
***
Get a list of all devices.


#### Base Command

`insight-get-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Filter devices based on when they were seen. | Optional | 
| end_date | Filter devices based on when they were seen. | Optional | 
| cidr | Filter devices that are under a specific CIDR. | Optional | 
| sensor_id | Filter devices that were observed by a specific sensor. | Optional | 
| traffic_direction | Filter devices that have been noted to only have a certain directionality of traffic ("external" vs "internal"). | Optional | 
| sort_by | Sort output by: "ip", "internal", "external". | Optional | 
| sort_direction | Sort direction ("asc" vs "desc"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Devices.date | date | Date when the device was first seen | 
| Insight.Devices.external | boolean | If external traffic has been observed for this device | 
| Insight.Devices.internal | boolean | If internal traffic has been observed for this device | 
| Insight.Devices.ip_address | string | IP address of the device | 
| Insight.Devices.sensor_id | string | ID code of the sensor | 

#### Command example
```!insight-get-devices start_date=2019-01-01T00:00:00.000Z end_date=2019-01-31T23:59:59.999Z```
#### Context Example
```json
{
    "Insight": {
        "Devices": [
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.2"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.0.100"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.100"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.200"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.1"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "10.1.70.3"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.1.70.121"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.10.31.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.10.31.5"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.10.31.101"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "169.254.162.93"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "169.254.193.71"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.0.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.0.200"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "169.254.225.146"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.1.70"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.0.1"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.99.130"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.99.131"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.122.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.122.52"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.122.130"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.122.132"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.0.0.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.0.0.10"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.0.0.17"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.0.0.19"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.0.0.20"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.0.1.66"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.1.1.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.55"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.56"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.57"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.58"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.59"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.1.70.60"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.2.2.101"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.2.2.104"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.3.30.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.5.1.10"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.5.1.155"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.10.0.3"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.10.10.1"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.10.10.3"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.10.10.209"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.205.1.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.205.1.100"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "10.205.1.200"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.255.255.23"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "10.255.255.28"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "172.16.0.8"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "172.16.0.102"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.0.107"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.0.111"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.0.114"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.0.122"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.0.253"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.1.138"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.1"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.2"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.101"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.121"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.123"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "172.16.16.128"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.134"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.136"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.139"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.140"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.150"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "172.16.16.154"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.164"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.170"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.173"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.174"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.181"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.16.16.197"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.221"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.225"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.231"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.235"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.16.16.251"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "172.19.72.6"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "172.19.72.156"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "172.31.136.85"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.0.20"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.0.30"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.0.53"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.0.82"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "192.168.0.114"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.0.128"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.1.5"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.11.1"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.11.62"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "192.168.42.42"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.56.7"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.56.15"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.57.15"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.57.17"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "192.168.68.175"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "192.168.99.35"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.99.80"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.99.105"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.99.120"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.99.137"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.100.1"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.100.138"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.100.202"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.100.206"
            },
            {
                "date": null,
                "external": true,
                "internal": false,
                "ip_address": "192.168.122.145"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.200.1"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.200.4"
            },
            {
                "date": null,
                "external": true,
                "internal": true,
                "ip_address": "192.168.200.95"
            },
            {
                "date": null,
                "external": false,
                "internal": true,
                "ip_address": "192.168.200.254"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|date|external|internal|ip_address|
>|---|---|---|---|
>|  | true | true | 10.1.70.2 |
>|  | true | true | 192.168.0.100 |
>|  | true | true | 10.1.70.100 |
>|  | true | true | 10.1.70.200 |
>|  | true | true | 10.1.70.1 |
>|  | true | false | 10.1.70.3 |
>|  | false | true | 10.1.70.121 |
>|  | true | true | 10.10.31.1 |
>|  | true | true | 10.10.31.5 |
>|  | true | true | 10.10.31.101 |
>|  | false | true | 169.254.162.93 |
>|  | false | true | 169.254.193.71 |
>|  | false | true | 192.168.0.1 |
>|  | true | true | 192.168.0.200 |
>|  | false | true | 169.254.225.146 |
>|  | true | true | 10.1.1.70 |
>|  | false | true | 172.16.0.1 |
>|  | false | true | 172.16.99.130 |
>|  | false | true | 172.16.99.131 |
>|  | false | true | 192.168.122.1 |
>|  | true | true | 192.168.122.52 |
>|  | true | true | 192.168.122.130 |
>|  | true | true | 192.168.122.132 |
>|  | false | true | 10.0.0.1 |
>|  | true | true | 10.0.0.10 |
>|  | true | true | 10.0.0.17 |
>|  | true | true | 10.0.0.19 |
>|  | true | true | 10.0.0.20 |
>|  | false | true | 10.0.1.66 |
>|  | false | true | 10.1.1.1 |
>|  | true | true | 10.1.70.55 |
>|  | true | true | 10.1.70.56 |
>|  | true | true | 10.1.70.57 |
>|  | true | true | 10.1.70.58 |
>|  | true | true | 10.1.70.59 |
>|  | true | true | 10.1.70.60 |
>|  | false | true | 10.2.2.101 |
>|  | false | true | 10.2.2.104 |
>|  | false | true | 10.3.30.1 |
>|  | true | true | 10.5.1.10 |
>|  | true | true | 10.5.1.155 |
>|  | false | true | 10.10.0.3 |
>|  | false | true | 10.10.10.1 |
>|  | false | true | 10.10.10.3 |
>|  | true | true | 10.10.10.209 |
>|  | false | true | 10.205.1.1 |
>|  | true | true | 10.205.1.100 |
>|  | true | true | 10.205.1.200 |
>|  | false | true | 10.255.255.23 |
>|  | false | true | 10.255.255.28 |
>|  | true | true | 172.16.0.8 |
>|  | true | true | 172.16.0.102 |
>|  | true | false | 172.16.0.107 |
>|  | false | true | 172.16.0.111 |
>|  | false | true | 172.16.0.114 |
>|  | true | false | 172.16.0.122 |
>|  | false | true | 172.16.0.253 |
>|  | false | true | 172.16.1.138 |
>|  | true | false | 172.16.16.1 |
>|  | false | true | 172.16.16.2 |
>|  | false | true | 172.16.16.101 |
>|  | false | true | 172.16.16.121 |
>|  | true | false | 172.16.16.123 |
>|  | true | true | 172.16.16.128 |
>|  | true | false | 172.16.16.134 |
>|  | true | false | 172.16.16.136 |
>|  | false | true | 172.16.16.139 |
>|  | false | true | 172.16.16.140 |
>|  | false | true | 172.16.16.150 |
>|  | true | true | 172.16.16.154 |
>|  | false | true | 172.16.16.164 |
>|  | true | false | 172.16.16.170 |
>|  | false | true | 172.16.16.173 |
>|  | true | false | 172.16.16.174 |
>|  | false | true | 172.16.16.181 |
>|  | true | false | 172.16.16.197 |
>|  | false | true | 172.16.16.221 |
>|  | false | true | 172.16.16.225 |
>|  | false | true | 172.16.16.231 |
>|  | false | true | 172.16.16.235 |
>|  | false | true | 172.16.16.251 |
>|  | false | true | 172.19.72.6 |
>|  | true | true | 172.19.72.156 |
>|  | true | false | 172.31.136.85 |
>|  | false | true | 192.168.0.20 |
>|  | false | true | 192.168.0.30 |
>|  | false | true | 192.168.0.53 |
>|  | false | true | 192.168.0.82 |
>|  | true | false | 192.168.0.114 |
>|  | false | true | 192.168.0.128 |
>|  | false | true | 192.168.1.5 |
>|  | false | true | 192.168.11.1 |
>|  | false | true | 192.168.11.62 |
>|  | true | false | 192.168.42.42 |
>|  | false | true | 192.168.56.7 |
>|  | true | true | 192.168.56.15 |
>|  | true | true | 192.168.57.15 |
>|  | true | true | 192.168.57.17 |
>|  | true | false | 192.168.68.175 |
>|  | true | false | 192.168.99.35 |
>|  | true | true | 192.168.99.80 |
>|  | false | true | 192.168.99.105 |
>|  | false | true | 192.168.99.120 |
>|  | true | true | 192.168.99.137 |
>|  | false | true | 192.168.100.1 |
>|  | false | true | 192.168.100.138 |
>|  | false | true | 192.168.100.202 |
>|  | true | true | 192.168.100.206 |
>|  | true | false | 192.168.122.145 |
>|  | false | true | 192.168.200.1 |
>|  | true | true | 192.168.200.4 |
>|  | true | true | 192.168.200.95 |
>|  | false | true | 192.168.200.254 |


### insight-get-tasks
***
Get a list of all the PCAP tasks.


#### Base Command

`insight-get-tasks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_uuid | Filter to a specific task. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Tasks.task_uuid | string | Unique ID of the task | 
| Insight.Tasks.actual_start_time | date | Date when the task actually ended | 
| Insight.Tasks.requested_start_time | date | Requested date for the task start | 
| Insight.Tasks.updated_email | string | Email address of the user that updated the task | 
| Insight.Tasks.created_uuid | string | Unique ID of the user that created the task | 
| Insight.Tasks.created | date | Date when the task was created | 
| Insight.Tasks.name | string | Name of the task | 
| Insight.Tasks.status | string | Current status of the task | 
| Insight.Tasks.created_email | string | Email address of the user that created the task | 
| Insight.Tasks.updated_uuid | string | Unique ID of the user that updated the task | 
| Insight.Tasks.bpf | string | Berkeley Packet Filter for the task | 
| Insight.Tasks.actual_end_time | date | Date when the task actually ended | 
| Insight.Tasks.account_code | string | ID code of the customer account | 
| Insight.Tasks.requested_end_time | date | Requested date for the task end | 
| Insight.Tasks.updated | date | Date when the task was updated | 
| Insight.Tasks.description | string | Description of the task | 
| Insight.Tasks.has_files | boolean | If this task has files \(true/false\) | 
| Insight.Tasks.sensor_ids | string | Sensors this task is running on | 
| Insight.Tasks.files | string | Files captured for this task | 

### insight-create-task
***
Create a new PCAP task.


#### Base Command

`insight-create-task`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the task. | Required | 
| account_uuid | Account where the task will be created. | Required | 
| description | A description for the task. | Required | 
| bpf | The Berkeley Packet Filter for capture filtering. | Required | 
| requested_start_date | The date the task will become active. (2019-01-30T00:00:00.000Z). | Required | 
| requested_end_date | The date the task will become inactive. (2019-12-31T23:59:59.000Z). | Required | 
| sensor_ids | Sensor IDs on which this task will run (separate multiple accounts by comma). | Required | 


#### Context Output

There is no context output for this command.
### insight-get-detections
***
Get a list of detections.


#### Base Command

`insight-get-detections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | Filter to a specific rule. | Optional | 
| account_uuid | For those with access to multiple accounts, specify a single account to return results from. | Optional | 
| status | Filter by detection status: active / resolved. | Optional | 
| device_ip | Device IP to filter by. | Optional | 
| sensor_id | Sensor ID to filter by. | Optional | 
| muted | List detections that a user muted: true / false. | Optional | 
| muted_device | List detections for muted devices: true / false. | Optional | 
| muted_rule | List detections for muted rules. | Optional | 
| include | Include additional information in the response (rules). Possible values are: rules. | Optional | 
| created_or_shared_start_date | Created or shared start date to filter by (inclusive). | Optional | 
| created_or_shared_end_date | Created or shared start date to filter by (exclusive). | Optional | 
| sort_by | Sort output by: "ip", "internal", "external". | Optional | 
| sort_order | Sort direction ("asc" vs "desc"). | Optional | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. Default is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Detections.muted_rule | boolean | Is this rule muted \(true/false\) | 
| Insight.Detections.created | date | Date when the detection was created | 
| Insight.Detections.account_uuid | unknown | Unique ID of the account for this detection | 
| Insight.Detections.resolution_timestamp | date | Date when the detection was resolved | 
| Insight.Detections.first_seen | date | Date when the detection was first seen | 
| Insight.Detections.muted | boolean | If the detection is muted or not \(true/false\) | 
| Insight.Detections.resolution | string | Resolution type | 
| Insight.Detections.muted_user_uuid | string | Unique ID of the user that muted the detection | 
| Insight.Detections.last_seen | date | Date when the detection was last seen | 
| Insight.Detections.status | string | Current status of the detection | 
| Insight.Detections.resolution_user_uuid | string | Unique identifier of the user that resolved the detection | 
| Insight.Detections.resolution_comment | string | Comment entered when detection was resolved | 
| Insight.Detections.muted_comment | string | Comment entered when detection was muted | 
| Insight.Detections.sensor_id | string | ID code of the sensor | 
| Insight.Detections.rule_uuid | string | Unique ID of the rule for this detection | 
| Insight.Detections.updated | date | Date when the detection was last updated | 
| Insight.Detections.uuid | string | Unique ID of the detection | 
| Insight.Detections.muted_device_uuid | string | Unique ID of the muted device | 
| Insight.Detections.device_ip | string | IP address of the detection | 

#### Command example
```!insight-get-detections status=active include=rules created_or_shared_start_date=2019-01-01T00:00:00.000Z```
#### Context Example
```json
{
    "Insight": {
        "Detections": [
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-18T09:06:32.552668Z",
                "device_ip": "10.1.70.100",
                "event_count": 2,
                "first_seen": "2022-08-18T08:04:17.071000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T08:04:29.641000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.\r\n\r\nGigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by: \r\n      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.\r\n      2. Inspecting the downloaded application for malicious content.\r\n2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host. ",
                "rule_name": "HTML Application (HTA) Download",
                "rule_severity": "moderate",
                "rule_uuid": "f290eaaf-4748-4b35-a32e-0b88e1b0beee",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-18T09:06:32.552668Z",
                "username": null,
                "uuid": "af36de10-405b-4b39-92a1-1bfaeab2cb35"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:16:40.665678Z",
                "device_ip": "192.168.200.4",
                "event_count": 2,
                "first_seen": "2022-08-18T00:01:39.751000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:41.319000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "## Description\n\nThis logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n## Next Steps\n\n1.  Investigate the listed events to determine if the downloaded file was malicious.\n2.    Investigate the host for compromise.",
                "rule_name": "[Scenario 1] Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "1d315815-f7c5-4086-83f9-db2ced7d11df",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:16:40.665678Z",
                "username": null,
                "uuid": "044fbe86-c14e-40ed-845b-8fbc4f1a58ac"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:05:39.017559Z",
                "device_ip": "192.168.200.4",
                "event_count": 2,
                "first_seen": "2022-08-18T00:01:39.751000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:41.319000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:05:39.017559Z",
                "username": null,
                "uuid": "93465d3f-3fc7-429c-9740-f7ebddee5163"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:23:49.563723Z",
                "device_ip": "192.168.200.4",
                "event_count": 4,
                "first_seen": "2022-08-18T00:01:38.243000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:41.319000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Verifying that the file is an executable.\n    2. Verifying that the executable is malicious in nature.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Executable Binary or Script Downloaded as Image",
                "rule_severity": "moderate",
                "rule_uuid": "3a87c020-a7fe-48bf-b3fd-71aa40072f72",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:23:49.563723Z",
                "username": null,
                "uuid": "41acd215-9442-40a5-abc8-2ca0b50990de"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:22:41.816188Z",
                "device_ip": "192.168.200.4",
                "event_count": 4,
                "first_seen": "2022-08-18T00:01:38.243000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:41.319000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:22:41.816188Z",
                "username": null,
                "uuid": "abd08dab-7ad9-4a4d-a21b-b3920087ef62"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:25:41.618986Z",
                "device_ip": "192.168.200.4",
                "event_count": 85,
                "first_seen": "2022-08-18T00:01:28.919000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:02:42.089000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n## Next Steps\n1. Determine if this is a true positive by:\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n    2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 1] Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "43030c3b-da2a-4016-9035-5958aaea5b8e",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:25:41.618986Z",
                "username": null,
                "uuid": "1983ae93-2743-4269-8760-7b33be26d84e"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:22:41.816303Z",
                "device_ip": "192.168.200.95",
                "event_count": 3,
                "first_seen": "2022-08-18T00:01:15.015000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:27.709000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:22:41.816303Z",
                "username": null,
                "uuid": "a0eec2e4-29c7-4448-8427-9bccae764a00"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:23:49.563830Z",
                "device_ip": "192.168.200.95",
                "event_count": 3,
                "first_seen": "2022-08-18T00:01:15.015000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:27.709000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Verifying that the file is an executable.\n    2. Verifying that the executable is malicious in nature.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Executable Binary or Script Downloaded as Image",
                "rule_severity": "moderate",
                "rule_uuid": "3a87c020-a7fe-48bf-b3fd-71aa40072f72",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:23:49.563830Z",
                "username": null,
                "uuid": "b5c5d9af-5ac7-4f96-9ea1-da0f7eb91c7f"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:02:32.614759Z",
                "device_ip": "192.168.200.95",
                "event_count": 1,
                "first_seen": "2022-08-18T00:01:13.819000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:13.819000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. \n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "ETERNALBLUE Exploitation",
                "rule_severity": "high",
                "rule_uuid": "e5bb5bab-e6df-469b-9892-96bf4b84ecae",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:02:32.614759Z",
                "username": null,
                "uuid": "0d2faa27-e30b-4bc0-ae9c-e599211033c6"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:19:39.325120Z",
                "device_ip": "192.168.200.4",
                "event_count": 1,
                "first_seen": "2022-08-18T00:01:13.819000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:13.819000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "[Practical Packet Analysis] ETERNALBLUE Exploitation",
                "rule_severity": "moderate",
                "rule_uuid": "2ad64816-4a7b-41a6-b664-e1b1cf08683f",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:19:39.325120Z",
                "username": null,
                "uuid": "d44afbc6-3269-4935-b3de-b1b4a80734fc"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:19:39.325115Z",
                "device_ip": "192.168.200.95",
                "event_count": 1,
                "first_seen": "2022-08-18T00:01:13.819000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:13.819000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "[Practical Packet Analysis] ETERNALBLUE Exploitation",
                "rule_severity": "moderate",
                "rule_uuid": "2ad64816-4a7b-41a6-b664-e1b1cf08683f",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:19:39.325115Z",
                "username": null,
                "uuid": "d8bcf829-b2f0-4c8a-8826-532ead93a269"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:02:32.614764Z",
                "device_ip": "192.168.200.4",
                "event_count": 1,
                "first_seen": "2022-08-18T00:01:13.819000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:13.819000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. \n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "ETERNALBLUE Exploitation",
                "rule_severity": "high",
                "rule_uuid": "e5bb5bab-e6df-469b-9892-96bf4b84ecae",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:02:32.614764Z",
                "username": null,
                "uuid": "f858da39-b1d0-4f5e-a0d7-6db231d02ee4"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:25:41.619141Z",
                "device_ip": "192.168.200.95",
                "event_count": 80,
                "first_seen": "2022-08-18T00:01:08.657000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:02:39.463000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n## Next Steps\n1. Determine if this is a true positive by:\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n    2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 1] Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "43030c3b-da2a-4016-9035-5958aaea5b8e",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:25:41.619141Z",
                "username": null,
                "uuid": "2bc46b34-1e16-4c6c-8765-1e125bc18ad9"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:16:40.665746Z",
                "device_ip": "192.168.200.95",
                "event_count": 2,
                "first_seen": "2022-08-18T00:01:04.153000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:15.015000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "## Description\n\nThis logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n## Next Steps\n\n1.  Investigate the listed events to determine if the downloaded file was malicious.\n2.    Investigate the host for compromise.",
                "rule_name": "[Scenario 1] Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "1d315815-f7c5-4086-83f9-db2ced7d11df",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:16:40.665746Z",
                "username": null,
                "uuid": "b4d151a2-62e1-4927-864d-88b0196b2d45"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-18T01:05:39.017623Z",
                "device_ip": "192.168.200.95",
                "event_count": 2,
                "first_seen": "2022-08-18T00:01:04.153000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:15.015000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:05:39.017623Z",
                "username": null,
                "uuid": "fd605858-8ac7-4d8d-83d7-e07db41ded95"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-17T21:20:08.050684Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-17T08:04:36.650000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-17T08:04:36.650000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Discovery",
                "rule_confidence": "moderate",
                "rule_description": "This rule is designed to use the TCP Device Enumeration Observation event generated from a DMZ host that is not a scanner.  This would indicate a potentially compromised DMZ host scanning for other assets within the environment.  \n",
                "rule_name": "TCP Device Enumeration from DMZ host",
                "rule_severity": "moderate",
                "rule_uuid": "2d719a2b-4efb-4ba6-8555-0cd0f9636729",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-17T21:20:08.050684Z",
                "username": null,
                "uuid": "5f68bdef-199d-4c8b-a09b-9a8c37f27287"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-17T09:03:19.093979Z",
                "device_ip": "192.168.0.100",
                "event_count": 9,
                "first_seen": "2022-08-17T08:03:31.871000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-17T08:06:15.080000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client.\n\nGigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.\n   2. Validating that the external entity interacting with the device is unknown or unauthorized.\n   3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent.\n3. Quarantine the impacted device.\n4. Begin incident response procedures on the impacted device.\n5. Block traffic from attacker infrastructure.\n6. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers.",
                "rule_name": "CKnife Webshell Activity",
                "rule_severity": "high",
                "rule_uuid": "e9008859-c038-4bd5-a805-21efffd58355",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-17T09:03:19.093979Z",
                "username": null,
                "uuid": "8a058880-effd-42e3-8add-f4414c04a5a0"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-16T09:52:25.788277Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T08:36:18.896000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T08:36:18.896000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "PUA:Unauthorized Resource Use",
                "rule_confidence": "moderate",
                "rule_description": "This signature is intended to detect a cryptocurrency mining client performing a login or check-in to a cryptocurrency server. Cryptocurrency mining is a popular method of monetizing unauthorized access to hosts; however, it is also possible that this activity is the result of deliberate user behavior. To prevent unwanted expenditures of both power and system resources, Gigamon ATR recommends preventing cryptocurrency mining on company assets. \r\n\r\nGigamon ATR considers cryptocurrency mining to be moderate severity. While it poses no direct threat, it can indicate a compromised host. Gigamon ATR considers this detection moderate confidence due to the potential for these signatures to detect benign traffic with similar strings in the packet contents.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying the presence of coinmining software on the impacted asset.\r\n2. Determine if this is legitimate and approved use of coinmining software.\r\n3. Remove software if unnecessary.",
                "rule_name": "Cryptocurrency Mining Client Check-in",
                "rule_severity": "moderate",
                "rule_uuid": "bfcb4b76-96ef-4b33-9812-58158c871f99",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-16T09:52:25.788277Z",
                "username": null,
                "uuid": "a7313034-e244-41fc-8057-63d531d5f93c"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-16T09:17:17.985155Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T08:35:57.466000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T08:35:57.466000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the downloaded executable is malicious in nature. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Executable Binary or Script Download via Wget or cURL",
                "rule_severity": "high",
                "rule_uuid": "22c9ee01-2cbd-418d-bebf-c0cb3a175602",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-16T09:17:17.985155Z",
                "username": null,
                "uuid": "1d477bb2-80ba-4093-a222-1fae14732c76"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-16T09:22:15.675257Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T08:35:57.466000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T08:35:57.466000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-16T09:22:15.675257Z",
                "username": null,
                "uuid": "daf35d2b-a2a9-42c6-be0f-9bc2716bc275"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-16T00:51:35.213806Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T00:07:50.615000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T00:07:50.615000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n",
                "rule_name": "[Scenario 2] Executable Binary or Script from VPS",
                "rule_severity": "high",
                "rule_uuid": "bc828199-03c2-45cb-99ff-6d2713c4de60",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T00:51:35.213806Z",
                "username": null,
                "uuid": "2e4dc6c9-32c0-4c28-ae26-a69cf7e6e920"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-16T01:05:39.659469Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T00:07:50.615000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T00:07:50.615000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity.\n\n## Next Steps\n1.  Determine if this detection is a true positive by:\n    1.  Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the downloaded executable is malicious in nature.\n3.  Quarantine the impacted device.\n3.  Begin incident response procedures on the impacted device.\n4.  Block traffic to attacker infrastructure.\n5.  Search for other impacted devices.",
                "rule_name": "[Scenario 2] Executable Binary or Script Download via Wget or cURL",
                "rule_severity": "high",
                "rule_uuid": "ee538666-4159-4edf-b611-b507f40ac628",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T01:05:39.659469Z",
                "username": null,
                "uuid": "31e3697c-5413-408c-8144-d1bd02b41b5c"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-16T01:17:51.457732Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T00:07:50.615000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T00:07:50.615000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the downloaded executable is malicious in nature. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Executable Binary or Script Download via Wget or cURL",
                "rule_severity": "high",
                "rule_uuid": "22c9ee01-2cbd-418d-bebf-c0cb3a175602",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T01:17:51.457732Z",
                "username": null,
                "uuid": "9e84ba00-84b1-4f4c-bdc1-19c41fc7055f"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-16T01:22:51.107142Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T00:07:50.615000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T00:07:50.615000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T01:22:51.107142Z",
                "username": null,
                "uuid": "b4e5ec28-ea4f-40c3-930a-3df6c995be65"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-16T00:40:30.597455Z",
                "device_ip": "192.168.0.100",
                "event_count": 1,
                "first_seen": "2022-08-16T00:07:50.615000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T00:07:50.615000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "# Description\n\nThis logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\n\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 2] Executable or Script Download From External Python SimpleHTTPServer",
                "rule_severity": "moderate",
                "rule_uuid": "85360e3a-93a7-40d0-9db5-e1beafa80ef3",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T00:40:30.597455Z",
                "username": null,
                "uuid": "c267c098-ecf8-4f11-a17f-d69904180940"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:26:27.659327Z",
                "device_ip": "10.10.31.5",
                "event_count": 2,
                "first_seen": "2022-08-15T08:09:04.090000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:09.640000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n   2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n   3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "4727a9aa-8f71-487f-8fd6-c7f64d925443",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:26:27.659327Z",
                "username": null,
                "uuid": "94434482-6236-4808-a352-03d4e24e57cb"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:55:28.657534Z",
                "device_ip": "10.10.31.5",
                "event_count": 16,
                "first_seen": "2022-08-15T08:07:05.050000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:07:11.350000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "https://us-cert.cisa.gov/ncas/alerts/aa20-302a\n\nCISA MALWARE IOCs for Hospitals 28 OCT 2020",
                "rule_name": "Custom: CISA Malware IOCs",
                "rule_severity": "high",
                "rule_uuid": "c76aff9b-0f65-48d6-8312-cc5eac8b81ba",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:55:28.657534Z",
                "username": null,
                "uuid": "1ca3d158-7814-4b96-b217-520c8d6f5e48"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:26:27.659391Z",
                "device_ip": "10.10.31.101",
                "event_count": 2,
                "first_seen": "2022-08-15T08:06:09.940000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:06:40.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n   2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n   3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "4727a9aa-8f71-487f-8fd6-c7f64d925443",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:26:27.659391Z",
                "username": null,
                "uuid": "dd69a982-3c23-41b8-9979-2f8d627dcfea"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:56:16.861111Z",
                "device_ip": "10.10.31.5",
                "event_count": 7,
                "first_seen": "2022-08-15T08:05:59.860000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:08:48.190000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Evaluating the timing of the connections for beacon-like regularity.\n   2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Banking Trojan C2",
                "rule_severity": "high",
                "rule_uuid": "caab7261-ee92-4b78-aa29-4e47e89d7276",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:56:16.861111Z",
                "username": null,
                "uuid": "eed38f6d-bf69-47dd-a682-c62fb16d9279"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:36:27.103328Z",
                "device_ip": "10.10.31.101",
                "event_count": 1,
                "first_seen": "2022-08-15T08:05:57.000000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:05:57.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n   2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration",
                "rule_severity": "high",
                "rule_uuid": "732df04c-fdbc-4715-93ce-809a6b9ebd74",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:36:27.103328Z",
                "username": null,
                "uuid": "2ab0437d-2710-4d57-bc5e-a03bb98d70b3"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:36:27.102758Z",
                "device_ip": "10.10.31.5",
                "event_count": 51,
                "first_seen": "2022-08-15T08:04:18.640000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:33.210000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n   2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration",
                "rule_severity": "high",
                "rule_uuid": "732df04c-fdbc-4715-93ce-809a6b9ebd74",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:36:27.102758Z",
                "username": null,
                "uuid": "f6d6263d-60d8-4b09-a2f0-b154678710c7"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:22:32.829119Z",
                "device_ip": "10.10.31.5",
                "event_count": 4,
                "first_seen": "2022-08-15T08:04:07.640000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:09.640000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:22:32.829119Z",
                "username": null,
                "uuid": "84f3ad9d-2127-4058-9a4f-c5d0663b9d5e"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:06:25.361300Z",
                "device_ip": "10.10.31.5",
                "event_count": 2,
                "first_seen": "2022-08-15T08:04:07.640000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:08:48.860000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:06:25.361300Z",
                "username": null,
                "uuid": "b63c32ab-1fbd-4a62-8d56-b3cab04ae572"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:23:31.302329Z",
                "device_ip": "10.10.31.5",
                "event_count": 4,
                "first_seen": "2022-08-15T08:04:07.640000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:09.640000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Verifying that the file is an executable.\n    2. Verifying that the executable is malicious in nature.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Executable Binary or Script Downloaded as Image",
                "rule_severity": "moderate",
                "rule_uuid": "3a87c020-a7fe-48bf-b3fd-71aa40072f72",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:23:31.302329Z",
                "username": null,
                "uuid": "b6712cdf-aa4b-4273-98f0-85375ca65c79"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:55:28.657933Z",
                "device_ip": "10.10.31.101",
                "event_count": 30,
                "first_seen": "2022-08-15T08:03:54.200000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:04:01.796000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "https://us-cert.cisa.gov/ncas/alerts/aa20-302a\n\nCISA MALWARE IOCs for Hospitals 28 OCT 2020",
                "rule_name": "Custom: CISA Malware IOCs",
                "rule_severity": "high",
                "rule_uuid": "c76aff9b-0f65-48d6-8312-cc5eac8b81ba",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:55:28.657933Z",
                "username": null,
                "uuid": "8911815a-10aa-47e4-8338-d5c07e9010f3"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:02:22.138790Z",
                "device_ip": "10.10.31.101",
                "event_count": 2,
                "first_seen": "2022-08-15T08:03:33.441000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:04:04.280000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. \n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "ETERNALBLUE Exploitation",
                "rule_severity": "high",
                "rule_uuid": "e5bb5bab-e6df-469b-9892-96bf4b84ecae",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:02:22.138790Z",
                "username": null,
                "uuid": "2df53808-754e-4d93-a8e2-1a6033afcfc5"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:02:22.138785Z",
                "device_ip": "10.10.31.5",
                "event_count": 2,
                "first_seen": "2022-08-15T08:03:33.441000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:04:04.280000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. \n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "ETERNALBLUE Exploitation",
                "rule_severity": "high",
                "rule_uuid": "e5bb5bab-e6df-469b-9892-96bf4b84ecae",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:02:22.138785Z",
                "username": null,
                "uuid": "bbab40fb-fb14-46b4-8e3e-ea3972508436"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:56:16.860964Z",
                "device_ip": "10.10.31.101",
                "event_count": 42,
                "first_seen": "2022-08-15T08:03:22.840000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:33.040000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Evaluating the timing of the connections for beacon-like regularity.\n   2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Banking Trojan C2",
                "rule_severity": "high",
                "rule_uuid": "caab7261-ee92-4b78-aa29-4e47e89d7276",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:56:16.860964Z",
                "username": null,
                "uuid": "d24c95cb-b8cf-444e-97b8-3c9a308d909c"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:23:31.302405Z",
                "device_ip": "10.10.31.101",
                "event_count": 5,
                "first_seen": "2022-08-15T08:03:21.680000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:06:40.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Verifying that the file is an executable.\n    2. Verifying that the executable is malicious in nature.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Executable Binary or Script Downloaded as Image",
                "rule_severity": "moderate",
                "rule_uuid": "3a87c020-a7fe-48bf-b3fd-71aa40072f72",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:23:31.302405Z",
                "username": null,
                "uuid": "3b578973-28da-49dd-8d9a-104c6a1bd2d6"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:06:25.361348Z",
                "device_ip": "10.10.31.101",
                "event_count": 7,
                "first_seen": "2022-08-15T08:03:06.920000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:04:19.780000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:06:25.361348Z",
                "username": null,
                "uuid": "39ea26f2-32df-425f-8262-c5205dccd72f"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:15:22.218198Z",
                "device_ip": "10.10.31.101",
                "event_count": 4,
                "first_seen": "2022-08-15T08:03:06.920000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:03:06.980000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect the banking trojan, Emotet. This trojan is typically loaded as a second-stage payload by other malware\n\nGigamon ATR considers Emotet high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection low confidence as the detection logic may be triggered by a non-standard executable download\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.\n   2. Checking the affected asset for additional signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Emotet Banking Trojan Download",
                "rule_severity": "high",
                "rule_uuid": "1709f5a2-1563-4592-b430-16444399bb2a",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:15:22.218198Z",
                "username": null,
                "uuid": "881c0233-0cbf-41e7-905b-a89b07040e49"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T09:22:32.829201Z",
                "device_ip": "10.10.31.101",
                "event_count": 9,
                "first_seen": "2022-08-15T08:03:06.920000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:06:40.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:22:32.829201Z",
                "username": null,
                "uuid": "a235da48-db55-4d94-a46b-806ee059f4b2"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:56:17.660374Z",
                "device_ip": "10.10.31.101",
                "event_count": 4,
                "first_seen": "2022-08-15T08:03:06.920000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:03:06.980000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n   2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:56:17.660374Z",
                "username": null,
                "uuid": "a33a08ab-8a0c-450b-a4fa-bedc4693e4fd"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-15T08:54:16.927728Z",
                "device_ip": "10.10.31.101",
                "event_count": 1,
                "first_seen": "2022-08-15T08:02:16.710000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:02:16.710000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.\n\nGigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.\n   2. Checking the affected asset for additional signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "IcedID Banking Trojan Traffic",
                "rule_severity": "high",
                "rule_uuid": "c559f79e-0ca7-48ac-875b-fe226308ef4d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:54:16.927728Z",
                "username": null,
                "uuid": "98b177cc-f664-4774-b604-2900188846d6"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-15T01:23:17.831353Z",
                "device_ip": "10.10.10.209",
                "event_count": 7,
                "first_seen": "2022-08-15T00:01:04.226000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T00:01:08.494000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.\n\n\nICEBRG considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. ICEBRG considers this detection to be high confidence due to the uniqueness of the issuer of the SSL certificate used in the SSL requests by the trojan.\n\n## Next Steps\n1.  Determine if this is a true positive by:\n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3.  Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.\n2.  Quarantine the impacted device.\n3.  Begin incident response procedures on the impacted device.\n4.  Block traffic to attacker infrastructure.\n5.  Search for other impacted devices.",
                "rule_name": "[Scenario 1] Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "37e8edaa-ef2e-478b-a2cf-dfc85aae38c6",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-15T01:23:17.831353Z",
                "username": null,
                "uuid": "f36f0d29-79c2-4d47-b7a0-bb83300a1e76"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-15T01:26:03.536887Z",
                "device_ip": "10.10.10.209",
                "event_count": 5,
                "first_seen": "2022-08-15T00:01:04.194000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T00:01:07.886000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n## Next Steps\n1. Determine if this is a true positive by:\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n    2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 1] Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "43030c3b-da2a-4016-9035-5958aaea5b8e",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-15T01:26:03.536887Z",
                "username": null,
                "uuid": "c104ab27-ef99-453d-be03-76c2533cfa41"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-15T01:06:58.097153Z",
                "device_ip": "10.10.10.209",
                "event_count": 1,
                "first_seen": "2022-08-15T00:01:02.784000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T00:01:02.784000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-15T01:06:58.097153Z",
                "username": null,
                "uuid": "c74f1344-8bee-44f4-a3d9-e63750b338cf"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-15T01:17:03.046355Z",
                "device_ip": "10.10.10.209",
                "event_count": 1,
                "first_seen": "2022-08-15T00:01:02.784000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T00:01:02.784000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "## Description\n\nThis logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n## Next Steps\n\n1.  Investigate the listed events to determine if the downloaded file was malicious.\n2.    Investigate the host for compromise.",
                "rule_name": "[Scenario 1] Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "1d315815-f7c5-4086-83f9-db2ced7d11df",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-15T01:17:03.046355Z",
                "username": null,
                "uuid": "cbc002e9-f1be-4d67-bf54-f88b18b74aae"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:36:53.880438Z",
                "device_ip": "172.19.72.156",
                "event_count": 1,
                "first_seen": "2022-08-14T15:31:13.353000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:31:13.353000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Posture:Potentially Unauthorized Software or Device",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as \"Deep Web\" or \"Dark Web\" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  \r\n\r\nGigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. \r\n2. Ensure legitimate and approved use of Tor. \r\n3. Remove any unapproved software.",
                "rule_name": "Tor Connection Initialization",
                "rule_severity": "low",
                "rule_uuid": "7108db9b-6158-458f-b5b4-082f2ebae0f7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T16:36:53.880438Z",
                "username": null,
                "uuid": "94eac971-5634-47b6-999b-f5d146d70995"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:25:54.203300Z",
                "device_ip": "172.16.99.131",
                "event_count": 29,
                "first_seen": "2022-08-14T15:26:27.629000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:29.489000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Infection Vector",
                "rule_confidence": "low",
                "rule_description": "Important!",
                "rule_name": "Detection rule 2022.1.2",
                "rule_severity": "moderate",
                "rule_uuid": "421af990-caf9-4f4b-9fc5-339c53016e4b",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T04:25:57.681115Z",
                "username": null,
                "uuid": "474b1b9b-ceee-4f26-aa48-a65210648b00"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:02:49.594423Z",
                "device_ip": "172.16.99.130",
                "event_count": 28,
                "first_seen": "2022-08-14T15:26:27.629000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:29.489000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "low",
                "rule_description": "",
                "rule_name": "Test rule from investigation 2022.1.1",
                "rule_severity": "moderate",
                "rule_uuid": "e67675e7-3914-4d4c-9dd5-f239b4defae2",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T16:02:49.594423Z",
                "username": null,
                "uuid": "55656660-e58a-4852-9686-09a912027603"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:25:54.203294Z",
                "device_ip": "172.16.99.130",
                "event_count": 28,
                "first_seen": "2022-08-14T15:26:27.629000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:29.489000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Infection Vector",
                "rule_confidence": "low",
                "rule_description": "Important!",
                "rule_name": "Detection rule 2022.1.2",
                "rule_severity": "moderate",
                "rule_uuid": "421af990-caf9-4f4b-9fc5-339c53016e4b",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T16:25:54.203294Z",
                "username": null,
                "uuid": "618e2b02-50da-4f71-9cc5-72c4c3e3f96b"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:02:49.594435Z",
                "device_ip": "172.16.99.131",
                "event_count": 29,
                "first_seen": "2022-08-14T15:26:27.629000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:29.489000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "low",
                "rule_description": "",
                "rule_name": "Test rule from investigation 2022.1.1",
                "rule_severity": "moderate",
                "rule_uuid": "e67675e7-3914-4d4c-9dd5-f239b4defae2",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T04:02:54.645362Z",
                "username": null,
                "uuid": "d29a1724-a444-4eb6-aaf8-b91df442848e"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:36:53.880473Z",
                "device_ip": "10.1.1.70",
                "event_count": 5,
                "first_seen": "2022-08-14T15:25:30.730000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:25:43.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Posture:Potentially Unauthorized Software or Device",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as \"Deep Web\" or \"Dark Web\" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  \r\n\r\nGigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. \r\n2. Ensure legitimate and approved use of Tor. \r\n3. Remove any unapproved software.",
                "rule_name": "Tor Connection Initialization",
                "rule_severity": "low",
                "rule_uuid": "7108db9b-6158-458f-b5b4-082f2ebae0f7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T16:36:53.880473Z",
                "username": null,
                "uuid": "103104b4-01cf-4861-b880-61fa4a889b02"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T16:19:50.022011Z",
                "device_ip": "10.1.1.70",
                "event_count": 1,
                "first_seen": "2022-08-14T15:22:31.910000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:22:31.910000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. \n\n## Next Steps\n1. Determine if this detection is a true positive by checking the host for signs of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Pony or Hancitor Second Stage Download",
                "rule_severity": "high",
                "rule_uuid": "2d06c01f-5ae4-4346-8d6a-99926dcac4f1",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T16:19:50.022011Z",
                "username": null,
                "uuid": "b04694a9-4cf7-46c8-b754-6b7447e4640b"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T12:33:32.846970Z",
                "device_ip": "10.5.1.155",
                "event_count": 1,
                "first_seen": "2022-08-14T11:45:15.504000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:45:15.504000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect the download of PowerShell scripts from external HTTP servers. While commonly used in systems administration, PowerShell scripts are also used extensively by malware authors for post-exploitation actions.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence, as PowerShell is commonly used for administrative tasks.\n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Determining if the script retrieved was downloaded from a reputable source, and what the purpose may be. \n    2. Investigating the impacted device to determine what initiated the request.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "PowerShell Downloaded from External HTTP Server",
                "rule_severity": "high",
                "rule_uuid": "65ce4d1e-a7dd-4966-9db1-7c9e0efe6266",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T12:33:32.846970Z",
                "username": null,
                "uuid": "6f433af2-e5b2-4d0a-816b-6a5240f06146"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T12:22:35.437583Z",
                "device_ip": "10.5.1.155",
                "event_count": 1,
                "first_seen": "2022-08-14T11:45:15.504000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:45:15.504000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T12:22:35.437583Z",
                "username": null,
                "uuid": "9787bc91-27f1-4571-927b-400b8cb59fda"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T11:56:18.393538Z",
                "device_ip": "10.5.1.10",
                "event_count": 1,
                "first_seen": "2022-08-14T11:27:13.585000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:27:13.585000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n   2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T11:56:18.393538Z",
                "username": null,
                "uuid": "791a91d7-b03b-4065-9969-ca10578ea58b"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T12:06:25.119515Z",
                "device_ip": "10.5.1.10",
                "event_count": 1,
                "first_seen": "2022-08-14T11:27:13.585000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:27:13.585000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T12:06:25.119515Z",
                "username": null,
                "uuid": "a4059c82-f403-4973-8720-90a1e0374e71"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T10:07:15.228348Z",
                "device_ip": "10.5.1.10",
                "event_count": 3,
                "first_seen": "2022-08-14T09:38:30.063000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T09:38:37.403000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.\r\n\r\nGigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by: \r\n      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.\r\n      2. Inspecting the downloaded application for malicious content.\r\n2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host. ",
                "rule_name": "HTML Application (HTA) Download",
                "rule_severity": "moderate",
                "rule_uuid": "f290eaaf-4748-4b35-a32e-0b88e1b0beee",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T11:07:05.016847Z",
                "username": null,
                "uuid": "2a6804cf-21e2-4e1a-9c0a-fa570e18372f"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-14T10:01:42.754408Z",
                "device_ip": "10.5.1.10",
                "event_count": 3,
                "first_seen": "2022-08-14T09:38:30.063000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T09:38:37.403000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\r\n\r\nGigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by: \r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. \r\n    2. Verifying that the file is malicious in nature. \r\n2. Quarantine the impacted device. \r\n3. Begin incident response procedures on the impacted device. \r\n4. Block traffic to attacker infrastructure. \r\n5. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script from VPS",
                "rule_severity": "high",
                "rule_uuid": "e1bb1e78-3a25-4c52-b766-402b4f8e9849",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T11:02:01.974481Z",
                "username": null,
                "uuid": "60761125-50f2-40ae-93c9-264aa9001beb"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-14T09:19:28.421114Z",
                "device_ip": "192.168.42.42",
                "event_count": 9,
                "first_seen": "2022-08-14T08:21:42.931000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T08:21:49.641000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "[Practical Packet Analysis] ETERNALBLUE Exploitation",
                "rule_severity": "moderate",
                "rule_uuid": "2ad64816-4a7b-41a6-b664-e1b1cf08683f",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-14T09:19:28.421114Z",
                "username": null,
                "uuid": "78d662a1-1c73-4a94-bd36-f7fcf737866b"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-14T09:02:25.802064Z",
                "device_ip": "192.168.42.42",
                "event_count": 9,
                "first_seen": "2022-08-14T08:21:42.931000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T08:21:49.641000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exploitation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. \n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "rule_name": "ETERNALBLUE Exploitation",
                "rule_severity": "high",
                "rule_uuid": "e5bb5bab-e6df-469b-9892-96bf4b84ecae",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-14T09:02:25.802064Z",
                "username": null,
                "uuid": "c13d3a64-145b-4d62-998b-56ddf5c7d110"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-13T08:39:29.510389Z",
                "device_ip": "10.1.70.200",
                "event_count": 8,
                "first_seen": "2022-08-13T08:02:11.619000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-13T08:02:29.949000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Posture:Potentially Unauthorized Software or Device",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect active BitTorrent file sharing clients. BitTorrent is a peer-to-peer (P2P) client commonly used for sharing large files. Having the client installed on a host enables the user to both send and receive files. This activity frequently includes the download or sharing of illegally obtained files, and utilizes organizational resources to perform these activities, putting the company at risk.\n\nGigamon ATR considers BitTorrent activity low severity due to the relatively innocuous nature of the software that is installed. Gigamon ATR considers this detection high confidence due to the uniqueness of the user agent strings used in HTTP communications by BitTorrent clients. \n\n## Next Steps \n1. Determine if this detection is a true positive by inspecting the affected asset for installed BitTorrent client software.\n2. Determine legitimate business need for software.\n3. Remove software if unnecessary.",
                "rule_name": "BitTorrent Client User Agent",
                "rule_severity": "low",
                "rule_uuid": "7d561d24-7c6a-407f-b14b-8e60ca3b8432",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-13T08:39:29.510389Z",
                "username": null,
                "uuid": "f0d52187-76ba-44ee-a6be-117c3ca9ed1a"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-12T12:06:37.699746Z",
                "device_ip": "10.1.70.2",
                "event_count": 2,
                "first_seen": "2022-08-12T10:50:17.385000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T11:35:05.884000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T12:06:37.699746Z",
                "username": null,
                "uuid": "3a2865d1-9c56-44d2-8f85-cbbc9f977287"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-12T11:56:31.973596Z",
                "device_ip": "10.1.70.2",
                "event_count": 2,
                "first_seen": "2022-08-12T10:50:17.385000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T11:35:05.884000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n   2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T12:56:50.165404Z",
                "username": null,
                "uuid": "d44bb594-66b5-4870-9f2f-0e92b50bb28b"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-12T11:06:19.722504Z",
                "device_ip": "10.1.70.100",
                "event_count": 1,
                "first_seen": "2022-08-12T10:06:12.545000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T10:06:12.545000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "rule_name": "Executable Retrieved with Minimal HTTP Headers",
                "rule_severity": "high",
                "rule_uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T11:06:19.722504Z",
                "username": null,
                "uuid": "5f636b2d-ed21-4b5c-a9e0-bd6a0ef22eae"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-12T11:22:28.891753Z",
                "device_ip": "10.1.70.100",
                "event_count": 1,
                "first_seen": "2022-08-12T10:06:12.545000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T10:06:12.545000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T11:22:28.891753Z",
                "username": null,
                "uuid": "dc1caaf0-e6e5-4422-b608-967505ae3a7d"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-08-12T10:56:26.317162Z",
                "device_ip": "10.1.70.100",
                "event_count": 1,
                "first_seen": "2022-08-12T10:06:12.545000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T10:06:12.545000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n   2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T10:56:26.317162Z",
                "username": null,
                "uuid": "eec9ed6c-827c-4a7c-878b-b86f72d63933"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T01:31:52.543295Z",
                "device_ip": "10.1.70.2",
                "event_count": 270,
                "first_seen": "2022-08-12T00:32:10.735000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:45:11.918000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.\n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 5] Empire Default Profile",
                "rule_severity": "moderate",
                "rule_uuid": "5cd225d7-1a65-4653-a5be-ae034e5f2934",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:31:52.543295Z",
                "username": null,
                "uuid": "6dc52396-63ba-43bd-b099-a4e3a8bf97d9"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T01:55:04.660065Z",
                "device_ip": "10.1.70.2",
                "event_count": 270,
                "first_seen": "2022-08-12T00:32:10.735000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:45:11.918000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. \n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Empire Default Profile",
                "rule_severity": "high",
                "rule_uuid": "c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:55:04.660065Z",
                "username": null,
                "uuid": "ab734514-2873-4e5e-af72-24a366751a42"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T01:55:04.660257Z",
                "device_ip": "10.1.70.200",
                "event_count": 218,
                "first_seen": "2022-08-12T00:32:07.682000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:45:02.778000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. \n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Empire Default Profile",
                "rule_severity": "high",
                "rule_uuid": "c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:55:04.660257Z",
                "username": null,
                "uuid": "8a3f9a72-7667-49e6-a1f4-3585727fdff4"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T01:31:52.543472Z",
                "device_ip": "10.1.70.200",
                "event_count": 218,
                "first_seen": "2022-08-12T00:32:07.682000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:45:02.778000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.\n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 5] Empire Default Profile",
                "rule_severity": "moderate",
                "rule_uuid": "5cd225d7-1a65-4653-a5be-ae034e5f2934",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:31:52.543472Z",
                "username": null,
                "uuid": "b28ad275-fbc7-4dca-ba61-0057188735e5"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T00:54:19.952013Z",
                "device_ip": "10.1.70.100",
                "event_count": 663,
                "first_seen": "2022-08-12T00:02:37.562000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:45:10.714000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. \n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Empire Default Profile",
                "rule_severity": "high",
                "rule_uuid": "c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:55:04.660114Z",
                "username": null,
                "uuid": "965e1dac-7c69-4bc3-9397-5001017d9579"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T01:06:34.041019Z",
                "device_ip": "10.1.70.100",
                "event_count": 2,
                "first_seen": "2022-08-12T00:01:30.256000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:01:32.770000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.\r\n\r\nGigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by: \r\n      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.\r\n      2. Inspecting the downloaded application for malicious content.\r\n2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host. ",
                "rule_name": "HTML Application (HTA) Download",
                "rule_severity": "moderate",
                "rule_uuid": "f290eaaf-4748-4b35-a32e-0b88e1b0beee",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:06:34.041019Z",
                "username": null,
                "uuid": "1e7e7f73-65bc-4471-81d3-448d305bd4bf"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T00:52:19.828496Z",
                "device_ip": "10.1.70.100",
                "event_count": 2,
                "first_seen": "2022-08-12T00:01:30.256000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:01:32.770000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n",
                "rule_name": "[Scenario 2] Executable Binary or Script from VPS",
                "rule_severity": "high",
                "rule_uuid": "bc828199-03c2-45cb-99ff-6d2713c4de60",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T00:52:19.828496Z",
                "username": null,
                "uuid": "40caad00-4416-43b2-88fc-432e57151d2d"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-08-12T00:57:30.922646Z",
                "device_ip": "10.1.70.100",
                "event_count": 2,
                "first_seen": "2022-08-12T00:01:30.256000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:01:32.770000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect successful downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.\n\nGigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.\n      2. Inspecting the downloaded application for malicious content.\n2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host. ",
                "rule_name": "[Scenario 5] HTML Application (HTA) Download",
                "rule_severity": "moderate",
                "rule_uuid": "d1740713-b975-4341-a580-456511fcb784",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T00:57:30.922646Z",
                "username": null,
                "uuid": "ac2fb2c7-e88c-494a-bfc8-43b93c3cfff6"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-07-22T01:31:57.184214Z",
                "device_ip": "10.1.70.100",
                "event_count": 2734,
                "first_seen": "2022-07-22T00:02:37.325000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:45:10.714000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.\n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Scenario 5] Empire Default Profile",
                "rule_severity": "moderate",
                "rule_uuid": "5cd225d7-1a65-4653-a5be-ae034e5f2934",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:31:52.543341Z",
                "username": null,
                "uuid": "8d52c813-2d6f-47cc-add8-d5b59e811db2"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-07-17T09:19:29.880658Z",
                "device_ip": "10.1.1.70",
                "event_count": 10,
                "first_seen": "2022-07-17T08:12:14.946000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:10:28.642000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. \n\n## Next Steps\n1. Determine if this detection is a true positive by checking the host for signs of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "Pony or Hancitor Second Stage Download",
                "rule_severity": "high",
                "rule_uuid": "2d06c01f-5ae4-4346-8d6a-99926dcac4f1",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-14T12:19:29.311145Z",
                "username": null,
                "uuid": "2b8774ea-19dc-4182-a9af-88e7fa06dc71"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-07-17T08:45:59.122907Z",
                "device_ip": "10.1.1.70",
                "event_count": 10,
                "first_seen": "2022-07-17T08:12:14.946000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:10:28.642000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity.\n\n## Next Steps\n1. Determine if this detection is a true positive by checking the host for signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "rule_name": "[Practical Packet Analysis] Pony or Hancitor Second Stage Download",
                "rule_severity": "high",
                "rule_uuid": "9c5e5aae-b3fb-47e7-998e-4cce5f34dd1e",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-14T11:45:11.143096Z",
                "username": null,
                "uuid": "95f702ea-74f8-4c16-abd4-0c7d79d529aa"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-07-05T01:08:50.045379Z",
                "device_ip": "192.168.0.100",
                "event_count": 7,
                "first_seen": "2022-07-05T00:07:50.082000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T00:07:50.615000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable or Script Download From External Python SimpleHTTPServer",
                "rule_severity": "moderate",
                "rule_uuid": "fe4d55b4-7293-425a-b549-43a22472923d",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T01:08:42.415011Z",
                "username": null,
                "uuid": "2a0335ae-68e6-4476-9d39-46c2e5a4701e"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-06-19T12:08:24.984537Z",
                "device_ip": "10.5.1.10",
                "event_count": 81,
                "first_seen": "2022-06-19T10:58:29.675000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:27:13.585000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable or Script Download From External Python SimpleHTTPServer",
                "rule_severity": "moderate",
                "rule_uuid": "fe4d55b4-7293-425a-b549-43a22472923d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T12:08:25.484343Z",
                "username": null,
                "uuid": "b54300bd-3e1a-46de-9f88-aa29ae21159c"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-06-17T12:08:58.241290Z",
                "device_ip": "10.1.70.2",
                "event_count": 18,
                "first_seen": "2022-06-17T10:50:17.474000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T11:35:05.884000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable or Script Download From External Python SimpleHTTPServer",
                "rule_severity": "moderate",
                "rule_uuid": "fe4d55b4-7293-425a-b549-43a22472923d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T12:08:37.075688Z",
                "username": null,
                "uuid": "3ce07005-36b5-4ff6-bb2d-14a7c91b1c38"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-06-17T11:24:24.760619Z",
                "device_ip": "10.1.70.2",
                "event_count": 18,
                "first_seen": "2022-06-17T10:50:17.474000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T11:35:05.884000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Executable Binary or Script Downloaded from Dotted Quad",
                "rule_severity": "moderate",
                "rule_uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T12:22:48.306076Z",
                "username": null,
                "uuid": "f697ce30-249d-4390-9bb3-ce868e7747ab"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-06-17T11:08:43.148494Z",
                "device_ip": "10.1.70.100",
                "event_count": 9,
                "first_seen": "2022-06-17T10:06:12.636000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T10:06:12.545000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable or Script Download From External Python SimpleHTTPServer",
                "rule_severity": "moderate",
                "rule_uuid": "fe4d55b4-7293-425a-b549-43a22472923d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T11:08:20.965907Z",
                "username": null,
                "uuid": "ece847ff-84b8-4d7c-8426-1db6091dc15b"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-23T01:00:31.288913Z",
                "device_ip": "10.10.10.209",
                "event_count": 63,
                "first_seen": "2022-05-23T00:01:04.844000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T00:01:07.886000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\r\n\r\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\r\n\r\n## Next Steps\r\n1. Determine if this is a true positive by:\r\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\r\n    2. Checking the impacted asset for other indicators of compromise.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "db969564-0ba3-43d6-ad9e-67bf2509006f",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-15T01:00:51.885928Z",
                "username": null,
                "uuid": "534acb0f-a91a-41bc-966e-a6f41575c025"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-05-22T12:12:44.967357Z",
                "device_ip": "10.5.1.10",
                "event_count": 12,
                "first_seen": "2022-05-22T11:27:00.225000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:27:13.585000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\r\n\r\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "0968b4a7-a6b9-475c-86f8-72b1571100d6",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T12:12:24.734534Z",
                "username": null,
                "uuid": "2613e897-c156-472b-bca6-46af5a9e6123"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-05-20T12:12:35.814386Z",
                "device_ip": "10.1.70.2",
                "event_count": 24,
                "first_seen": "2022-05-20T10:50:17.820000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T11:35:05.884000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\r\n\r\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "0968b4a7-a6b9-475c-86f8-72b1571100d6",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T12:12:35.588771Z",
                "username": null,
                "uuid": "86b99672-9adc-4348-9ca0-918e589af2ae"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-05-20T11:12:19.813099Z",
                "device_ip": "10.1.70.100",
                "event_count": 12,
                "first_seen": "2022-05-20T10:06:12.980000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T10:06:12.545000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\r\n\r\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "0968b4a7-a6b9-475c-86f8-72b1571100d6",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-12T11:12:17.235368Z",
                "username": null,
                "uuid": "231a3afb-b622-4dc5-a985-9349f9df9ce9"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-20T01:39:40.367085Z",
                "device_ip": "10.1.70.100",
                "event_count": 13,
                "first_seen": "2022-05-20T00:32:03.720000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-12T00:32:03.763000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Discovery",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.\r\n\r\nGigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Search enumerated objects for signs of compromise. ",
                "rule_name": "Enumeration of Domain Objects",
                "rule_severity": "high",
                "rule_uuid": "810076e5-c11e-4948-856e-10e437c563e6",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-12T01:39:40.801265Z",
                "username": null,
                "uuid": "105f629b-c3cc-4111-934b-0c3e0cef019a"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-19T00:49:00.503514Z",
                "device_ip": "192.168.200.4",
                "event_count": 28,
                "first_seen": "2022-05-19T00:01:37.406000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:39.755000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. \n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "aadb155e-712f-481f-9680-482bab5a238d",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T00:47:26.404778Z",
                "username": null,
                "uuid": "9790bdda-e205-4c96-a520-5b8a08f2efa6"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-19T01:21:19.968177Z",
                "device_ip": "192.168.200.4",
                "event_count": 42,
                "first_seen": "2022-05-19T00:01:28.175000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:02:07.397000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Evaluating the timing of the connections for beacon-like regularity. \n    2. Checking the impacted asset for other indicators of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices.",
                "rule_name": "Trickbot Banking Trojan SSL Certificate",
                "rule_severity": "high",
                "rule_uuid": "2bbb5dda-ed01-4f49-888b-057233568abe",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:19:49.158236Z",
                "username": null,
                "uuid": "6272015d-1fc0-4b5b-8ee6-09f35c5df616"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-19T01:00:37.035468Z",
                "device_ip": "192.168.200.4",
                "event_count": 1182,
                "first_seen": "2022-05-19T00:01:28.082000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:02:42.089000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\r\n\r\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\r\n\r\n## Next Steps\r\n1. Determine if this is a true positive by:\r\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\r\n    2. Checking the impacted asset for other indicators of compromise.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "db969564-0ba3-43d6-ad9e-67bf2509006f",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:00:29.151728Z",
                "username": null,
                "uuid": "394e1165-21cb-4d49-83b8-8323f2ae9de5"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-19T00:49:00.503577Z",
                "device_ip": "192.168.200.95",
                "event_count": 28,
                "first_seen": "2022-05-19T00:01:21.258000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:27.709000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. \n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "aadb155e-712f-481f-9680-482bab5a238d",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T00:47:26.404839Z",
                "username": null,
                "uuid": "bb6b8db5-e515-48ca-80a9-54eebd0088cc"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-19T01:00:37.035633Z",
                "device_ip": "192.168.200.95",
                "event_count": 1126,
                "first_seen": "2022-05-19T00:01:12.058000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:02:39.463000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\r\n\r\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\r\n\r\n## Next Steps\r\n1. Determine if this is a true positive by:\r\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\r\n    2. Checking the impacted asset for other indicators of compromise.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "db969564-0ba3-43d6-ad9e-67bf2509006f",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:00:29.151899Z",
                "username": null,
                "uuid": "b44b4efd-4c2d-4bab-b8d9-9746b179a890"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-19T01:21:19.968206Z",
                "device_ip": "192.168.200.95",
                "event_count": 68,
                "first_seen": "2022-05-19T00:01:07.863000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T00:01:43.749000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Evaluating the timing of the connections for beacon-like regularity. \n    2. Checking the impacted asset for other indicators of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices.",
                "rule_name": "Trickbot Banking Trojan SSL Certificate",
                "rule_severity": "high",
                "rule_uuid": "2bbb5dda-ed01-4f49-888b-057233568abe",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-18T01:19:49.158271Z",
                "username": null,
                "uuid": "25db8bb5-80ee-4ddf-b780-6785817e316d"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-05-17T09:08:18.590866Z",
                "device_ip": "192.168.0.100",
                "event_count": 14,
                "first_seen": "2022-05-17T08:35:58.182000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T08:35:57.466000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable or Script Download From External Python SimpleHTTPServer",
                "rule_severity": "moderate",
                "rule_uuid": "fe4d55b4-7293-425a-b549-43a22472923d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-16T09:08:10.043529Z",
                "username": null,
                "uuid": "37eb67e0-f850-4d35-b445-87376afef760"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-10T14:12:19.315419Z",
                "device_ip": "172.16.99.131",
                "event_count": 10,
                "first_seen": "2022-05-10T01:01:06.508000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-09T01:01:05.585000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Infection Vector",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.\r\n\r\nKerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.\r\n\r\nGigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.\r\n\r\n## Next Steps\r\n1. Review the services requested and determine if an SPN should be set for a given account.\r\n2. Ensure that service accounts have strong passwords.\r\n3. Review Kerberos logs to determine the user account involved.\r\n4. Verify that the activity was authorized.",
                "rule_name": "Kerberoasting",
                "rule_severity": "high",
                "rule_uuid": "0de05ba7-d42d-4de8-aff7-aeb4350bb564",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-09T14:41:10.880491Z",
                "username": null,
                "uuid": "8498606c-aacb-464d-be8c-9e7ae0f02b2c"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-10T01:39:47.062453Z",
                "device_ip": "172.16.99.131",
                "event_count": 15,
                "first_seen": "2022-05-10T01:01:06.464000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-16T01:01:03.814000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Discovery",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.\r\n\r\nGigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Search enumerated objects for signs of compromise. ",
                "rule_name": "Enumeration of Domain Objects",
                "rule_severity": "high",
                "rule_uuid": "810076e5-c11e-4948-856e-10e437c563e6",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-16T01:39:55.066931Z",
                "username": null,
                "uuid": "518f9bbd-5f49-44f4-a1f5-e4e72c6a66d0"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-09T16:36:59.462092Z",
                "device_ip": "10.1.1.70",
                "event_count": 218,
                "first_seen": "2022-05-09T16:05:16.277000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:13:39.732000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Posture:Potentially Unauthorized Software or Device",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as \"Deep Web\" or \"Dark Web\" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  \r\n\r\nGigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. \r\n2. Ensure legitimate and approved use of Tor. \r\n3. Remove any unapproved software.",
                "rule_name": "Tor Connection Initialization",
                "rule_severity": "low",
                "rule_uuid": "7108db9b-6158-458f-b5b4-082f2ebae0f7",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-14T11:36:10.312240Z",
                "username": null,
                "uuid": "89bc0e5e-27ba-4f16-b5e7-0c82b673fc07"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "created": "2022-05-09T16:46:06.827787Z",
                "device_ip": "10.1.1.70",
                "event_count": 218,
                "first_seen": "2022-05-09T16:05:16.277000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T11:13:39.732000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Posture:Potentially Unauthorized Software or Device",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as \"Deep Web\" or \"Dark Web\" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.\n\nGigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.\n\n## Next Steps\n1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network.\n2. Ensure legitimate and approved use of Tor.\n3. Remove any unapproved software. ",
                "rule_name": "[Practical Packet Analysis] Tor Connection Initialization",
                "rule_severity": "low",
                "rule_uuid": "9d838451-4d33-4124-b6fd-43439217bee3",
                "sensor_id": "tma2",
                "status": "active",
                "updated": "2022-08-14T11:45:11.128439Z",
                "username": null,
                "uuid": "f5afe33f-119d-4e31-b159-1f75bf59d78f"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-06T09:13:50.225137Z",
                "device_ip": "192.168.0.100",
                "event_count": 171,
                "first_seen": "2022-04-06T08:03:30.713000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-17T08:06:15.080000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client. \n\nGigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n     1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.\n     2. Validating that the external entity interacting with the device is unknown or unauthorized. \n     3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic from attacker infrastructure. \n5. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers.",
                "rule_name": "CKnife Webshell HTTP POST Request",
                "rule_severity": "high",
                "rule_uuid": "0ffc3a5a-6cc5-443f-ad79-f94d99584b26",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-17T09:13:13.984895Z",
                "username": null,
                "uuid": "69eaef8a-e077-480a-9b71-21a7b410ef64"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T08:48:37.999636Z",
                "device_ip": "10.10.31.5",
                "event_count": 37,
                "first_seen": "2022-04-04T08:09:04.280000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:09.640000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. \n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "aadb155e-712f-481f-9680-482bab5a238d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:47:16.812989Z",
                "username": null,
                "uuid": "1ca5448c-fa10-4e8a-84e5-dbf5dde6e3f1"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T08:48:37.999696Z",
                "device_ip": "10.10.31.101",
                "event_count": 38,
                "first_seen": "2022-04-04T08:06:10.130000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:06:40.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. \n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "rule_name": "Trickbot Staging Download",
                "rule_severity": "high",
                "rule_uuid": "aadb155e-712f-481f-9680-482bab5a238d",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T08:47:16.813046Z",
                "username": null,
                "uuid": "598e2790-fc75-41df-a1ba-026582882173"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T09:20:07.852157Z",
                "device_ip": "10.10.31.5",
                "event_count": 133,
                "first_seen": "2022-04-04T08:06:00.050000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:08:48.190000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Evaluating the timing of the connections for beacon-like regularity. \n    2. Checking the impacted asset for other indicators of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices.",
                "rule_name": "Trickbot Banking Trojan SSL Certificate",
                "rule_severity": "high",
                "rule_uuid": "2bbb5dda-ed01-4f49-888b-057233568abe",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:19:27.919195Z",
                "username": null,
                "uuid": "c61d2389-df78-4daf-b8cc-b576f14df683"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T09:00:42.936731Z",
                "device_ip": "10.10.31.101",
                "event_count": 19,
                "first_seen": "2022-04-04T08:05:57.190000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:05:57.000000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\r\n\r\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\r\n\r\n## Next Steps\r\n1. Determine if this is a true positive by:\r\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\r\n    2. Checking the impacted asset for other indicators of compromise.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "db969564-0ba3-43d6-ad9e-67bf2509006f",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:00:17.058322Z",
                "username": null,
                "uuid": "b16c6b57-48fd-4bab-929a-12eb4708c7ca"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T09:00:42.936171Z",
                "device_ip": "10.10.31.5",
                "event_count": 966,
                "first_seen": "2022-04-04T08:04:18.830000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:33.210000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Exfiltration",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\r\n\r\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\r\n\r\n## Next Steps\r\n1. Determine if this is a true positive by:\r\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\r\n    2. Checking the impacted asset for other indicators of compromise.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Trickbot Data Exfiltration over SSL",
                "rule_severity": "high",
                "rule_uuid": "db969564-0ba3-43d6-ad9e-67bf2509006f",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:00:17.057770Z",
                "username": null,
                "uuid": "2ddf11c7-0c40-4c19-b687-a3c1db819e4f"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T09:20:07.852001Z",
                "device_ip": "10.10.31.101",
                "event_count": 782,
                "first_seen": "2022-04-04T08:03:23.030000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:09:33.040000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Evaluating the timing of the connections for beacon-like regularity. \n    2. Checking the impacted asset for other indicators of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices.",
                "rule_name": "Trickbot Banking Trojan SSL Certificate",
                "rule_severity": "high",
                "rule_uuid": "2bbb5dda-ed01-4f49-888b-057233568abe",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:19:27.919038Z",
                "username": null,
                "uuid": "3a275dc4-2313-4a0c-8b9f-fca2225e9a25"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T09:12:43.668174Z",
                "device_ip": "10.10.31.101",
                "event_count": 72,
                "first_seen": "2022-04-04T08:03:07.110000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:03:06.980000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": true,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Installation",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\r\n\r\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "rule_name": "Executable in Root of Web Directory",
                "rule_severity": "high",
                "rule_uuid": "0968b4a7-a6b9-475c-86f8-72b1571100d6",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:12:23.133734Z",
                "username": null,
                "uuid": "d728be03-1a73-4c06-865c-796693ba6c1a"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T09:24:53.016814Z",
                "device_ip": "10.10.31.101",
                "event_count": 18,
                "first_seen": "2022-04-04T08:02:16.900000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-15T08:02:16.710000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.\n\nGigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.\n    2. Checking the affected asset for additional signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "rule_name": "IcedID Banking Trojan HTTP GET Request",
                "rule_severity": "high",
                "rule_uuid": "3e8c54a6-1934-4517-b217-e98f342b6c5a",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T09:24:29.568416Z",
                "username": null,
                "uuid": "7fb23eec-2dad-49e1-ac92-7d3d9af7be98"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-04T04:12:10.667253Z",
                "device_ip": "172.16.99.131",
                "event_count": 18,
                "first_seen": "2022-04-03T15:26:13.757000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:28.279000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Infection Vector",
                "rule_confidence": "moderate",
                "rule_description": "This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.\r\n\r\nKerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.\r\n\r\nGigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.\r\n\r\n## Next Steps\r\n1. Review the services requested and determine if an SPN should be set for a given account.\r\n2. Ensure that service accounts have strong passwords.\r\n3. Review Kerberos logs to determine the user account involved.\r\n4. Verify that the activity was authorized.",
                "rule_name": "Kerberoasting",
                "rule_severity": "high",
                "rule_uuid": "0de05ba7-d42d-4de8-aff7-aeb4350bb564",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-15T04:12:50.365734Z",
                "username": null,
                "uuid": "1a126f5c-4e36-4de5-a9d2-7de7b17dd0c2"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-03T16:39:36.845325Z",
                "device_ip": "172.16.99.131",
                "event_count": 19,
                "first_seen": "2022-04-03T15:26:13.537000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:28.059000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Discovery",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.\r\n\r\nGigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Search enumerated objects for signs of compromise. ",
                "rule_name": "Enumeration of Domain Objects",
                "rule_severity": "high",
                "rule_uuid": "810076e5-c11e-4948-856e-10e437c563e6",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T16:39:59.129348Z",
                "username": null,
                "uuid": "d855248d-759f-4e74-91b8-e7f32b38d4ee"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-04-03T15:51:16.806362Z",
                "device_ip": "192.168.68.175",
                "event_count": 19,
                "first_seen": "2022-04-03T15:26:11.959000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-14T15:26:26.040000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Command and Control",
                "rule_confidence": "high",
                "rule_description": "This logic is intended to detect a Windows banner over ICMP. This Windows banner appears at the start of a reverse shell session over ICMP, often started with tools such as `icmpsh`. By using ICMP, attackers are often able to circumvent firewall protections.\r\n\r\nGigamon ATR considers a Windows banner over ICMP high severity, as it is indicative of successful malicious code execution. Gigamon ATR considers this detection high confidence due to the uniqueness of the Windows banner string in ICMP traffic.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by starting packet capture and investigating ICMP traffic produced by the impacted asset, looking for the presence of plaintext shell commands.\r\n2. Quarantine the impacted device.\r\n3. Search for other impacted devices.\r\n4. Block traffic to attacker infrastructure.\r\n5. Begin incident response procedures on the impacted device. ",
                "rule_name": "Windows Banner String in ICMP Request",
                "rule_severity": "high",
                "rule_uuid": "b73126a8-5cd1-4c2f-a0ef-ce12e02e4b31",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-14T15:50:39.389855Z",
                "username": null,
                "uuid": "fbd27f09-f355-4c5a-9126-556778c56e1c"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "created": "2022-03-31T11:40:03.229566Z",
                "device_ip": "10.1.70.100",
                "event_count": 58,
                "first_seen": "2022-03-31T10:37:03.949000Z",
                "hostname": null,
                "indicators": null,
                "last_seen": "2022-08-18T10:37:04.588000Z",
                "muted": false,
                "muted_comment": null,
                "muted_device_uuid": null,
                "muted_rule": false,
                "muted_timestamp": null,
                "muted_user_uuid": null,
                "resolution": null,
                "resolution_comment": null,
                "resolution_timestamp": null,
                "resolution_user_uuid": null,
                "rule_category": "Attack:Discovery",
                "rule_confidence": "low",
                "rule_description": "This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.\r\n\r\nGigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Search enumerated objects for signs of compromise. ",
                "rule_name": "Enumeration of Domain Objects",
                "rule_severity": "high",
                "rule_uuid": "810076e5-c11e-4948-856e-10e437c563e6",
                "sensor_id": "gdm2",
                "status": "active",
                "updated": "2022-08-18T11:39:57.030910Z",
                "username": null,
                "uuid": "bc7f2bc5-7ab2-487f-8197-6ee6a4390959"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_uuid|created|device_ip|event_count|first_seen|hostname|indicators|last_seen|muted|muted_comment|muted_device_uuid|muted_rule|muted_timestamp|muted_user_uuid|resolution|resolution_comment|resolution_timestamp|resolution_user_uuid|rule_category|rule_confidence|rule_description|rule_name|rule_severity|rule_uuid|sensor_id|status|updated|username|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-18T09:06:32.552668Z | 10.1.70.100 | 2 | 2022-08-18T08:04:17.071000Z |  |  | 2022-08-18T08:04:29.641000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.<br/><br/>Gigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.<br/>      2. Inspecting the downloaded application for malicious content.<br/>2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host.  | HTML Application (HTA) Download | moderate | f290eaaf-4748-4b35-a32e-0b88e1b0beee | gdm2 | active | 2022-08-18T09:06:32.552668Z |  | af36de10-405b-4b39-92a1-1bfaeab2cb35 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:16:40.665678Z | 192.168.200.4 | 2 | 2022-08-18T00:01:39.751000Z |  |  | 2022-08-18T00:01:41.319000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | ## Description<br/><br/>This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/>## Next Steps<br/><br/>1.  Investigate the listed events to determine if the downloaded file was malicious.<br/>2.    Investigate the host for compromise. | [Scenario 1] Executable Retrieved with Minimal HTTP Headers | high | 1d315815-f7c5-4086-83f9-db2ced7d11df | tma2 | active | 2022-08-18T01:16:40.665678Z |  | 044fbe86-c14e-40ed-845b-8fbc4f1a58ac |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:05:39.017559Z | 192.168.200.4 | 2 | 2022-08-18T00:01:39.751000Z |  |  | 2022-08-18T00:01:41.319000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | tma2 | active | 2022-08-18T01:05:39.017559Z |  | 93465d3f-3fc7-429c-9740-f7ebddee5163 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:23:49.563723Z | 192.168.200.4 | 4 | 2022-08-18T00:01:38.243000Z |  |  | 2022-08-18T00:01:41.319000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Verifying that the file is an executable.<br/>    2. Verifying that the executable is malicious in nature.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Executable Binary or Script Downloaded as Image | moderate | 3a87c020-a7fe-48bf-b3fd-71aa40072f72 | tma2 | active | 2022-08-18T01:23:49.563723Z |  | 41acd215-9442-40a5-abc8-2ca0b50990de |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:22:41.816188Z | 192.168.200.4 | 4 | 2022-08-18T00:01:38.243000Z |  |  | 2022-08-18T00:01:41.319000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | tma2 | active | 2022-08-18T01:22:41.816188Z |  | abd08dab-7ad9-4a4d-a21b-b3920087ef62 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:25:41.618986Z | 192.168.200.4 | 85 | 2022-08-18T00:01:28.919000Z |  |  | 2022-08-18T00:02:42.089000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 1] Trickbot Data Exfiltration over SSL | high | 43030c3b-da2a-4016-9035-5958aaea5b8e | tma2 | active | 2022-08-18T01:25:41.618986Z |  | 1983ae93-2743-4269-8760-7b33be26d84e |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:22:41.816303Z | 192.168.200.95 | 3 | 2022-08-18T00:01:15.015000Z |  |  | 2022-08-18T00:01:27.709000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | tma2 | active | 2022-08-18T01:22:41.816303Z |  | a0eec2e4-29c7-4448-8427-9bccae764a00 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:23:49.563830Z | 192.168.200.95 | 3 | 2022-08-18T00:01:15.015000Z |  |  | 2022-08-18T00:01:27.709000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Verifying that the file is an executable.<br/>    2. Verifying that the executable is malicious in nature.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Executable Binary or Script Downloaded as Image | moderate | 3a87c020-a7fe-48bf-b3fd-71aa40072f72 | tma2 | active | 2022-08-18T01:23:49.563830Z |  | b5c5d9af-5ac7-4f96-9ea1-da0f7eb91c7f |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:02:32.614759Z | 192.168.200.95 | 1 | 2022-08-18T00:01:13.819000Z |  |  | 2022-08-18T00:01:13.819000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. <br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | ETERNALBLUE Exploitation | high | e5bb5bab-e6df-469b-9892-96bf4b84ecae | tma2 | active | 2022-08-18T01:02:32.614759Z |  | 0d2faa27-e30b-4bc0-ae9c-e599211033c6 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:19:39.325120Z | 192.168.200.4 | 1 | 2022-08-18T00:01:13.819000Z |  |  | 2022-08-18T00:01:13.819000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | [Practical Packet Analysis] ETERNALBLUE Exploitation | moderate | 2ad64816-4a7b-41a6-b664-e1b1cf08683f | tma2 | active | 2022-08-18T01:19:39.325120Z |  | d44afbc6-3269-4935-b3de-b1b4a80734fc |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:19:39.325115Z | 192.168.200.95 | 1 | 2022-08-18T00:01:13.819000Z |  |  | 2022-08-18T00:01:13.819000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | [Practical Packet Analysis] ETERNALBLUE Exploitation | moderate | 2ad64816-4a7b-41a6-b664-e1b1cf08683f | tma2 | active | 2022-08-18T01:19:39.325115Z |  | d8bcf829-b2f0-4c8a-8826-532ead93a269 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:02:32.614764Z | 192.168.200.4 | 1 | 2022-08-18T00:01:13.819000Z |  |  | 2022-08-18T00:01:13.819000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. <br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | ETERNALBLUE Exploitation | high | e5bb5bab-e6df-469b-9892-96bf4b84ecae | tma2 | active | 2022-08-18T01:02:32.614764Z |  | f858da39-b1d0-4f5e-a0d7-6db231d02ee4 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:25:41.619141Z | 192.168.200.95 | 80 | 2022-08-18T00:01:08.657000Z |  |  | 2022-08-18T00:02:39.463000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 1] Trickbot Data Exfiltration over SSL | high | 43030c3b-da2a-4016-9035-5958aaea5b8e | tma2 | active | 2022-08-18T01:25:41.619141Z |  | 2bc46b34-1e16-4c6c-8765-1e125bc18ad9 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:16:40.665746Z | 192.168.200.95 | 2 | 2022-08-18T00:01:04.153000Z |  |  | 2022-08-18T00:01:15.015000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | ## Description<br/><br/>This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/>## Next Steps<br/><br/>1.  Investigate the listed events to determine if the downloaded file was malicious.<br/>2.    Investigate the host for compromise. | [Scenario 1] Executable Retrieved with Minimal HTTP Headers | high | 1d315815-f7c5-4086-83f9-db2ced7d11df | tma2 | active | 2022-08-18T01:16:40.665746Z |  | b4d151a2-62e1-4927-864d-88b0196b2d45 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-18T01:05:39.017623Z | 192.168.200.95 | 2 | 2022-08-18T00:01:04.153000Z |  |  | 2022-08-18T00:01:15.015000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | tma2 | active | 2022-08-18T01:05:39.017623Z |  | fd605858-8ac7-4d8d-83d7-e07db41ded95 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-17T21:20:08.050684Z | 192.168.0.100 | 1 | 2022-08-17T08:04:36.650000Z |  |  | 2022-08-17T08:04:36.650000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | moderate | This rule is designed to use the TCP Device Enumeration Observation event generated from a DMZ host that is not a scanner.  This would indicate a potentially compromised DMZ host scanning for other assets within the environment.  <br/> | TCP Device Enumeration from DMZ host | moderate | 2d719a2b-4efb-4ba6-8555-0cd0f9636729 | gdm2 | active | 2022-08-17T21:20:08.050684Z |  | 5f68bdef-199d-4c8b-a09b-9a8c37f27287 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-17T09:03:19.093979Z | 192.168.0.100 | 9 | 2022-08-17T08:03:31.871000Z |  |  | 2022-08-17T08:06:15.080000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client.<br/><br/>Gigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.<br/>   2. Validating that the external entity interacting with the device is unknown or unauthorized.<br/>   3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent.<br/>3. Quarantine the impacted device.<br/>4. Begin incident response procedures on the impacted device.<br/>5. Block traffic from attacker infrastructure.<br/>6. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers. | CKnife Webshell Activity | high | e9008859-c038-4bd5-a805-21efffd58355 | gdm2 | active | 2022-08-17T09:03:19.093979Z |  | 8a058880-effd-42e3-8add-f4414c04a5a0 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-16T09:52:25.788277Z | 192.168.0.100 | 1 | 2022-08-16T08:36:18.896000Z |  |  | 2022-08-16T08:36:18.896000Z | false |  |  | false |  |  |  |  |  |  | PUA:Unauthorized Resource Use | moderate | This signature is intended to detect a cryptocurrency mining client performing a login or check-in to a cryptocurrency server. Cryptocurrency mining is a popular method of monetizing unauthorized access to hosts; however, it is also possible that this activity is the result of deliberate user behavior. To prevent unwanted expenditures of both power and system resources, Gigamon ATR recommends preventing cryptocurrency mining on company assets. <br/><br/>Gigamon ATR considers cryptocurrency mining to be moderate severity. While it poses no direct threat, it can indicate a compromised host. Gigamon ATR considers this detection moderate confidence due to the potential for these signatures to detect benign traffic with similar strings in the packet contents.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying the presence of coinmining software on the impacted asset.<br/>2. Determine if this is legitimate and approved use of coinmining software.<br/>3. Remove software if unnecessary. | Cryptocurrency Mining Client Check-in | moderate | bfcb4b76-96ef-4b33-9812-58158c871f99 | gdm2 | active | 2022-08-16T09:52:25.788277Z |  | a7313034-e244-41fc-8057-63d531d5f93c |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-16T09:17:17.985155Z | 192.168.0.100 | 1 | 2022-08-16T08:35:57.466000Z |  |  | 2022-08-16T08:35:57.466000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the downloaded executable is malicious in nature. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Executable Binary or Script Download via Wget or cURL | high | 22c9ee01-2cbd-418d-bebf-c0cb3a175602 | gdm2 | active | 2022-08-16T09:17:17.985155Z |  | 1d477bb2-80ba-4093-a222-1fae14732c76 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-16T09:22:15.675257Z | 192.168.0.100 | 1 | 2022-08-16T08:35:57.466000Z |  |  | 2022-08-16T08:35:57.466000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | gdm2 | active | 2022-08-16T09:22:15.675257Z |  | daf35d2b-a2a9-42c6-be0f-9bc2716bc275 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-16T00:51:35.213806Z | 192.168.0.100 | 1 | 2022-08-16T00:07:50.615000Z |  |  | 2022-08-16T00:07:50.615000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/> | [Scenario 2] Executable Binary or Script from VPS | high | bc828199-03c2-45cb-99ff-6d2713c4de60 | tma2 | active | 2022-08-16T00:51:35.213806Z |  | 2e4dc6c9-32c0-4c28-ae26-a69cf7e6e920 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-16T01:05:39.659469Z | 192.168.0.100 | 1 | 2022-08-16T00:07:50.615000Z |  |  | 2022-08-16T00:07:50.615000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity.<br/><br/>## Next Steps<br/>1.  Determine if this detection is a true positive by:<br/>    1.  Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the downloaded executable is malicious in nature.<br/>3.  Quarantine the impacted device.<br/>3.  Begin incident response procedures on the impacted device.<br/>4.  Block traffic to attacker infrastructure.<br/>5.  Search for other impacted devices. | [Scenario 2] Executable Binary or Script Download via Wget or cURL | high | ee538666-4159-4edf-b611-b507f40ac628 | tma2 | active | 2022-08-16T01:05:39.659469Z |  | 31e3697c-5413-408c-8144-d1bd02b41b5c |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-16T01:17:51.457732Z | 192.168.0.100 | 1 | 2022-08-16T00:07:50.615000Z |  |  | 2022-08-16T00:07:50.615000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the downloaded executable is malicious in nature. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Executable Binary or Script Download via Wget or cURL | high | 22c9ee01-2cbd-418d-bebf-c0cb3a175602 | tma2 | active | 2022-08-16T01:17:51.457732Z |  | 9e84ba00-84b1-4f4c-bdc1-19c41fc7055f |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-16T01:22:51.107142Z | 192.168.0.100 | 1 | 2022-08-16T00:07:50.615000Z |  |  | 2022-08-16T00:07:50.615000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | tma2 | active | 2022-08-16T01:22:51.107142Z |  | b4e5ec28-ea4f-40c3-930a-3df6c995be65 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-16T00:40:30.597455Z | 192.168.0.100 | 1 | 2022-08-16T00:07:50.615000Z |  |  | 2022-08-16T00:07:50.615000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | # Description<br/><br/>This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 2] Executable or Script Download From External Python SimpleHTTPServer | moderate | 85360e3a-93a7-40d0-9db5-e1beafa80ef3 | tma2 | active | 2022-08-16T00:40:30.597455Z |  | c267c098-ecf8-4f11-a17f-d69904180940 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:26:27.659327Z | 10.10.31.5 | 2 | 2022-08-15T08:09:04.090000Z |  |  | 2022-08-15T08:09:09.640000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>   2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>   3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Staging Download | high | 4727a9aa-8f71-487f-8fd6-c7f64d925443 | gdm2 | active | 2022-08-15T09:26:27.659327Z |  | 94434482-6236-4808-a352-03d4e24e57cb |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:55:28.657534Z | 10.10.31.5 | 16 | 2022-08-15T08:07:05.050000Z |  |  | 2022-08-15T08:07:11.350000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | https://us-cert.cisa.gov/ncas/alerts/aa20-302a<br/><br/>CISA MALWARE IOCs for Hospitals 28 OCT 2020 | Custom: CISA Malware IOCs | high | c76aff9b-0f65-48d6-8312-cc5eac8b81ba | gdm2 | active | 2022-08-15T08:55:28.657534Z |  | 1ca3d158-7814-4b96-b217-520c8d6f5e48 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:26:27.659391Z | 10.10.31.101 | 2 | 2022-08-15T08:06:09.940000Z |  |  | 2022-08-15T08:06:40.000000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>   2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>   3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Staging Download | high | 4727a9aa-8f71-487f-8fd6-c7f64d925443 | gdm2 | active | 2022-08-15T09:26:27.659391Z |  | dd69a982-3c23-41b8-9979-2f8d627dcfea |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:56:16.861111Z | 10.10.31.5 | 7 | 2022-08-15T08:05:59.860000Z |  |  | 2022-08-15T08:08:48.190000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Evaluating the timing of the connections for beacon-like regularity.<br/>   2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Banking Trojan C2 | high | caab7261-ee92-4b78-aa29-4e47e89d7276 | gdm2 | active | 2022-08-15T08:56:16.861111Z |  | eed38f6d-bf69-47dd-a682-c62fb16d9279 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:36:27.103328Z | 10.10.31.101 | 1 | 2022-08-15T08:05:57.000000Z |  |  | 2022-08-15T08:05:57.000000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>   2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration | high | 732df04c-fdbc-4715-93ce-809a6b9ebd74 | gdm2 | active | 2022-08-15T08:36:27.103328Z |  | 2ab0437d-2710-4d57-bc5e-a03bb98d70b3 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:36:27.102758Z | 10.10.31.5 | 51 | 2022-08-15T08:04:18.640000Z |  |  | 2022-08-15T08:09:33.210000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>   2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration | high | 732df04c-fdbc-4715-93ce-809a6b9ebd74 | gdm2 | active | 2022-08-15T08:36:27.102758Z |  | f6d6263d-60d8-4b09-a2f0-b154678710c7 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:22:32.829119Z | 10.10.31.5 | 4 | 2022-08-15T08:04:07.640000Z |  |  | 2022-08-15T08:09:09.640000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | gdm2 | active | 2022-08-15T09:22:32.829119Z |  | 84f3ad9d-2127-4058-9a4f-c5d0663b9d5e |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:06:25.361300Z | 10.10.31.5 | 2 | 2022-08-15T08:04:07.640000Z |  |  | 2022-08-15T08:08:48.860000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | gdm2 | active | 2022-08-15T09:06:25.361300Z |  | b63c32ab-1fbd-4a62-8d56-b3cab04ae572 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:23:31.302329Z | 10.10.31.5 | 4 | 2022-08-15T08:04:07.640000Z |  |  | 2022-08-15T08:09:09.640000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Verifying that the file is an executable.<br/>    2. Verifying that the executable is malicious in nature.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Executable Binary or Script Downloaded as Image | moderate | 3a87c020-a7fe-48bf-b3fd-71aa40072f72 | gdm2 | active | 2022-08-15T09:23:31.302329Z |  | b6712cdf-aa4b-4273-98f0-85375ca65c79 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:55:28.657933Z | 10.10.31.101 | 30 | 2022-08-15T08:03:54.200000Z |  |  | 2022-08-15T08:04:01.796000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | https://us-cert.cisa.gov/ncas/alerts/aa20-302a<br/><br/>CISA MALWARE IOCs for Hospitals 28 OCT 2020 | Custom: CISA Malware IOCs | high | c76aff9b-0f65-48d6-8312-cc5eac8b81ba | gdm2 | active | 2022-08-15T08:55:28.657933Z |  | 8911815a-10aa-47e4-8338-d5c07e9010f3 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:02:22.138790Z | 10.10.31.101 | 2 | 2022-08-15T08:03:33.441000Z |  |  | 2022-08-15T08:04:04.280000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. <br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | ETERNALBLUE Exploitation | high | e5bb5bab-e6df-469b-9892-96bf4b84ecae | gdm2 | active | 2022-08-15T09:02:22.138790Z |  | 2df53808-754e-4d93-a8e2-1a6033afcfc5 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:02:22.138785Z | 10.10.31.5 | 2 | 2022-08-15T08:03:33.441000Z |  |  | 2022-08-15T08:04:04.280000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. <br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | ETERNALBLUE Exploitation | high | e5bb5bab-e6df-469b-9892-96bf4b84ecae | gdm2 | active | 2022-08-15T09:02:22.138785Z |  | bbab40fb-fb14-46b4-8e3e-ea3972508436 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:56:16.860964Z | 10.10.31.101 | 42 | 2022-08-15T08:03:22.840000Z |  |  | 2022-08-15T08:09:33.040000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Evaluating the timing of the connections for beacon-like regularity.<br/>   2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Banking Trojan C2 | high | caab7261-ee92-4b78-aa29-4e47e89d7276 | gdm2 | active | 2022-08-15T08:56:16.860964Z |  | d24c95cb-b8cf-444e-97b8-3c9a308d909c |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:23:31.302405Z | 10.10.31.101 | 5 | 2022-08-15T08:03:21.680000Z |  |  | 2022-08-15T08:06:40.000000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Verifying that the file is an executable.<br/>    2. Verifying that the executable is malicious in nature.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Executable Binary or Script Downloaded as Image | moderate | 3a87c020-a7fe-48bf-b3fd-71aa40072f72 | gdm2 | active | 2022-08-15T09:23:31.302405Z |  | 3b578973-28da-49dd-8d9a-104c6a1bd2d6 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:06:25.361348Z | 10.10.31.101 | 7 | 2022-08-15T08:03:06.920000Z |  |  | 2022-08-15T08:04:19.780000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | gdm2 | active | 2022-08-15T09:06:25.361348Z |  | 39ea26f2-32df-425f-8262-c5205dccd72f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:15:22.218198Z | 10.10.31.101 | 4 | 2022-08-15T08:03:06.920000Z |  |  | 2022-08-15T08:03:06.980000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect the banking trojan, Emotet. This trojan is typically loaded as a second-stage payload by other malware<br/><br/>Gigamon ATR considers Emotet high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection low confidence as the detection logic may be triggered by a non-standard executable download<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>   2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Emotet Banking Trojan Download | high | 1709f5a2-1563-4592-b430-16444399bb2a | gdm2 | active | 2022-08-15T09:15:22.218198Z |  | 881c0233-0cbf-41e7-905b-a89b07040e49 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T09:22:32.829201Z | 10.10.31.101 | 9 | 2022-08-15T08:03:06.920000Z |  |  | 2022-08-15T08:06:40.000000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | gdm2 | active | 2022-08-15T09:22:32.829201Z |  | a235da48-db55-4d94-a46b-806ee059f4b2 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:56:17.660374Z | 10.10.31.101 | 4 | 2022-08-15T08:03:06.920000Z |  |  | 2022-08-15T08:03:06.980000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>   2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a | gdm2 | active | 2022-08-15T08:56:17.660374Z |  | a33a08ab-8a0c-450b-a4fa-bedc4693e4fd |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-15T08:54:16.927728Z | 10.10.31.101 | 1 | 2022-08-15T08:02:16.710000Z |  |  | 2022-08-15T08:02:16.710000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.<br/><br/>Gigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>   2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | IcedID Banking Trojan Traffic | high | c559f79e-0ca7-48ac-875b-fe226308ef4d | gdm2 | active | 2022-08-15T08:54:16.927728Z |  | 98b177cc-f664-4774-b604-2900188846d6 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-15T01:23:17.831353Z | 10.10.10.209 | 7 | 2022-08-15T00:01:04.226000Z |  |  | 2022-08-15T00:01:08.494000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.<br/><br/><br/>ICEBRG considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. ICEBRG considers this detection to be high confidence due to the uniqueness of the issuer of the SSL certificate used in the SSL requests by the trojan.<br/><br/>## Next Steps<br/>1.  Determine if this is a true positive by:<br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3.  Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.<br/>2.  Quarantine the impacted device.<br/>3.  Begin incident response procedures on the impacted device.<br/>4.  Block traffic to attacker infrastructure.<br/>5.  Search for other impacted devices. | [Scenario 1] Trickbot Staging Download | high | 37e8edaa-ef2e-478b-a2cf-dfc85aae38c6 | tma2 | active | 2022-08-15T01:23:17.831353Z |  | f36f0d29-79c2-4d47-b7a0-bb83300a1e76 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-15T01:26:03.536887Z | 10.10.10.209 | 5 | 2022-08-15T00:01:04.194000Z |  |  | 2022-08-15T00:01:07.886000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 1] Trickbot Data Exfiltration over SSL | high | 43030c3b-da2a-4016-9035-5958aaea5b8e | tma2 | active | 2022-08-15T01:26:03.536887Z |  | c104ab27-ef99-453d-be03-76c2533cfa41 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-15T01:06:58.097153Z | 10.10.10.209 | 1 | 2022-08-15T00:01:02.784000Z |  |  | 2022-08-15T00:01:02.784000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | tma2 | active | 2022-08-15T01:06:58.097153Z |  | c74f1344-8bee-44f4-a3d9-e63750b338cf |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-15T01:17:03.046355Z | 10.10.10.209 | 1 | 2022-08-15T00:01:02.784000Z |  |  | 2022-08-15T00:01:02.784000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | ## Description<br/><br/>This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/>## Next Steps<br/><br/>1.  Investigate the listed events to determine if the downloaded file was malicious.<br/>2.    Investigate the host for compromise. | [Scenario 1] Executable Retrieved with Minimal HTTP Headers | high | 1d315815-f7c5-4086-83f9-db2ced7d11df | tma2 | active | 2022-08-15T01:17:03.046355Z |  | cbc002e9-f1be-4d67-bf54-f88b18b74aae |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:36:53.880438Z | 172.19.72.156 | 1 | 2022-08-14T15:31:13.353000Z |  |  | 2022-08-14T15:31:13.353000Z | false |  |  | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  <br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. <br/>2. Ensure legitimate and approved use of Tor. <br/>3. Remove any unapproved software. | Tor Connection Initialization | low | 7108db9b-6158-458f-b5b4-082f2ebae0f7 | gdm2 | active | 2022-08-14T16:36:53.880438Z |  | 94eac971-5634-47b6-999b-f5d146d70995 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:25:54.203300Z | 172.16.99.131 | 29 | 2022-08-14T15:26:27.629000Z |  |  | 2022-08-14T15:26:29.489000Z | false |  |  | false |  |  |  |  |  |  | Attack:Infection Vector | low | Important! | Detection rule 2022.1.2 | moderate | 421af990-caf9-4f4b-9fc5-339c53016e4b | gdm2 | active | 2022-08-15T04:25:57.681115Z |  | 474b1b9b-ceee-4f26-aa48-a65210648b00 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:02:49.594423Z | 172.16.99.130 | 28 | 2022-08-14T15:26:27.629000Z |  |  | 2022-08-14T15:26:29.489000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | low |  | Test rule from investigation 2022.1.1 | moderate | e67675e7-3914-4d4c-9dd5-f239b4defae2 | gdm2 | active | 2022-08-14T16:02:49.594423Z |  | 55656660-e58a-4852-9686-09a912027603 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:25:54.203294Z | 172.16.99.130 | 28 | 2022-08-14T15:26:27.629000Z |  |  | 2022-08-14T15:26:29.489000Z | false |  |  | false |  |  |  |  |  |  | Attack:Infection Vector | low | Important! | Detection rule 2022.1.2 | moderate | 421af990-caf9-4f4b-9fc5-339c53016e4b | gdm2 | active | 2022-08-14T16:25:54.203294Z |  | 618e2b02-50da-4f71-9cc5-72c4c3e3f96b |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:02:49.594435Z | 172.16.99.131 | 29 | 2022-08-14T15:26:27.629000Z |  |  | 2022-08-14T15:26:29.489000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | low |  | Test rule from investigation 2022.1.1 | moderate | e67675e7-3914-4d4c-9dd5-f239b4defae2 | gdm2 | active | 2022-08-15T04:02:54.645362Z |  | d29a1724-a444-4eb6-aaf8-b91df442848e |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:36:53.880473Z | 10.1.1.70 | 5 | 2022-08-14T15:25:30.730000Z |  |  | 2022-08-14T15:25:43.000000Z | false |  |  | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  <br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. <br/>2. Ensure legitimate and approved use of Tor. <br/>3. Remove any unapproved software. | Tor Connection Initialization | low | 7108db9b-6158-458f-b5b4-082f2ebae0f7 | gdm2 | active | 2022-08-14T16:36:53.880473Z |  | 103104b4-01cf-4861-b880-61fa4a889b02 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T16:19:50.022011Z | 10.1.1.70 | 1 | 2022-08-14T15:22:31.910000Z |  |  | 2022-08-14T15:22:31.910000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. <br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by checking the host for signs of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Pony or Hancitor Second Stage Download | high | 2d06c01f-5ae4-4346-8d6a-99926dcac4f1 | gdm2 | active | 2022-08-14T16:19:50.022011Z |  | b04694a9-4cf7-46c8-b754-6b7447e4640b |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T12:33:32.846970Z | 10.5.1.155 | 1 | 2022-08-14T11:45:15.504000Z |  |  | 2022-08-14T11:45:15.504000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect the download of PowerShell scripts from external HTTP servers. While commonly used in systems administration, PowerShell scripts are also used extensively by malware authors for post-exploitation actions.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence, as PowerShell is commonly used for administrative tasks.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Determining if the script retrieved was downloaded from a reputable source, and what the purpose may be. <br/>    2. Investigating the impacted device to determine what initiated the request.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | PowerShell Downloaded from External HTTP Server | high | 65ce4d1e-a7dd-4966-9db1-7c9e0efe6266 | gdm2 | active | 2022-08-14T12:33:32.846970Z |  | 6f433af2-e5b2-4d0a-816b-6a5240f06146 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T12:22:35.437583Z | 10.5.1.155 | 1 | 2022-08-14T11:45:15.504000Z |  |  | 2022-08-14T11:45:15.504000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | gdm2 | active | 2022-08-14T12:22:35.437583Z |  | 9787bc91-27f1-4571-927b-400b8cb59fda |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T11:56:18.393538Z | 10.5.1.10 | 1 | 2022-08-14T11:27:13.585000Z |  |  | 2022-08-14T11:27:13.585000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>   2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a | gdm2 | active | 2022-08-14T11:56:18.393538Z |  | 791a91d7-b03b-4065-9969-ca10578ea58b |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T12:06:25.119515Z | 10.5.1.10 | 1 | 2022-08-14T11:27:13.585000Z |  |  | 2022-08-14T11:27:13.585000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | gdm2 | active | 2022-08-14T12:06:25.119515Z |  | a4059c82-f403-4973-8720-90a1e0374e71 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T10:07:15.228348Z | 10.5.1.10 | 3 | 2022-08-14T09:38:30.063000Z |  |  | 2022-08-14T09:38:37.403000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.<br/><br/>Gigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.<br/>      2. Inspecting the downloaded application for malicious content.<br/>2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host.  | HTML Application (HTA) Download | moderate | f290eaaf-4748-4b35-a32e-0b88e1b0beee | gdm2 | active | 2022-08-14T11:07:05.016847Z |  | 2a6804cf-21e2-4e1a-9c0a-fa570e18372f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-14T10:01:42.754408Z | 10.5.1.10 | 3 | 2022-08-14T09:38:30.063000Z |  |  | 2022-08-14T09:38:37.403000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the file is malicious in nature. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Executable Binary or Script from VPS | high | e1bb1e78-3a25-4c52-b766-402b4f8e9849 | gdm2 | active | 2022-08-14T11:02:01.974481Z |  | 60761125-50f2-40ae-93c9-264aa9001beb |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-14T09:19:28.421114Z | 192.168.42.42 | 9 | 2022-08-14T08:21:42.931000Z |  |  | 2022-08-14T08:21:49.641000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | [Practical Packet Analysis] ETERNALBLUE Exploitation | moderate | 2ad64816-4a7b-41a6-b664-e1b1cf08683f | tma2 | active | 2022-08-14T09:19:28.421114Z |  | 78d662a1-1c73-4a94-bd36-f7fcf737866b |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-14T09:02:25.802064Z | 192.168.42.42 | 9 | 2022-08-14T08:21:42.931000Z |  |  | 2022-08-14T08:21:49.641000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exploitation | moderate | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. <br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | ETERNALBLUE Exploitation | high | e5bb5bab-e6df-469b-9892-96bf4b84ecae | tma2 | active | 2022-08-14T09:02:25.802064Z |  | c13d3a64-145b-4d62-998b-56ddf5c7d110 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-13T08:39:29.510389Z | 10.1.70.200 | 8 | 2022-08-13T08:02:11.619000Z |  |  | 2022-08-13T08:02:29.949000Z | false |  |  | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect active BitTorrent file sharing clients. BitTorrent is a peer-to-peer (P2P) client commonly used for sharing large files. Having the client installed on a host enables the user to both send and receive files. This activity frequently includes the download or sharing of illegally obtained files, and utilizes organizational resources to perform these activities, putting the company at risk.<br/><br/>Gigamon ATR considers BitTorrent activity low severity due to the relatively innocuous nature of the software that is installed. Gigamon ATR considers this detection high confidence due to the uniqueness of the user agent strings used in HTTP communications by BitTorrent clients. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by inspecting the affected asset for installed BitTorrent client software.<br/>2. Determine legitimate business need for software.<br/>3. Remove software if unnecessary. | BitTorrent Client User Agent | low | 7d561d24-7c6a-407f-b14b-8e60ca3b8432 | gdm2 | active | 2022-08-13T08:39:29.510389Z |  | f0d52187-76ba-44ee-a6be-117c3ca9ed1a |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-12T12:06:37.699746Z | 10.1.70.2 | 2 | 2022-08-12T10:50:17.385000Z |  |  | 2022-08-12T11:35:05.884000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | gdm2 | active | 2022-08-12T12:06:37.699746Z |  | 3a2865d1-9c56-44d2-8f85-cbbc9f977287 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-12T11:56:31.973596Z | 10.1.70.2 | 2 | 2022-08-12T10:50:17.385000Z |  |  | 2022-08-12T11:35:05.884000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>   2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a | gdm2 | active | 2022-08-12T12:56:50.165404Z |  | d44bb594-66b5-4870-9f2f-0e92b50bb28b |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-12T11:06:19.722504Z | 10.1.70.100 | 1 | 2022-08-12T10:06:12.545000Z |  |  | 2022-08-12T10:06:12.545000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | Executable Retrieved with Minimal HTTP Headers | high | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 | gdm2 | active | 2022-08-12T11:06:19.722504Z |  | 5f636b2d-ed21-4b5c-a9e0-bd6a0ef22eae |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-12T11:22:28.891753Z | 10.1.70.100 | 1 | 2022-08-12T10:06:12.545000Z |  |  | 2022-08-12T10:06:12.545000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | gdm2 | active | 2022-08-12T11:22:28.891753Z |  | dc1caaf0-e6e5-4422-b608-967505ae3a7d |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-08-12T10:56:26.317162Z | 10.1.70.100 | 1 | 2022-08-12T10:06:12.545000Z |  |  | 2022-08-12T10:06:12.545000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>   2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a | gdm2 | active | 2022-08-12T10:56:26.317162Z |  | eec9ed6c-827c-4a7c-878b-b86f72d63933 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T01:31:52.543295Z | 10.1.70.2 | 270 | 2022-08-12T00:32:10.735000Z |  |  | 2022-08-12T00:45:11.918000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.<br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 5] Empire Default Profile | moderate | 5cd225d7-1a65-4653-a5be-ae034e5f2934 | tma2 | active | 2022-08-12T01:31:52.543295Z |  | 6dc52396-63ba-43bd-b099-a4e3a8bf97d9 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T01:55:04.660065Z | 10.1.70.2 | 270 | 2022-08-12T00:32:10.735000Z |  |  | 2022-08-12T00:45:11.918000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. <br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Empire Default Profile | high | c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6 | tma2 | active | 2022-08-12T01:55:04.660065Z |  | ab734514-2873-4e5e-af72-24a366751a42 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T01:55:04.660257Z | 10.1.70.200 | 218 | 2022-08-12T00:32:07.682000Z |  |  | 2022-08-12T00:45:02.778000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. <br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Empire Default Profile | high | c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6 | tma2 | active | 2022-08-12T01:55:04.660257Z |  | 8a3f9a72-7667-49e6-a1f4-3585727fdff4 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T01:31:52.543472Z | 10.1.70.200 | 218 | 2022-08-12T00:32:07.682000Z |  |  | 2022-08-12T00:45:02.778000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.<br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 5] Empire Default Profile | moderate | 5cd225d7-1a65-4653-a5be-ae034e5f2934 | tma2 | active | 2022-08-12T01:31:52.543472Z |  | b28ad275-fbc7-4dca-ba61-0057188735e5 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T00:54:19.952013Z | 10.1.70.100 | 663 | 2022-08-12T00:02:37.562000Z |  |  | 2022-08-12T00:45:10.714000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. <br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Empire Default Profile | high | c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6 | tma2 | active | 2022-08-12T01:55:04.660114Z |  | 965e1dac-7c69-4bc3-9397-5001017d9579 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T01:06:34.041019Z | 10.1.70.100 | 2 | 2022-08-12T00:01:30.256000Z |  |  | 2022-08-12T00:01:32.770000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.<br/><br/>Gigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.<br/>      2. Inspecting the downloaded application for malicious content.<br/>2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host.  | HTML Application (HTA) Download | moderate | f290eaaf-4748-4b35-a32e-0b88e1b0beee | tma2 | active | 2022-08-12T01:06:34.041019Z |  | 1e7e7f73-65bc-4471-81d3-448d305bd4bf |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T00:52:19.828496Z | 10.1.70.100 | 2 | 2022-08-12T00:01:30.256000Z |  |  | 2022-08-12T00:01:32.770000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/> | [Scenario 2] Executable Binary or Script from VPS | high | bc828199-03c2-45cb-99ff-6d2713c4de60 | tma2 | active | 2022-08-12T00:52:19.828496Z |  | 40caad00-4416-43b2-88fc-432e57151d2d |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-08-12T00:57:30.922646Z | 10.1.70.100 | 2 | 2022-08-12T00:01:30.256000Z |  |  | 2022-08-12T00:01:32.770000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect successful downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.<br/><br/>Gigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.<br/>      2. Inspecting the downloaded application for malicious content.<br/>2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host.  | [Scenario 5] HTML Application (HTA) Download | moderate | d1740713-b975-4341-a580-456511fcb784 | tma2 | active | 2022-08-12T00:57:30.922646Z |  | ac2fb2c7-e88c-494a-bfc8-43b93c3cfff6 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-07-22T01:31:57.184214Z | 10.1.70.100 | 2734 | 2022-07-22T00:02:37.325000Z |  |  | 2022-08-12T00:45:10.714000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.<br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Scenario 5] Empire Default Profile | moderate | 5cd225d7-1a65-4653-a5be-ae034e5f2934 | tma2 | active | 2022-08-12T01:31:52.543341Z |  | 8d52c813-2d6f-47cc-add8-d5b59e811db2 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-07-17T09:19:29.880658Z | 10.1.1.70 | 10 | 2022-07-17T08:12:14.946000Z |  |  | 2022-08-14T11:10:28.642000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. <br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by checking the host for signs of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | Pony or Hancitor Second Stage Download | high | 2d06c01f-5ae4-4346-8d6a-99926dcac4f1 | tma2 | active | 2022-08-14T12:19:29.311145Z |  | 2b8774ea-19dc-4182-a9af-88e7fa06dc71 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-07-17T08:45:59.122907Z | 10.1.1.70 | 10 | 2022-07-17T08:12:14.946000Z |  |  | 2022-08-14T11:10:28.642000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by checking the host for signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | [Practical Packet Analysis] Pony or Hancitor Second Stage Download | high | 9c5e5aae-b3fb-47e7-998e-4cce5f34dd1e | tma2 | active | 2022-08-14T11:45:11.143096Z |  | 95f702ea-74f8-4c16-abd4-0c7d79d529aa |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-07-05T01:08:50.045379Z | 192.168.0.100 | 7 | 2022-07-05T00:07:50.082000Z |  |  | 2022-08-16T00:07:50.615000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable or Script Download From External Python SimpleHTTPServer | moderate | fe4d55b4-7293-425a-b549-43a22472923d | tma2 | active | 2022-08-16T01:08:42.415011Z |  | 2a0335ae-68e6-4476-9d39-46c2e5a4701e |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-06-19T12:08:24.984537Z | 10.5.1.10 | 81 | 2022-06-19T10:58:29.675000Z |  |  | 2022-08-14T11:27:13.585000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable or Script Download From External Python SimpleHTTPServer | moderate | fe4d55b4-7293-425a-b549-43a22472923d | gdm2 | active | 2022-08-14T12:08:25.484343Z |  | b54300bd-3e1a-46de-9f88-aa29ae21159c |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-06-17T12:08:58.241290Z | 10.1.70.2 | 18 | 2022-06-17T10:50:17.474000Z |  |  | 2022-08-12T11:35:05.884000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable or Script Download From External Python SimpleHTTPServer | moderate | fe4d55b4-7293-425a-b549-43a22472923d | gdm2 | active | 2022-08-12T12:08:37.075688Z |  | 3ce07005-36b5-4ff6-bb2d-14a7c91b1c38 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-06-17T11:24:24.760619Z | 10.1.70.2 | 18 | 2022-06-17T10:50:17.474000Z |  |  | 2022-08-12T11:35:05.884000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | moderate | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Executable Binary or Script Downloaded from Dotted Quad | moderate | 376a54b4-1456-430d-bceb-4ff58bed65d0 | gdm2 | active | 2022-08-12T12:22:48.306076Z |  | f697ce30-249d-4390-9bb3-ce868e7747ab |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-06-17T11:08:43.148494Z | 10.1.70.100 | 9 | 2022-06-17T10:06:12.636000Z |  |  | 2022-08-12T10:06:12.545000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable or Script Download From External Python SimpleHTTPServer | moderate | fe4d55b4-7293-425a-b549-43a22472923d | gdm2 | active | 2022-08-12T11:08:20.965907Z |  | ece847ff-84b8-4d7c-8426-1db6091dc15b |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-23T01:00:31.288913Z | 10.10.10.209 | 63 | 2022-05-23T00:01:04.844000Z |  |  | 2022-08-15T00:01:07.886000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | tma2 | active | 2022-08-15T01:00:51.885928Z |  | 534acb0f-a91a-41bc-966e-a6f41575c025 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-05-22T12:12:44.967357Z | 10.5.1.10 | 12 | 2022-05-22T11:27:00.225000Z |  |  | 2022-08-14T11:27:13.585000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | 0968b4a7-a6b9-475c-86f8-72b1571100d6 | gdm2 | active | 2022-08-14T12:12:24.734534Z |  | 2613e897-c156-472b-bca6-46af5a9e6123 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-05-20T12:12:35.814386Z | 10.1.70.2 | 24 | 2022-05-20T10:50:17.820000Z |  |  | 2022-08-12T11:35:05.884000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | 0968b4a7-a6b9-475c-86f8-72b1571100d6 | gdm2 | active | 2022-08-12T12:12:35.588771Z |  | 86b99672-9adc-4348-9ca0-918e589af2ae |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-05-20T11:12:19.813099Z | 10.1.70.100 | 12 | 2022-05-20T10:06:12.980000Z |  |  | 2022-08-12T10:06:12.545000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | 0968b4a7-a6b9-475c-86f8-72b1571100d6 | gdm2 | active | 2022-08-12T11:12:17.235368Z |  | 231a3afb-b622-4dc5-a985-9349f9df9ce9 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-20T01:39:40.367085Z | 10.1.70.100 | 13 | 2022-05-20T00:32:03.720000Z |  |  | 2022-08-12T00:32:03.763000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | low | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | Enumeration of Domain Objects | high | 810076e5-c11e-4948-856e-10e437c563e6 | tma2 | active | 2022-08-12T01:39:40.801265Z |  | 105f629b-c3cc-4111-934b-0c3e0cef019a |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-19T00:49:00.503514Z | 192.168.200.4 | 28 | 2022-05-19T00:01:37.406000Z |  |  | 2022-08-18T00:01:39.755000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Trickbot Staging Download | high | aadb155e-712f-481f-9680-482bab5a238d | tma2 | active | 2022-08-18T00:47:26.404778Z |  | 9790bdda-e205-4c96-a520-5b8a08f2efa6 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-19T01:21:19.968177Z | 192.168.200.4 | 42 | 2022-05-19T00:01:28.175000Z |  |  | 2022-08-18T00:02:07.397000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Trickbot Banking Trojan SSL Certificate | high | 2bbb5dda-ed01-4f49-888b-057233568abe | tma2 | active | 2022-08-18T01:19:49.158236Z |  | 6272015d-1fc0-4b5b-8ee6-09f35c5df616 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-19T01:00:37.035468Z | 192.168.200.4 | 1182 | 2022-05-19T00:01:28.082000Z |  |  | 2022-08-18T00:02:42.089000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | tma2 | active | 2022-08-18T01:00:29.151728Z |  | 394e1165-21cb-4d49-83b8-8323f2ae9de5 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-19T00:49:00.503577Z | 192.168.200.95 | 28 | 2022-05-19T00:01:21.258000Z |  |  | 2022-08-18T00:01:27.709000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Trickbot Staging Download | high | aadb155e-712f-481f-9680-482bab5a238d | tma2 | active | 2022-08-18T00:47:26.404839Z |  | bb6b8db5-e515-48ca-80a9-54eebd0088cc |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-19T01:00:37.035633Z | 192.168.200.95 | 1126 | 2022-05-19T00:01:12.058000Z |  |  | 2022-08-18T00:02:39.463000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | tma2 | active | 2022-08-18T01:00:29.151899Z |  | b44b4efd-4c2d-4bab-b8d9-9746b179a890 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-19T01:21:19.968206Z | 192.168.200.95 | 68 | 2022-05-19T00:01:07.863000Z |  |  | 2022-08-18T00:01:43.749000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Trickbot Banking Trojan SSL Certificate | high | 2bbb5dda-ed01-4f49-888b-057233568abe | tma2 | active | 2022-08-18T01:19:49.158271Z |  | 25db8bb5-80ee-4ddf-b780-6785817e316d |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-05-17T09:08:18.590866Z | 192.168.0.100 | 14 | 2022-05-17T08:35:58.182000Z |  |  | 2022-08-16T08:35:57.466000Z | false |  |  | false |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable or Script Download From External Python SimpleHTTPServer | moderate | fe4d55b4-7293-425a-b549-43a22472923d | gdm2 | active | 2022-08-16T09:08:10.043529Z |  | 37eb67e0-f850-4d35-b445-87376afef760 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-10T14:12:19.315419Z | 172.16.99.131 | 10 | 2022-05-10T01:01:06.508000Z |  |  | 2022-08-09T01:01:05.585000Z | false |  |  | false |  |  |  |  |  |  | Attack:Infection Vector | moderate | This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.<br/><br/>Kerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.<br/><br/>Gigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.<br/><br/>## Next Steps<br/>1. Review the services requested and determine if an SPN should be set for a given account.<br/>2. Ensure that service accounts have strong passwords.<br/>3. Review Kerberos logs to determine the user account involved.<br/>4. Verify that the activity was authorized. | Kerberoasting | high | 0de05ba7-d42d-4de8-aff7-aeb4350bb564 | tma2 | active | 2022-08-09T14:41:10.880491Z |  | 8498606c-aacb-464d-be8c-9e7ae0f02b2c |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-10T01:39:47.062453Z | 172.16.99.131 | 15 | 2022-05-10T01:01:06.464000Z |  |  | 2022-08-16T01:01:03.814000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | low | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | Enumeration of Domain Objects | high | 810076e5-c11e-4948-856e-10e437c563e6 | tma2 | active | 2022-08-16T01:39:55.066931Z |  | 518f9bbd-5f49-44f4-a1f5-e4e72c6a66d0 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-09T16:36:59.462092Z | 10.1.1.70 | 218 | 2022-05-09T16:05:16.277000Z |  |  | 2022-08-14T11:13:39.732000Z | false |  |  | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  <br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. <br/>2. Ensure legitimate and approved use of Tor. <br/>3. Remove any unapproved software. | Tor Connection Initialization | low | 7108db9b-6158-458f-b5b4-082f2ebae0f7 | tma2 | active | 2022-08-14T11:36:10.312240Z |  | 89bc0e5e-27ba-4f16-b5e7-0c82b673fc07 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-09T16:46:06.827787Z | 10.1.1.70 | 218 | 2022-05-09T16:05:16.277000Z |  |  | 2022-08-14T11:13:39.732000Z | false |  |  | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.<br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network.<br/>2. Ensure legitimate and approved use of Tor.<br/>3. Remove any unapproved software.  | [Practical Packet Analysis] Tor Connection Initialization | low | 9d838451-4d33-4124-b6fd-43439217bee3 | tma2 | active | 2022-08-14T11:45:11.128439Z |  | f5afe33f-119d-4e31-b159-1f75bf59d78f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-06T09:13:50.225137Z | 192.168.0.100 | 171 | 2022-04-06T08:03:30.713000Z |  |  | 2022-08-17T08:06:15.080000Z | false |  |  | true |  |  |  |  |  |  | Attack:Command and Control | moderate | This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client. <br/><br/>Gigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>     1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.<br/>     2. Validating that the external entity interacting with the device is unknown or unauthorized. <br/>     3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic from attacker infrastructure. <br/>5. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers. | CKnife Webshell HTTP POST Request | high | 0ffc3a5a-6cc5-443f-ad79-f94d99584b26 | gdm2 | active | 2022-08-17T09:13:13.984895Z |  | 69eaef8a-e077-480a-9b71-21a7b410ef64 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T08:48:37.999636Z | 10.10.31.5 | 37 | 2022-04-04T08:09:04.280000Z |  |  | 2022-08-15T08:09:09.640000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Trickbot Staging Download | high | aadb155e-712f-481f-9680-482bab5a238d | gdm2 | active | 2022-08-15T08:47:16.812989Z |  | 1ca5448c-fa10-4e8a-84e5-dbf5dde6e3f1 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T08:48:37.999696Z | 10.10.31.101 | 38 | 2022-04-04T08:06:10.130000Z |  |  | 2022-08-15T08:06:40.000000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Trickbot Staging Download | high | aadb155e-712f-481f-9680-482bab5a238d | gdm2 | active | 2022-08-15T08:47:16.813046Z |  | 598e2790-fc75-41df-a1ba-026582882173 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:20:07.852157Z | 10.10.31.5 | 133 | 2022-04-04T08:06:00.050000Z |  |  | 2022-08-15T08:08:48.190000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Trickbot Banking Trojan SSL Certificate | high | 2bbb5dda-ed01-4f49-888b-057233568abe | gdm2 | active | 2022-08-15T09:19:27.919195Z |  | c61d2389-df78-4daf-b8cc-b576f14df683 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:00:42.936731Z | 10.10.31.101 | 19 | 2022-04-04T08:05:57.190000Z |  |  | 2022-08-15T08:05:57.000000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | gdm2 | active | 2022-08-15T09:00:17.058322Z |  | b16c6b57-48fd-4bab-929a-12eb4708c7ca |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:00:42.936171Z | 10.10.31.5 | 966 | 2022-04-04T08:04:18.830000Z |  |  | 2022-08-15T08:09:33.210000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | gdm2 | active | 2022-08-15T09:00:17.057770Z |  | 2ddf11c7-0c40-4c19-b687-a3c1db819e4f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:20:07.852001Z | 10.10.31.101 | 782 | 2022-04-04T08:03:23.030000Z |  |  | 2022-08-15T08:09:33.040000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Trickbot Banking Trojan SSL Certificate | high | 2bbb5dda-ed01-4f49-888b-057233568abe | gdm2 | active | 2022-08-15T09:19:27.919038Z |  | 3a275dc4-2313-4a0c-8b9f-fca2225e9a25 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:12:43.668174Z | 10.10.31.101 | 72 | 2022-04-04T08:03:07.110000Z |  |  | 2022-08-15T08:03:06.980000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | 0968b4a7-a6b9-475c-86f8-72b1571100d6 | gdm2 | active | 2022-08-15T09:12:23.133734Z |  | d728be03-1a73-4c06-865c-796693ba6c1a |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:24:53.016814Z | 10.10.31.101 | 18 | 2022-04-04T08:02:16.900000Z |  |  | 2022-08-15T08:02:16.710000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.<br/><br/>Gigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>    2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | IcedID Banking Trojan HTTP GET Request | high | 3e8c54a6-1934-4517-b217-e98f342b6c5a | gdm2 | active | 2022-08-15T09:24:29.568416Z |  | 7fb23eec-2dad-49e1-ac92-7d3d9af7be98 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T04:12:10.667253Z | 172.16.99.131 | 18 | 2022-04-03T15:26:13.757000Z |  |  | 2022-08-14T15:26:28.279000Z | false |  |  | false |  |  |  |  |  |  | Attack:Infection Vector | moderate | This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.<br/><br/>Kerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.<br/><br/>Gigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.<br/><br/>## Next Steps<br/>1. Review the services requested and determine if an SPN should be set for a given account.<br/>2. Ensure that service accounts have strong passwords.<br/>3. Review Kerberos logs to determine the user account involved.<br/>4. Verify that the activity was authorized. | Kerberoasting | high | 0de05ba7-d42d-4de8-aff7-aeb4350bb564 | gdm2 | active | 2022-08-15T04:12:50.365734Z |  | 1a126f5c-4e36-4de5-a9d2-7de7b17dd0c2 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T16:39:36.845325Z | 172.16.99.131 | 19 | 2022-04-03T15:26:13.537000Z |  |  | 2022-08-14T15:26:28.059000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | low | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | Enumeration of Domain Objects | high | 810076e5-c11e-4948-856e-10e437c563e6 | gdm2 | active | 2022-08-14T16:39:59.129348Z |  | d855248d-759f-4e74-91b8-e7f32b38d4ee |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T15:51:16.806362Z | 192.168.68.175 | 19 | 2022-04-03T15:26:11.959000Z |  |  | 2022-08-14T15:26:26.040000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | high | This logic is intended to detect a Windows banner over ICMP. This Windows banner appears at the start of a reverse shell session over ICMP, often started with tools such as \`icmpsh\`. By using ICMP, attackers are often able to circumvent firewall protections.<br/><br/>Gigamon ATR considers a Windows banner over ICMP high severity, as it is indicative of successful malicious code execution. Gigamon ATR considers this detection high confidence due to the uniqueness of the Windows banner string in ICMP traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by starting packet capture and investigating ICMP traffic produced by the impacted asset, looking for the presence of plaintext shell commands.<br/>2. Quarantine the impacted device.<br/>3. Search for other impacted devices.<br/>4. Block traffic to attacker infrastructure.<br/>5. Begin incident response procedures on the impacted device.  | Windows Banner String in ICMP Request | high | b73126a8-5cd1-4c2f-a0ef-ce12e02e4b31 | gdm2 | active | 2022-08-14T15:50:39.389855Z |  | fbd27f09-f355-4c5a-9126-556778c56e1c |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-03-31T11:40:03.229566Z | 10.1.70.100 | 58 | 2022-03-31T10:37:03.949000Z |  |  | 2022-08-18T10:37:04.588000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | low | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | Enumeration of Domain Objects | high | 810076e5-c11e-4948-856e-10e437c563e6 | gdm2 | active | 2022-08-18T11:39:57.030910Z |  | bc7f2bc5-7ab2-487f-8197-6ee6a4390959 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-09T16:46:06.827787Z | 10.1.1.70 | 218 | 2022-05-09T16:05:16.277000Z |  |  | 2022-08-14T11:13:39.732000Z | false |  |  | false |  |  |  |  |  |  | Posture:Potentially Unauthorized Software or Device | high | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.<br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network.<br/>2. Ensure legitimate and approved use of Tor.<br/>3. Remove any unapproved software.  | [Practical Packet Analysis] Tor Connection Initialization | low | 9d838451-4d33-4124-b6fd-43439217bee3 | tma2 | active | 2022-08-14T11:45:11.128439Z |  | f5afe33f-119d-4e31-b159-1f75bf59d78f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-06T09:13:50.225137Z | 192.168.0.100 | 171 | 2022-04-06T08:03:30.713000Z |  |  | 2022-08-17T08:06:15.080000Z | false |  |  | true |  |  |  |  |  |  | Attack:Command and Control | moderate | This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client. <br/><br/>Gigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>     1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.<br/>     2. Validating that the external entity interacting with the device is unknown or unauthorized. <br/>     3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic from attacker infrastructure. <br/>5. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers. | CKnife Webshell HTTP POST Request | high | 0ffc3a5a-6cc5-443f-ad79-f94d99584b26 | gdm2 | active | 2022-08-17T09:13:13.984895Z |  | 69eaef8a-e077-480a-9b71-21a7b410ef64 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T08:48:37.999636Z | 10.10.31.5 | 37 | 2022-04-04T08:09:04.280000Z |  |  | 2022-08-15T08:09:09.640000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Trickbot Staging Download | high | aadb155e-712f-481f-9680-482bab5a238d | gdm2 | active | 2022-08-15T08:47:16.812989Z |  | 1ca5448c-fa10-4e8a-84e5-dbf5dde6e3f1 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T08:48:37.999696Z | 10.10.31.101 | 38 | 2022-04-04T08:06:10.130000Z |  |  | 2022-08-15T08:06:40.000000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | high | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | Trickbot Staging Download | high | aadb155e-712f-481f-9680-482bab5a238d | gdm2 | active | 2022-08-15T08:47:16.813046Z |  | 598e2790-fc75-41df-a1ba-026582882173 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:20:07.852157Z | 10.10.31.5 | 133 | 2022-04-04T08:06:00.050000Z |  |  | 2022-08-15T08:08:48.190000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Trickbot Banking Trojan SSL Certificate | high | 2bbb5dda-ed01-4f49-888b-057233568abe | gdm2 | active | 2022-08-15T09:19:27.919195Z |  | c61d2389-df78-4daf-b8cc-b576f14df683 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:00:42.936731Z | 10.10.31.101 | 19 | 2022-04-04T08:05:57.190000Z |  |  | 2022-08-15T08:05:57.000000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | gdm2 | active | 2022-08-15T09:00:17.058322Z |  | b16c6b57-48fd-4bab-929a-12eb4708c7ca |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:00:42.936171Z | 10.10.31.5 | 966 | 2022-04-04T08:04:18.830000Z |  |  | 2022-08-15T08:09:33.210000Z | false |  |  | false |  |  |  |  |  |  | Attack:Exfiltration | moderate | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Trickbot Data Exfiltration over SSL | high | db969564-0ba3-43d6-ad9e-67bf2509006f | gdm2 | active | 2022-08-15T09:00:17.057770Z |  | 2ddf11c7-0c40-4c19-b687-a3c1db819e4f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:20:07.852001Z | 10.10.31.101 | 782 | 2022-04-04T08:03:23.030000Z |  |  | 2022-08-15T08:09:33.040000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | Trickbot Banking Trojan SSL Certificate | high | 2bbb5dda-ed01-4f49-888b-057233568abe | gdm2 | active | 2022-08-15T09:19:27.919038Z |  | 3a275dc4-2313-4a0c-8b9f-fca2225e9a25 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:12:43.668174Z | 10.10.31.101 | 72 | 2022-04-04T08:03:07.110000Z |  |  | 2022-08-15T08:03:06.980000Z | false |  |  | true |  |  |  |  |  |  | Attack:Installation | low | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | Executable in Root of Web Directory | high | 0968b4a7-a6b9-475c-86f8-72b1571100d6 | gdm2 | active | 2022-08-15T09:12:23.133734Z |  | d728be03-1a73-4c06-865c-796693ba6c1a |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T09:24:53.016814Z | 10.10.31.101 | 18 | 2022-04-04T08:02:16.900000Z |  |  | 2022-08-15T08:02:16.710000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | moderate | This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.<br/><br/>Gigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>    2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | IcedID Banking Trojan HTTP GET Request | high | 3e8c54a6-1934-4517-b217-e98f342b6c5a | gdm2 | active | 2022-08-15T09:24:29.568416Z |  | 7fb23eec-2dad-49e1-ac92-7d3d9af7be98 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-04T04:12:10.667253Z | 172.16.99.131 | 18 | 2022-04-03T15:26:13.757000Z |  |  | 2022-08-14T15:26:28.279000Z | false |  |  | false |  |  |  |  |  |  | Attack:Infection Vector | moderate | This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.<br/><br/>Kerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.<br/><br/>Gigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.<br/><br/>## Next Steps<br/>1. Review the services requested and determine if an SPN should be set for a given account.<br/>2. Ensure that service accounts have strong passwords.<br/>3. Review Kerberos logs to determine the user account involved.<br/>4. Verify that the activity was authorized. | Kerberoasting | high | 0de05ba7-d42d-4de8-aff7-aeb4350bb564 | gdm2 | active | 2022-08-15T04:12:50.365734Z |  | 1a126f5c-4e36-4de5-a9d2-7de7b17dd0c2 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T16:39:36.845325Z | 172.16.99.131 | 19 | 2022-04-03T15:26:13.537000Z |  |  | 2022-08-14T15:26:28.059000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | low | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | Enumeration of Domain Objects | high | 810076e5-c11e-4948-856e-10e437c563e6 | gdm2 | active | 2022-08-14T16:39:59.129348Z |  | d855248d-759f-4e74-91b8-e7f32b38d4ee |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T15:51:16.806362Z | 192.168.68.175 | 19 | 2022-04-03T15:26:11.959000Z |  |  | 2022-08-14T15:26:26.040000Z | false |  |  | false |  |  |  |  |  |  | Attack:Command and Control | high | This logic is intended to detect a Windows banner over ICMP. This Windows banner appears at the start of a reverse shell session over ICMP, often started with tools such as \`icmpsh\`. By using ICMP, attackers are often able to circumvent firewall protections.<br/><br/>Gigamon ATR considers a Windows banner over ICMP high severity, as it is indicative of successful malicious code execution. Gigamon ATR considers this detection high confidence due to the uniqueness of the Windows banner string in ICMP traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by starting packet capture and investigating ICMP traffic produced by the impacted asset, looking for the presence of plaintext shell commands.<br/>2. Quarantine the impacted device.<br/>3. Search for other impacted devices.<br/>4. Block traffic to attacker infrastructure.<br/>5. Begin incident response procedures on the impacted device.  | Windows Banner String in ICMP Request | high | b73126a8-5cd1-4c2f-a0ef-ce12e02e4b31 | gdm2 | active | 2022-08-14T15:50:39.389855Z |  | fbd27f09-f355-4c5a-9126-556778c56e1c |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-03-31T11:40:03.229566Z | 10.1.70.100 | 58 | 2022-03-31T10:37:03.949000Z |  |  | 2022-08-18T10:37:04.588000Z | false |  |  | false |  |  |  |  |  |  | Attack:Discovery | low | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | Enumeration of Domain Objects | high | 810076e5-c11e-4948-856e-10e437c563e6 | gdm2 | active | 2022-08-18T11:39:57.030910Z |  | bc7f2bc5-7ab2-487f-8197-6ee6a4390959 |


### insight-get-detection-rules
***
Get a list of detection rules.


#### Base Command

`insight-get-detection-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Filter name or category. | Optional | 
| account_uuid | For those with access to multiple accounts, specify a single account to return results from. | Optional | 
| has_detections | Include rules that have unmuted, unresolved detections. Possible values are: true, false. | Optional | 
| severity | Filter by severity: high, moderate, low. Possible values are: low, moderate, high. | Optional | 
| confidence | Filter by confidence: high, moderate, low. Possible values are: low, moderate, high. | Optional | 
| category | Category to filter by. Possible values are: Attack:Command and Control, Attack:Exploitation, Attack:Exfiltration, Attack:Installation, Attack:Lateral Movement, Attack:Infection Vector, Attack:Miscellaneous, Miscellaneous, Posture:Anomalous Activity, Posture:Insecure Configuration, Posture:Potentially Unauthorized Software or Device, Posture:Miscellaneous, PUA:Adware, PUA:Spyware, PUA:Unauthorized Resource Use, PUA:Miscellaneous. | Optional | 
| rule_account_muted | Include muted rules: true / false. Possible values are: true, false. | Optional | 
| enabled | Enabled rules only. Possible values are: true, false. | Optional | 
| sort_by | Sort output by: "ip", "internal", "external". Possible values are: ip, internal, external. | Optional | 
| sort_order | Sort direction ("asc" vs "desc"). Possible values are: asc, desc. | Optional | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Rules.enabled | boolean | Status of the rule: If true it is enabled, if false it is disabled. | 
| Insight.Rules.updated_user_uuid | string | User ID that updated the rule | 
| Insight.Rules.rule_accounts | string | Accounts which have seen detections for this rule | 
| Insight.Rules.auto_resolution_minutes | number | Length of time \(in minutes\) the rule will auto-resolve detections | 
| Insight.Rules.created | date | Date the rule was created | 
| Insight.Rules.account_uuid | string | Account ID the rule was created under | 
| Insight.Rules.confidence | string | Confidence level of the rule | 
| Insight.Rules.name | string | Name of the rule | 
| Insight.Rules.created_user_uuid | string | User ID that created the rule | 
| Insight.Rules.query_signature | string | IQL signature of the rule | 
| Insight.Rules.shared_account_uuids | string | Account IDs the rule is visible to | 
| Insight.Rules.run_account_uuids | string | Account IDs the rule runs on | 
| Insight.Rules.updated | date | Date the rule was updated | 
| Insight.Rules.uuid | string | Unique ID of the rule | 
| Insight.Rules.description | string | Description of the rule | 
| Insight.Rules.severity | string | Severity level of the rule | 
| Insight.Rules.category | string | Category of the rule | 

#### Command example
```!insight-get-detection-rules has_detections=true sort_by=last_seen```
#### Context Example
```json
{
    "Insight": {
        "Rules": [
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Discovery",
                "confidence": "low",
                "created": "2020-08-17T23:04:31.001000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-05-12T17:34:08.014000Z",
                "description": "This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.\r\n\r\nGigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Search enumerated objects for signs of compromise. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Enumeration of Domain Objects",
                "primary_attack_id": "T1087.002",
                "query_signature": "(sig_id = 2900687 AND sig_rev = 1)\r\nOR (sig_id = 2900688 AND sig_rev = 1)\r\nOR (sig_id = 2900689 AND sig_rev = 1)\r\nOR (sig_id = 2900690 AND sig_rev = 1)\r\nOR (sig_id = 2900691 AND sig_rev = 1)\r\nOR (sig_id = 2900741 AND sig_rev = 2)\r\nOR (sig_id = 2900742 AND sig_rev = 1)\r\nOR (sig_id = 2900746 AND sig_rev = 2)\r\n\r\n/*\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory Domain Container Enumeration\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x26\\x04\\x0eobjectcategory\\x04\\x14grouppolicycontainer/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x24\\x04\\x0eobjectcategory\\x04\\x12organizationalunit/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x15\\x04\\x0bobjectclass\\x04\\x06domain/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900687; rev:1;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory Users, Computers, and OU Enumeration Within OU\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; content:\"OU=\"; distance:7; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09805306368/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09805306369/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x21\\x04\\x0bobjectclass\\x04\\x12organizationalunit/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900688; rev:1;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory Users, Computers, and OU Enumeration Within Domain\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; content:\"DC=\"; distance:7; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09805306368/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09805306369/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x21\\x04\\x0bobjectclass\\x04\\x12organizationalunit/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900689; rev:1;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory User and Computer Enumeration Within Container\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; content:\"CN=\"; distance:7; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09805306368/i\"; pcre:\"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09805306369/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900690; rev:1;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory Domain Group Membership Query\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; pcre: \"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09268435456/i\"; pcre: \"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09268435457/i\"; pcre: \"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09536870912/i\"; pcre: \"/\\xa3\\x84\\x00\\x00\\x00\\x1b\\x04\\x0esamaccounttype\\x04\\x09536870913/i\"; pcre: \"/\\x87\\x0eprimarygroupid/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900691; rev:1;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory All Group Policy Objects\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; pcre: \"/[\\x00\\x01]\\xa3\\x84\\x00\\x00\\x00\\x26\\x04\\x0eobjectCategory\\x04\\x14groupPolicyContainer\\x30\\x84\\x00\\x00\\x00/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900746; rev:2;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory All Objects with SPNs Set\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; pcre: \"/(?<!\\xa2\\x84\\x00\\x00\\x00.)\\x87\\x14serviceprincipalname/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900741; rev:2;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory OUs or Domains With Linked Group Policy Objects\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; pcre: \"/\\xa0\\x84\\x00\\x00\\x00[\\x5a\\x53]\\xa1\\x84\\x00\\x00\\x00\\x45\\xa3\\x84\\x00\\x00\\x00\\x24\\x04\\x0eobjectcategory\\x04\\x12organizationalUnit\\xa3\\x84\\x00\\x00\\x00\\x15\\x04\\x0bobjectclass\\x04\\x06domain\\x87\\x06gplink(\\x87\\x05flags)?/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900742; rev:1;)\r\n* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:\"ATR DISCOVERY LDAP Active Directory Users with SID History Set\"; flow:established,to_server,no_stream; content:\"|30 84 00 00|\"; content:\"|63|\"; distance:5; pcre: \"/(?<!\\xa2\\x84\\x00\\x00\\x00.)\\x87\\x0asidHistory\\x30\\x84\\x00\\x00\\x00/i\"; classtype: misc-attack; metadata: DET-6003; sid:2900743; rev:2;)\r\n*/",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-21T01:01:03.272000Z",
                        "last_seen": "2022-08-16T01:01:03.814000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-19T16:26:13.601000Z",
                        "last_seen": "2022-08-18T10:37:04.588000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": "T1069.002",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-05-12T17:42:52.843000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "810076e5-c11e-4948-856e-10e437c563e6"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "moderate",
                "created": "2018-03-19T17:45:06.418000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2022-01-06T18:00:18.510000Z",
                "description": "This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.\r\n\r\nGigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by: \r\n      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.\r\n      2. Inspecting the downloaded application for malicious content.\r\n2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent"
                ],
                "name": "HTML Application (HTA) Download",
                "primary_attack_id": "T1105",
                "query_signature": "// Look for HTA by URI or by MimeType\r\n(\r\n    http:uri.path MATCHES \".*?\\.[hH][tT][aA]\"\r\n    OR http:response_mime = \"application/hta\"\r\n)\r\nAND (\r\n    dst.internal = false\r\n    OR (\r\n        // Not an internal IP\r\n        host.ip != null\r\n        // Proxied traffic\r\n        AND uri.scheme != null\r\n    )\r\n)\r\n\r\n// Whitelist out known good that does this\r\nAND host.domain NOT LIKE \"%.kaspersky.com\"\r\nAND host.domain != \"kav8.zonealarm.com\"\r\nAND (\r\n    host.domain != \"downloadupdates.axway.com\"\r\n    OR uri.path NOT MATCHES  \"/kaspersky(86)?/.*\"\r\n)\r\nAND (\r\n    user_agent NOT LIKE \"HelloTalk %\"\r\n    OR uri.path NOT MATCHES \"/[0-9]{8}/[0-9a-f]{17}_[0-9a-f]{5}\\.hta\"\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 21,
                        "first_seen": "2021-12-24T00:01:30.364000Z",
                        "last_seen": "2022-08-12T00:01:32.770000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 58,
                        "first_seen": "2021-12-19T10:38:17.642000Z",
                        "last_seen": "2022-08-18T08:04:29.641000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": "T1218.005",
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2022-08-02T15:09:22.034171Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "f290eaaf-4748-4b35-a32e-0b88e1b0beee"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Exfiltration",
                "confidence": "moderate",
                "created": "2019-10-14T20:16:09.935000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-12-10T00:05:15.787000Z",
                "description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\r\n\r\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\r\n\r\n## Next Steps\r\n1. Determine if this is a true positive by:\r\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\r\n    2. Checking the impacted asset for other indicators of compromise.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "ssl:server_name_indication",
                    "ssl:subject",
                    "ssl:issuer",
                    "ssl:ja3"
                ],
                "name": "Trickbot Data Exfiltration over SSL",
                "primary_attack_id": "T1048.002",
                "query_signature": "ssl:subject = \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\"\r\nAND issuer = \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\"\r\nAND dst.port IN (447, 449)\r\nAND dst.internal = false",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-20T00:01:04.359000Z",
                        "last_seen": "2022-08-18T00:02:42.089000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-20T09:04:19.258000Z",
                        "last_seen": "2022-08-15T08:09:33.210000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2021-06-18T17:31:48.655000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "db969564-0ba3-43d6-ad9e-67bf2509006f"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Exfiltration",
                "confidence": "moderate",
                "created": "2021-12-18T15:36:46.843000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:36:46.843000Z",
                "description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n## Next Steps\n1. Determine if this is a true positive by:\n    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n    2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 1] Trickbot Data Exfiltration over SSL",
                "primary_attack_id": null,
                "query_signature": "ssl:subject = \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\"\nAND issuer = \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\"\nAND dst.port IN (447, 449)\nAND dst.internal = false",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 68,
                        "first_seen": "2021-12-20T00:01:04.359000Z",
                        "last_seen": "2022-08-18T00:02:42.089000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:36:46.843000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "43030c3b-da2a-4016-9035-5958aaea5b8e"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2018-08-01T19:38:43.696000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-12-10T00:03:18.840000Z",
                "description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Evaluating the timing of the connections for beacon-like regularity. \n    2. Checking the impacted asset for other indicators of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "ssl:server_name_indication",
                    "ssl:subject",
                    "ssl:issuer",
                    "ssl:ja3"
                ],
                "name": "Trickbot Banking Trojan SSL Certificate",
                "primary_attack_id": "T1071.001",
                "query_signature": "ssl:subject = \"CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB\"\r\nAND ssl:issuer = \"CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB\"",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-23T00:01:07.921000Z",
                        "last_seen": "2022-08-18T00:02:07.397000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-20T09:03:23.458000Z",
                        "last_seen": "2022-08-15T08:09:33.040000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2022-08-10T21:51:19.244790Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "2bbb5dda-ed01-4f49-888b-057233568abe"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "moderate",
                "created": "2018-03-22T23:22:11.307000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-11-18T19:38:39.719000Z",
                "description": "This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.\n\nNote that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. \n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the downloaded file is not a benign file from a reputable service.\n    2. Verifying that the file is malicious in nature. \n2. Determine if the file was executed on the impacted asset.\n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Executable Binary or Script Downloaded from Dotted Quad",
                "primary_attack_id": "T1105",
                "query_signature": "(\r\n    // Select HTTP dotted-quad requests to an external server\r\n    http:host.ip != null\r\n    AND dst.internal = false\r\n) AND (\r\n    // Executable Binaries or Scripts (x-alliant-executable is not reliable)\r\n    (\r\n        response_mime LIKE \"%executable%\" \r\n        AND response_mime != \"application/x-alliant-executable\"\r\n    )\r\n    OR response_mime LIKE \"%application/x-dosexec%\"\r\n    OR response_mime LIKE \"%application/x-macbinary%\"\r\n\r\n    // Commonly malicious\r\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\r\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\r\n\r\n    // System-level scripts\r\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\r\n    OR response_mime LIKE \"%x-shellscript%\"\r\n\r\n    // Filetypes not yet positively classified by FileTyper over binary content.\r\n    // Instead match by extension (also to be obviated by future FileTyper features)\r\n    OR (\r\n        http:status_code >= 200\r\n        AND http:status_code <= 300\r\n        AND http:response_len > 0\r\n        AND http:uri.path MATCHES \".*\\.(([hH][tT][aA])|([vV][bB][sS])|([pP][sS]1)|([jJ][sS][eE])|([wW][sS][fF])|([mM][sS][iI]))\"\r\n    )\r\n)\r\n\r\n// Remove Sophos antivirus\r\nAND http:uri.path NOT LIKE \"/SophosUpdate/%\"",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 6,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 110,
                        "first_seen": "2021-12-20T09:03:07.538000Z",
                        "last_seen": "2022-08-16T08:35:57.466000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 65,
                        "first_seen": "2021-12-21T00:07:50.553000Z",
                        "last_seen": "2022-08-18T00:01:41.319000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-12-17T22:37:00.932000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "376a54b4-1456-430d-bceb-4ff58bed65d0"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2021-12-18T15:38:37.470000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:38:37.470000Z",
                "description": "## Description\n\nThis logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n## Next Steps\n\n1.  Investigate the listed events to determine if the downloaded file was malicious.\n2.    Investigate the host for compromise.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 1] Executable Retrieved with Minimal HTTP Headers",
                "primary_attack_id": null,
                "query_signature": "// Most malware downloaded via macro or downloader uses short URI's\nhttp:uri.path MATCHES \"/.{0,32}\"\n\n// No referrer\nAND http:referrer.uri = null\n\nAND http:response_mime IN (\"application/x-dosexec\", \"application/x-mach-o-executable\", \"application/x-executable\")\nAND http:status_code = 200\n\n// Majority of downloaders use only GET\nand http:method = \"GET\"\n\n// No user agent, uncommon\nAND http:user_agent = null\n\nAND http:headers.accept = null\nAND http:headers.refresh = null\nAND headers.cookie_length IN (0, null)\n\n// Most malicious downloads are small, < 2MB\nAND http:response_len<2mb\n\nAND dst.internal = false\n\n// Common distribution / update sites\nAND http:host NOT MATCHES \".{0,50}(\\.beyondtrust\\.com|\\.microsoft\\.com|audiochannel\\.net|\\.autodesk\\.com|\\.dell\\.com|\\,windowsupdate.com|\\.hp\\.com|\\.cloudfront\\.net|\\.mozilla\\.org|\\.windows\\.net|\\.dellsupportcenter\\.com|\\.lavasoft\\.com|\\.bytefence\\.com|\\.techsmith\\.com|\\.solidworks.com)\" \n\n// Various akamai / cdn / hoster / legit software distribution asns \nAND dst.asn.asn NOT IN (22611,9891,4249,20940,15133,6461,9498,209,31976)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 65,
                        "first_seen": "2021-12-20T00:01:02.949000Z",
                        "last_seen": "2022-08-18T00:01:41.319000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:38:37.470000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "1d315815-f7c5-4086-83f9-db2ced7d11df"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2019-04-29T17:52:36.003000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-01-11T19:21:22.305000Z",
                "description": "This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.\n\nGigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).\n\n## Next Steps\n1. Investigate the listed events to determine if the downloaded file was malicious.\n2. Investigate the host for compromise.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "dst.asn.asn_org",
                    "http:host",
                    "http:uri.uri",
                    "http:response_mimes"
                ],
                "name": "Executable Retrieved with Minimal HTTP Headers",
                "primary_attack_id": "T1105",
                "query_signature": "// Most malware downloaded via macro or downloader uses short URI's\r\nhttp:uri.path MATCHES \"/.{0,32}\"\r\n\r\n// No referrer\r\nAND http:referrer.uri = null\r\n\r\nAND http:response_mime IN (\"application/x-dosexec\", \"application/x-mach-o-executable\", \"application/x-executable\")\r\nAND http:status_code = 200\r\n\r\n// Majority of downloaders use only GET\r\nand http:method = \"GET\"\r\n\r\n// No user agent, uncommon\r\nAND http:user_agent = null\r\n\r\nAND http:headers.accept = null\r\nAND http:headers.refresh = null\r\nAND headers.cookie_length IN (0, null)\r\n\r\n// Most malicious downloads are small, < 2MB\r\nAND http:response_len<2mb\r\n\r\nAND dst.internal = false\r\n\r\n// Common distribution / update sites\r\nAND http:host NOT MATCHES \".{0,50}(\\.beyondtrust\\.com|\\.microsoft\\.com|audiochannel\\.net|\\.autodesk\\.com|\\.dell\\.com|\\,windowsupdate.com|\\.hp\\.com|\\.cloudfront\\.net|\\.mozilla\\.org|\\.windows\\.net|\\.dellsupportcenter\\.com|\\.lavasoft\\.com|\\.bytefence\\.com|\\.techsmith\\.com|\\.solidworks.com)\" \r\n\r\n// Various akamai / cdn / hoster / legit software distribution asns \r\nAND dst.asn.asn NOT IN (22611,9891,4249,20940,15133,6461,9498,209,31976)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 5,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 104,
                        "first_seen": "2021-12-20T09:03:07.538000Z",
                        "last_seen": "2022-08-15T08:08:48.860000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 65,
                        "first_seen": "2021-12-20T00:01:02.949000Z",
                        "last_seen": "2022-08-18T00:01:41.319000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": "T1059.001",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-12-28T20:15:41.314000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "moderate",
                "created": "2018-03-19T17:46:13.592000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-09-04T21:01:54.987000Z",
                "description": "This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Verifying that the file is an executable.\n    2. Verifying that the executable is malicious in nature.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "http:response_mimes",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Executable Binary or Script Downloaded as Image",
                "primary_attack_id": "T1105",
                "query_signature": "// Select files ending with common image extensions downloaded from external HTTP server\r\nuri.path MATCHES \".*\\.(([jJ][pP][gG])|([jJ][pP][eE][gG])|([gG][iI][fF])|([pP][nN][gG]))\"\r\nAND (\r\n    dst.internal = false\r\n    OR (\r\n        // Not internal IP\r\n        host.internal != true\r\n        // Proxied traffic\r\n        AND uri.scheme != null\r\n    )\r\n)\r\n                    \r\nAND (\r\n    // Filter for plain executable binary MIME types\r\n    response_mime LIKE \"%executable%\"\r\n    OR response_mime LIKE \"%application/x-dosexec%\"\r\n    OR response_mime LIKE \"%application/x-macbinary%\"\r\n\r\n    // Commonly malicious\r\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\r\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\r\n\r\n    // System-level scripts\r\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\r\n    OR response_mime LIKE \"%x-shellscript%\"\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 45,
                        "first_seen": "2021-12-23T00:01:14.237000Z",
                        "last_seen": "2022-08-18T00:01:41.319000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 56,
                        "first_seen": "2021-12-20T09:03:22.298000Z",
                        "last_seen": "2022-08-15T08:09:09.640000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-07-23T18:38:06.342000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "3a87c020-a7fe-48bf-b3fd-71aa40072f72"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2018-04-24T23:39:13.382000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-12-10T00:04:21.861000Z",
                "description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. \n\n## Next Steps \n1. Determine if this is a true positive by: \n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. \n3. Quarantine the impacted device. \n4. Begin incident response procedures on the impacted device. \n5. Block traffic to attacker infrastructure. \n6. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Trickbot Staging Download",
                "primary_attack_id": "T1105",
                "query_signature": "http:user_agent = \"WinHTTP loader/1.0\"\r\nAND response_mime = \"application/x-dosexec\"",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-23T00:01:21.317000Z",
                        "last_seen": "2022-08-18T00:01:39.755000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-20T09:06:10.558000Z",
                        "last_seen": "2022-08-15T08:09:09.640000Z",
                        "muted": true,
                        "muted_comment": null,
                        "muted_timestamp": "2022-01-05T18:39:07.352000Z",
                        "muted_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2021-03-19T19:32:19.685000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "aadb155e-712f-481f-9680-482bab5a238d"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Exploitation",
                "confidence": "moderate",
                "created": "2018-03-19T17:45:57.463000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2022-08-11T22:50:12.664645Z",
                "description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. \n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": [
                    "src.ip",
                    "dst.ip"
                ],
                "name": "ETERNALBLUE Exploitation",
                "primary_attack_id": "T1203",
                "query_signature": "// ET EXPLOIT ETERNALBLUE signatures\r\nsuricata:sig_id IN (\r\n    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Heap Spray\r\n    // https://doc.emergingthreats.net/2024217\r\n    2024217,\r\n\r\n    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response\r\n    // https://doc.emergingthreats.net/2024218\r\n    2024218,\r\n\r\n    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Request (set)\r\n    // https://doc.emergingthreats.net/2024220\r\n    2024220, \r\n\r\n    // ET EXPLOIT ETERNALBLUE Exploit M2 MS17-010\r\n    // https://doc.emergingthreats.net/2024297\r\n    2024297,\r\n\r\n    // ET EXPLOIT Possible ETERNALBLUE Exploit M3 MS17-010\r\n    // https://doc.emergingthreats.net/2024430\r\n    2024430,\r\n\r\n    // ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010\r\n    // https://doc.emergingthreats.net/2025650\r\n    2025650\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 62,
                        "first_seen": "2021-12-20T09:03:34.058000Z",
                        "last_seen": "2022-08-15T08:04:04.280000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 62,
                        "first_seen": "2021-12-19T08:21:09.561000Z",
                        "last_seen": "2022-08-18T00:01:13.819000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2022-08-11T22:50:12.664645Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "e5bb5bab-e6df-469b-9892-96bf4b84ecae"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Exploitation",
                "confidence": "moderate",
                "created": "2021-12-18T15:44:18.716000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:44:18.716000Z",
                "description": "This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.\n\nGigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.\n\n## Next Steps\n1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n6. Disable SMBv1 across the domain, if possible.\n7. Ensure host operating systems are patched regularly. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Practical Packet Analysis] ETERNALBLUE Exploitation",
                "primary_attack_id": null,
                "query_signature": "// ET EXPLOIT ETERNALBLUE signatures\nsuricata:sig_id IN (\n    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Heap Spray\n    // http://doc.emergingthreats.net/2024217\n    2024217,\n\n    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response\n    // http://doc.emergingthreats.net/2024218\n    2024218,\n\n    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Request (set)\n    // http://doc.emergingthreats.net/2024220\n    2024220, \n\n    // ET EXPLOIT ETERNALBLUE Exploit M2 MS17-010\n    // http://doc.emergingthreats.net/2024297\n    2024297,\n\n    // ET EXPLOIT Possible ETERNALBLUE Exploit M3 MS17-010\n    // http://doc.emergingthreats.net/2024430\n    2024430,\n\n    // ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010\n    // http://doc.emergingthreats.net/2025650\n    2025650\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 62,
                        "first_seen": "2021-12-19T08:21:09.561000Z",
                        "last_seen": "2022-08-18T00:01:13.819000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:44:18.716000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "2ad64816-4a7b-41a6-b664-e1b1cf08683f"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2021-12-18T15:19:40.254000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:19:40.254000Z",
                "description": "This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client.\n\nGigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.\n   2. Validating that the external entity interacting with the device is unknown or unauthorized.\n   3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent.\n3. Quarantine the impacted device.\n4. Begin incident response procedures on the impacted device.\n5. Block traffic from attacker infrastructure.\n6. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "CKnife Webshell Activity",
                "primary_attack_id": null,
                "query_signature": "// Successful external -> internal HTTP POST request\nhttp:src.internal = false \nAND dst.internal = true \nAND method = \"POST\" \nAND status_code = 200 \n\n// CKnife only supports .php and .aspx filetypes\nAND uri.path MATCHES \".*(\\.php|\\.aspx)\"\nAND uri.query = null\n\n// The CKnife client uses a Java user agent by default\nAND user_agent LIKE 'Java%'\n\n// CKnife responses are plain text (not HTML)\nAND response_mime = \"text/plain\"",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 28,
                        "first_seen": "2021-12-22T09:03:30.175000Z",
                        "last_seen": "2022-08-17T08:06:15.080000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:19:40.254000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "e9008859-c038-4bd5-a805-21efffd58355"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Discovery",
                "confidence": "moderate",
                "created": "2021-12-18T15:28:38.093000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:28:38.093000Z",
                "description": "This rule is designed to use the TCP Device Enumeration Observation event generated from a DMZ host that is not a scanner.  This would indicate a potentially compromised DMZ host scanning for other assets within the environment.  \n",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "TCP Device Enumeration from DMZ host",
                "primary_attack_id": null,
                "query_signature": "observation_uuid = '941428b8-fb88-454c-8f7e-19b26c64e998'",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 24,
                        "first_seen": "2022-02-02T09:04:35.714000Z",
                        "last_seen": "2022-08-17T08:04:36.650000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:28:38.093000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "2d719a2b-4efb-4ba6-8555-0cd0f9636729"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "PUA:Unauthorized Resource Use",
                "confidence": "moderate",
                "created": "2018-04-02T20:12:13.486000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-04-17T01:03:41.513000Z",
                "description": "This signature is intended to detect a cryptocurrency mining client performing a login or check-in to a cryptocurrency server. Cryptocurrency mining is a popular method of monetizing unauthorized access to hosts; however, it is also possible that this activity is the result of deliberate user behavior. To prevent unwanted expenditures of both power and system resources, Gigamon ATR recommends preventing cryptocurrency mining on company assets. \r\n\r\nGigamon ATR considers cryptocurrency mining to be moderate severity. While it poses no direct threat, it can indicate a compromised host. Gigamon ATR considers this detection moderate confidence due to the potential for these signatures to detect benign traffic with similar strings in the packet contents.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying the presence of coinmining software on the impacted asset.\r\n2. Determine if this is legitimate and approved use of coinmining software.\r\n3. Remove software if unnecessary.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip"
                ],
                "name": "Cryptocurrency Mining Client Check-in",
                "primary_attack_id": "T1095",
                "query_signature": "suricata:sig_id IN (\r\n    // ET POLICY Crypto Coin Miner Login\r\n    // https://doc.emergingthreats.net/2022886\r\n    2022886,\r\n\r\n    // ET POLICY Cryptocurrency Miner Checkin\r\n    // https://doc.emergingthreats.net/2024792\r\n    2024792,\r\n\r\n    // ETPRO POLICY XMR CoinMiner Usage\r\n    // https://doc.emergingthreats.net/2826930\r\n    2826930 \r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 0,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 21,
                        "first_seen": "2021-12-21T00:07:54.839000Z",
                        "last_seen": "2022-08-09T00:07:54.399000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 32,
                        "first_seen": "2021-12-21T09:36:19.449000Z",
                        "last_seen": "2022-08-16T08:36:18.896000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2022-08-11T22:41:24.071679Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "bfcb4b76-96ef-4b33-9812-58158c871f99"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 20160,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2019-05-06T13:00:29.165000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-01-16T00:27:43.540000Z",
                "description": "This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\r\n\r\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by:\r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\r\n    2. Verifying that the file is malicious in nature.\r\n2. Quarantine the impacted device.\r\n3. Begin incident response procedures on the impacted device.\r\n4. Block traffic to attacker infrastructure.\r\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Executable or Script Download From External Python SimpleHTTPServer",
                "primary_attack_id": "T1105",
                "query_signature": "http:headers.server LIKE \"SimpleHTTP/% Python/%\"\r\n// Filter for plain executable binary MIME types\r\nAND (\r\n    response_mime LIKE \"%executable%\"\r\n    OR response_mime LIKE \"%application/x-dosexec%\"\r\n    OR response_mime LIKE \"%application/x-macbinary%\"\r\n\r\n    // Commonly malicious\r\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\r\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\r\n\r\n    // System-level scripts\r\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\r\n    OR response_mime LIKE \"%x-shellscript%\"\r\n)\r\n\r\n// Outbound traffic\r\nAND src.internal = true\r\nAND (\r\n    dst.internal = false\r\n    OR (\r\n        // Not internal IP address\r\n        host.internal != true\r\n        // Proxied traffic\r\n        AND uri.scheme != null\r\n    )\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 5,
                        "first_seen": "2021-12-21T00:07:50.553000Z",
                        "last_seen": "2022-08-16T00:07:50.615000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 4,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 12,
                        "first_seen": "2022-02-01T09:35:58.269000Z",
                        "last_seen": "2022-08-16T08:35:57.466000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2022-04-27T16:26:03.115153Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "fe4d55b4-7293-425a-b549-43a22472923d"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2018-03-20T21:27:02.337000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2022-01-07T17:29:49.377000Z",
                "description": "This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the downloaded executable is malicious in nature. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:files.sha256"
                ],
                "name": "Executable Binary or Script Download via Wget or cURL",
                "primary_attack_id": "T1105",
                "query_signature": "// User Agent is Wget or cURL\r\nhttp:user_agent MATCHES \"([wW][gG][eE][tT]|[cC][uU][rR][lL]).*\"\r\n\r\n// Internal downloading from external\r\nAND src.internal = true\r\nAND (\r\n    dst.internal = false\r\n    OR (\r\n        // Not internal IP address\r\n        host.internal != true\r\n        // Proxied traffic\r\n        AND uri.scheme != null\r\n    )\r\n)\r\n\r\nAND (\r\n    // Plain executable binaries\r\n    response_mime LIKE \"%executable%\" \r\n    OR response_mime LIKE \"%application/x-dosexec%\" \r\n    OR response_mime LIKE \"%application/x-macbinary%\" \r\n\r\n    // Commonly malicious\r\n    OR response_mime LIKE \"%application/x-ms-shortcut%\" \r\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\" \r\n\r\n    // System-level scripts\r\n    OR response_mime LIKE \"%text/x-msdos-batch%\" \r\n    OR response_mime LIKE \"%x-shellscript%\" \r\n\r\n    // Filetypes not yet positively classified by FileTyper over binary content.\r\n    // Instead match by extension (also to be obviated by future FileTyper features)\r\n    OR (\r\n        status_code >= 200\r\n        AND status_code <= 300\r\n        AND response_len > 0\r\n        AND (\r\n            uri.path MATCHES \".*\\.([hH][tT][aA]|[vV][bB][sS]|[pP][sS]1|[jJ][sS][eE]|[wW][sS][fF]|[mM][sS][iI])\"\r\n            OR uri.query MATCHES \".*\\.([hH][tT][aA]|[vV][bB][sS]|[pP][sS]1|[jJ][sS][eE]|[wW][sS][fF]|[mM][sS][iI])(&.+)?\"\r\n        )\r\n    )\r\n)\r\n\r\n// Ignore some well-known sources that push down executable content\r\nAND http:host.domain NOT LIKE \"%.nodesource.com\" \r\nAND http:host.domain NOT LIKE \"%.chef.io\" \r\nAND http:host.domain NOT LIKE \"%.cloudera.com\" \r\nAND http:host.domain NOT LIKE \"%.oracle.com\" \r\nAND http:host.domain NOT LIKE \"%.microsoft.com\" \r\nAND http:host.domain NOT LIKE \"%.windowsupdate.com\" \r\nAND http:host.domain NOT LIKE \"%.dell.com\" \r\nAND http:host.domain NOT LIKE \"%.sourceforge.net\" \r\nAND http:host.domain NOT LIKE \"%.portableapps.com\" \r\nAND http:host.domain NOT LIKE \"%.virtualbox.org\"\r\nAND http:host.domain != \"cygwin.com\"",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 19,
                        "first_seen": "2022-02-01T09:35:58.269000Z",
                        "last_seen": "2022-08-16T08:35:57.466000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 20,
                        "first_seen": "2021-12-21T00:07:50.553000Z",
                        "last_seen": "2022-08-16T00:07:50.615000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2022-07-01T20:09:34.695569Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "22c9ee01-2cbd-418d-bebf-c0cb3a175602"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2021-12-18T15:39:39.100000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:39:39.100000Z",
                "description": "This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.\n",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 2] Executable Binary or Script from VPS",
                "primary_attack_id": null,
                "query_signature": "(  \n    // From a select collection of VPS providers.\n    // To be replaced with intel matching\n    dst.asn.asn_org in ('AS-CHOOPA',\n                        'Hosting Solution Ltd.', \n                        'Linode, LLC',\n                        'Digital Ocean, Inc.',\n                        'Choopa, LLC',\n                        'DigitalFyre Internet Solutions, LLC.',\n                        'OVH SAS',\n                        'Relink LTD',\n                        'Hetzner Online GmbH',\n                        'Host Sailor Ltd.',\n                        'TimeWeb Ltd.')\n                        \n    // Plain executable binaries\n    AND (response_mime LIKE \"%executable%\"\n    OR response_mime LIKE \"%application/x-dosexec%\"\n    OR response_mime LIKE \"%application/x-macbinary%\"\n    \n    // Commonly malicious\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\n    \n    // System-level scripts\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\n    OR response_mime LIKE \"%x-shellscript%\"\n    \n    // Filetypes not yet positively classified by FileTyper over binary content.\n    // Instead match by extension (also to be obviated by future FileTyper features)\n    OR (http:status_code >= 200 AND http:status_code <= 300 AND http:response_len > 0\n        AND (http:uri.uri MATCHES \".*\\.(([hH][tT][aA])|([vV][bB][sS])|([pP][sS]1)|([jJ][sS][eE])|([wW][sS][fF])|([mM][sS][iI]))\"))\n    )\n) \n\n// Whitelist known benign\nAND host.domain NOT IN (\n    'notepad-plus-plus.org' // Notepad++ source code editor\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 41,
                        "first_seen": "2021-12-21T00:07:50.553000Z",
                        "last_seen": "2022-08-16T00:07:50.615000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:39:39.100000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "bc828199-03c2-45cb-99ff-6d2713c4de60"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2021-12-18T15:48:43.904000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:48:43.904000Z",
                "description": "# Description\n\nThis logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.\n\nGigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 2] Executable or Script Download From External Python SimpleHTTPServer",
                "primary_attack_id": null,
                "query_signature": "http:headers.server LIKE \"SimpleHTTP/% Python/%\"\n// Filter for plain executable binary MIME types\nAND (\n    response_mime LIKE \"%executable%\"\n    OR response_mime LIKE \"%application/x-dosexec%\"\n    OR response_mime LIKE \"%application/x-macbinary%\"\n\n    // Commonly malicious\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\n\n    // System-level scripts\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\n    OR response_mime LIKE \"%x-shellscript%\"\n)\n\n// Outbound traffic\nAND src.internal = true\nAND (\n    dst.internal = false\n    OR (\n        // Not internal IP address\n        host.internal != true\n        // Proxied traffic\n        AND uri.scheme != null\n    )\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 20,
                        "first_seen": "2021-12-21T00:07:50.553000Z",
                        "last_seen": "2022-08-16T00:07:50.615000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:48:43.904000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "85360e3a-93a7-40d0-9db5-e1beafa80ef3"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2021-12-18T15:40:55.346000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:40:55.346000Z",
                "description": "This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity.\n\n## Next Steps\n1.  Determine if this detection is a true positive by:\n    1.  Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the downloaded executable is malicious in nature.\n3.  Quarantine the impacted device.\n3.  Begin incident response procedures on the impacted device.\n4.  Block traffic to attacker infrastructure.\n5.  Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 2] Executable Binary or Script Download via Wget or cURL",
                "primary_attack_id": null,
                "query_signature": "( // user-agent string checks\n    http:user_agent MATCHES \"[wW][gG][eE][tT].*\"\n    OR http:user_agent MATCHES \"[cC][uU][rR][lL].*\"\n)\nAND ( // Internal downloading from external\n    http:src.internal = true\n    AND http:dst.internal = false\n)\nAND ( // Plain executable binaries\n    response_mime LIKE \"%executable%\" \n    OR response_mime LIKE \"%application/x-dosexec%\" \n    OR response_mime LIKE \"%application/x-macbinary%\" \n\n    // Commonly malicious\n    OR response_mime LIKE \"%application/x-ms-shortcut%\" \n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\" \n\n    // System-level scripts\n    OR response_mime LIKE \"%text/x-msdos-batch%\" \n    OR response_mime LIKE \"%x-shellscript%\" \n\n    // Filetypes not yet positively classified by FileTyper over binary content.\n    // Instead match by extension (also to be obviated by future FileTyper features)\n    OR (http:status_code >= 200 AND http:status_code <= 300 AND http:response_len > 0\n    AND (http:uri.uri MATCHES \".*\\.(([hH][tT][aA])|([vV][bB][sS])|([pP][sS]1)|([jJ][sS][eE])|([wW][sS][fF])|([mM][sS][iI]))\"))\n) \nAND ( // Ignore some well-known sources that push down executable content\n    http:host.domain NOT LIKE \"%.nodesource.com\" \n    AND http:host.domain NOT LIKE \"%.chef.io\" \n    AND http:host.domain NOT LIKE \"%.cloudera.com\" \n    AND http:host.domain NOT LIKE \"%.oracle.com\" \n    AND http:host.domain NOT LIKE \"%.microsoft.com\" \n    AND http:host.domain NOT LIKE \"%.windowsupdate.com\" \n    AND http:host.domain NOT LIKE \"%.dell.com\" \n    AND http:host.domain NOT LIKE \"%.sourceforge.net\" \n    AND http:host.domain NOT LIKE \"%.portableapps.com\" \n    AND http:host.domain NOT LIKE \"%.virtualbox.org\"\n)\n",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 20,
                        "first_seen": "2021-12-21T00:07:50.553000Z",
                        "last_seen": "2022-08-16T00:07:50.615000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:40:55.346000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "ee538666-4159-4edf-b611-b507f40ac628"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Exfiltration",
                "confidence": "moderate",
                "created": "2021-12-18T15:26:31.390000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:26:31.390000Z",
                "description": "This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.\n   2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Trickbot Data Exfiltration",
                "primary_attack_id": "T1048.001",
                "query_signature": "//Trickbot certificate subject and issue fields the same\nssl:subject = \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\"\nAND issuer = \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\"\n//non-standard destination ports for SSL\nAND dst.port IN (447, 449)\n//outbound traffic\nAND dst.internal = false",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 56,
                        "first_seen": "2021-12-20T09:04:19.258000Z",
                        "last_seen": "2022-08-15T08:09:33.210000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2021-12-18T15:26:31.390000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "732df04c-fdbc-4715-93ce-809a6b9ebd74"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2021-12-18T15:27:31.150000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:27:31.150000Z",
                "description": "This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Evaluating the timing of the connections for beacon-like regularity.\n   2. Checking the impacted asset for other indicators of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Trickbot Banking Trojan C2",
                "primary_attack_id": null,
                "query_signature": "//Trickbot C2 traffic certificate information\nssl:subject = \"CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB\"\nAND ssl:issuer = \"CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB\"",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 56,
                        "first_seen": "2021-12-20T09:03:23.458000Z",
                        "last_seen": "2022-08-15T08:09:33.040000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:27:31.150000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "caab7261-ee92-4b78-aa29-4e47e89d7276"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "moderate",
                "created": "2021-12-18T15:17:51.538000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:17:51.538000Z",
                "description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan.\n\n### Next Steps\n1. Determine if this is a true positive by:\n   1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n   2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n   3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Trickbot Staging Download",
                "primary_attack_id": "T1105",
                "query_signature": "//Trickbot user agent\nhttp:user_agent = \"WinHTTP loader/1.0\"\n//executable download\nAND response_mime = \"application/x-dosexec\"",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 56,
                        "first_seen": "2021-12-20T09:06:10.558000Z",
                        "last_seen": "2022-08-15T08:09:09.640000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2021-12-18T15:17:51.538000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "4727a9aa-8f71-487f-8fd6-c7f64d925443"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2021-12-18T15:23:48.348000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:23:48.348000Z",
                "description": "https://us-cert.cisa.gov/ncas/alerts/aa20-302a\n\nCISA MALWARE IOCs for Hospitals 28 OCT 2020",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Custom: CISA Malware IOCs",
                "primary_attack_id": null,
                "query_signature": "ip in ('93.119.208.86', // 13 October 2020\n'92.223.89.0/24',       //August - September 2020\n'92.223.89.224',        //12 September 2020\n'92.223.89.212',        //6 September 2020\n'88.202.178.104',       //20 October 2020\n'70.32.0.107',          //21 October 2020\n'64.44.81.36',          //12 September  2020\n'45.131.211.246',       //21 October 2020\n'37.235.103.27',        //16 October 2020 \u2013 17 October 2020\n'212.102.45.0/24',      //October 2020\n'212.102.45.23',        //21 October 2020\n'212.102.45.13',        // 12 October 2020\n'185.191.207.0/24',     // February - September 2020\n'185.191.207.164',      //19 September 2020\n'184.170.241.13',       //17 October 2020 - 19 October 2020\n'156.46.54.0/24',       //October 2020\n'156.146.55.0/24',      //October 2020\n'156.146.55.195',       //15 October 2020\n'156.146.54.0/24',      // October 2020\n'156.146.54.58',        //20 October 2020\n'156.146.54.45',        //18 October 2020\n'154.3.251.56',         //16 October 2020 -21 October 2020\n'145.239.110.112',      //20 October 2020\n'104.237.232.153',      //13 October 2020 \u2013 19 October 2020\n'103.205.140.0/24',     //October 2020\n'185.183.32.177',       //October 2020\n'92.223.89.191',        //19 August 2020 -25 August 2020\n'92.223.89.187',        //26 August 2020\n'92.223.89.172',        //26 August 2020\n'212.102.45.63',        //24 August 2020\n'185.191.207.179',      // 29 July 2020\n'128.90.56.147',        // 23 June 2020\n'104.140.54.91',        //23 August 2020\n'91.239.206.181',       // 23 April 2019\n'91.223.106.201',       // 10 March 2020\n'91.223.106.148',       // 22 February 2020\n'89.165.43.244',        //24 February 2020\n'5.160.253.152',        // 24 February 2020\n'46.45.138.100',        //3 May 2020\n'185.191.207.36',       //  17 September 2019\n'185.191.207.184',      //18 February 2020\n'176.53.23.252',        //31 May 2020\n'103.205.140.30',       //11 March 2020\n'103.205.140.177'      //10 March 2020 \n) OR\nserver_name_indication matches '.*([Kk][Oo][Ss][Tt][Uu][Nn][Ii][Vv][Oo].[Cc][Oo][Mm]|[Cc][Hh][Ii][Ss][Hh][Ii][Rr].[Cc][Oo][Mm]|[Mm][Aa][Nn][Gg][Oo][Cc][Ll][Oo][Nn][Ee].[Cc][Oo][Mm]|[Oo][Nn][Ii][Xx][Cc][Ee][Ll][Ll][Ee][Nn][Tt].[Cc][Oo][Mm]).*'\n// anchdorDNS c2 domain 28 OCT 2020\nOR\nip IN ('23.95.97.59','51.254.25.115','193.183.98.66','91.217.137.37','87.98.175.85')\n //anchdorDNS c2 IP 28 OCT 2020\nOR\nip IN ('45.148.10.92','170.238.117.187','177.74.232.124','185.68.93.17','203.176.135.102','96.9.73.73','96.9.77.142','37.187.3.176','45.89.127.92','62.108.35.103','91.200.103.242','103.84.238.3','36.89.106.69','103.76.169.213','36.91.87.227','105.163.17.83','185.117.73.163','5.2.78.118','185.90.61.69','185.90.61.62','86.104.194.30','31.131.21.184','46.28.64.8','104.161.32.111','107.172.140.171','131.153.22.148','195.123.240.219','195.123.242.119','195.123.242.120','51.81.113.25','74.222.14.27')\n//trickbot 28 OCT 2020",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 62,
                        "first_seen": "2021-12-20T09:03:54.818000Z",
                        "last_seen": "2022-08-15T08:07:11.350000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:23:48.348000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "c76aff9b-0f65-48d6-8312-cc5eac8b81ba"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2021-12-18T15:21:10.880000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:21:10.880000Z",
                "description": "This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\n\nGigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.\n   2. Verifying that the file is malicious in nature.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Executable in Root of Web Directory",
                "primary_attack_id": null,
                "query_signature": "// Outbound traffic\nhttp:src.internal = true\nAND (\n    dst.internal = false\n    OR (\n        // Not internal IP address\n        host.internal != true\n        // Proxied traffic\n        AND uri.scheme != null\n    )\n)\n\n// File is Windows executable\nAND response_mime = \"application/x-dosexec\"\n// File is approx 100KB to 1MB\nAND response_len > 100kb AND response_len < 1mb\n// Requests a file ending in .exe from the web root\nAND uri.path MATCHES \"\\/[a-zA-Z0-9_\\-]+\\.[eE][xX][eE]\"\n\n// Query and Referer parameters are frequently empty\nAND uri.query = null\nAND referrer.host = null\n\n// Whitelist of acceptable sites\nAND host.domain NOT IN (\"live.sysinternals.com\")",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 4,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 76,
                        "first_seen": "2021-12-20T09:03:07.538000Z",
                        "last_seen": "2022-08-15T08:03:06.980000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:21:10.880000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2021-12-18T15:24:45.996000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:24:45.996000Z",
                "description": "This logic is intended to detect the banking trojan, Emotet. This trojan is typically loaded as a second-stage payload by other malware\n\nGigamon ATR considers Emotet high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection low confidence as the detection logic may be triggered by a non-standard executable download\n\n### Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.\n   2. Checking the affected asset for additional signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Emotet Banking Trojan Download",
                "primary_attack_id": null,
                "query_signature": "//Successful outbound GET request to dotted quad\ndst.internal=false AND method = 'GET' AND status_code = 200 AND http:host.ip != null AND\n//Executable\nheaders.content_type = 'application/octet-stream' AND response_mimes = 'application/x-dosexec' AND  \n//Missing user agent\nuser_agent=NULL",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 28,
                        "first_seen": "2021-12-20T09:03:07.538000Z",
                        "last_seen": "2022-08-15T08:03:06.980000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:24:45.996000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "1709f5a2-1563-4592-b430-16444399bb2a"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2019-01-25T22:54:36.060000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-02-25T20:45:05.475000Z",
                "description": "This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.\n\nGigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.\n    2. Checking the affected asset for additional signs of compromise.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "dst.asn.asn_org",
                    "http:host",
                    "http:uri.uri"
                ],
                "name": "IcedID Banking Trojan HTTP GET Request",
                "primary_attack_id": "T1071.001",
                "query_signature": "// Outbound traffic\r\n(\r\n    (\r\n        http:src.internal = true\r\n        OR http:source IN (\"Zscaler\")\r\n    )\r\nAND (\r\n        dst.internal = false\r\n    OR (\r\n        // Not internal IP address\r\n        host.internal != true\r\n        // Proxied traffic\r\n        AND uri.scheme != null\r\n        )\r\n    )\r\n)\r\n\r\nAND method = \"GET\"\r\nAND uri.path LIKE \"/%.php\"\r\nAND uri.query MATCHES \"[A-F0-9]{16}\"\r\n\r\n// Change to SSL\r\nAND status_code = 101",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-20T09:02:17.328000Z",
                        "last_seen": "2022-08-15T08:02:16.710000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [],
                "specificity": "tool_implementation",
                "updated": "2022-08-10T21:50:30.442195Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "3e8c54a6-1934-4517-b217-e98f342b6c5a"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2021-12-18T15:22:27.041000Z",
                "created_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "critical_updated": "2021-12-18T15:22:27.041000Z",
                "description": "This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.\n\nGigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.\n   2. Checking the affected asset for additional signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "IcedID Banking Trojan Traffic",
                "primary_attack_id": null,
                "query_signature": "// Outbound traffic\nhttp: src.internal = true\nAND (\n    // Proxied traffic\n    dst.internal != true\n    OR uri.scheme != null \n)\n\nAND method = \"GET\"\nAND uri.path LIKE \"/%.php\"\nAND uri.query MATCHES \"[A-F0-9]{16}\"\n\n// Change to SSL\nAND status_code = 101",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 28,
                        "first_seen": "2021-12-20T09:02:17.328000Z",
                        "last_seen": "2022-08-15T08:02:16.710000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:22:27.041000Z",
                "updated_user_uuid": "b7943c6c-d6a7-421f-b2be-cc0a5134932d",
                "uuid": "c559f79e-0ca7-48ac-875b-fe226308ef4d"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2021-12-18T15:41:57.247000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:41:57.247000Z",
                "description": "This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.\n\n\nICEBRG considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. ICEBRG considers this detection to be high confidence due to the uniqueness of the issuer of the SSL certificate used in the SSL requests by the trojan.\n\n## Next Steps\n1.  Determine if this is a true positive by:\n    1. Investigating for connections outbound to ports 447 and 449 from the affected host.\n    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).\n    3.  Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.\n2.  Quarantine the impacted device.\n3.  Begin incident response procedures on the impacted device.\n4.  Block traffic to attacker infrastructure.\n5.  Search for other impacted devices.",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 1] Trickbot Staging Download",
                "primary_attack_id": null,
                "query_signature": "ssl:issuer like '%sd-97597.dedibox.fr%'",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 22,
                        "first_seen": "2021-12-20T00:01:04.391000Z",
                        "last_seen": "2022-08-15T00:01:08.494000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:41:57.247000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "37e8edaa-ef2e-478b-a2cf-dfc85aae38c6"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Posture:Potentially Unauthorized Software or Device",
                "confidence": "high",
                "created": "2018-03-16T19:49:01.018000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-02-18T01:01:03.282000Z",
                "description": "This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as \"Deep Web\" or \"Dark Web\" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  \r\n\r\nGigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. \r\n2. Ensure legitimate and approved use of Tor. \r\n3. Remove any unapproved software.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "ssl:server_name_indication",
                    "ssl:subject",
                    "ssl:issuer",
                    "ssl:ja3"
                ],
                "name": "Tor Connection Initialization",
                "primary_attack_id": "T1090",
                "query_signature": "src.internal = true \r\nAND (\r\n    // Random .com SNI\r\n    server_name_indication MATCHES \"www\\..*\\.com\"\r\n    // Random .net cert subject\r\n    AND subject MATCHES \"CN=www\\..*\\.net\"\r\n    // Random .com cert issuer\r\n    AND issuer MATCHES \"CN=www\\..*\\.com\"\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-19T05:12:21.554000Z",
                        "last_seen": "2022-08-14T11:13:39.732000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": "src.internal != false // just testing something out -- vien y"
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 56,
                        "first_seen": "2021-12-19T16:25:16.927000Z",
                        "last_seen": "2022-08-14T15:31:13.353000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "low",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "tool_implementation",
                "updated": "2021-03-17T23:36:21.343000Z",
                "updated_user_uuid": "9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3",
                "uuid": "7108db9b-6158-458f-b5b4-082f2ebae0f7"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Infection Vector",
                "confidence": "low",
                "created": "2022-01-28T20:06:48.014343Z",
                "created_user_uuid": "46b5401c-82a2-44ac-8d87-fa45340d5a64",
                "critical_updated": "2022-01-28T20:06:48.014343Z",
                "description": "Important!",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Detection rule 2022.1.2",
                "primary_attack_id": null,
                "query_signature": "src.ip = '172.16.99.131'",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 52,
                        "first_seen": "2022-01-23T16:26:16.783000Z",
                        "last_seen": "2022-08-14T15:26:29.489000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2022-01-28T20:06:48.014343Z",
                "updated_user_uuid": "46b5401c-82a2-44ac-8d87-fa45340d5a64",
                "uuid": "421af990-caf9-4f4b-9fc5-339c53016e4b"
            },
            {
                "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Exploitation",
                "confidence": "low",
                "created": "2022-01-24T20:28:14.614000Z",
                "created_user_uuid": "46b5401c-82a2-44ac-8d87-fa45340d5a64",
                "critical_updated": "2022-01-24T20:28:14.614000Z",
                "description": "",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Test rule from investigation 2022.1.1",
                "primary_attack_id": null,
                "query_signature": "src.ip = '172.16.99.131'",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 2,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 52,
                        "first_seen": "2022-01-23T16:26:16.783000Z",
                        "last_seen": "2022-08-14T15:26:29.489000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2022-01-24T20:28:14.614000Z",
                "updated_user_uuid": "46b5401c-82a2-44ac-8d87-fa45340d5a64",
                "uuid": "e67675e7-3914-4d4c-9dd5-f239b4defae2"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Infection Vector",
                "confidence": "moderate",
                "created": "2019-10-01T18:06:44.469000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-02-26T00:32:08.625000Z",
                "description": "This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.\r\n\r\nKerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.\r\n\r\nGigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.\r\n\r\n## Next Steps\r\n1. Review the services requested and determine if an SPN should be set for a given account.\r\n2. Ensure that service accounts have strong passwords.\r\n3. Review Kerberos logs to determine the user account involved.\r\n4. Verify that the activity was authorized.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "Kerberoasting",
                "primary_attack_id": "T1558.003",
                "query_signature": "// High Service Diversity in Kerberos TGS Requests\r\nobservation_uuid = \"2bd4a1d2-729d-47fc-b767-c471b456775e\"\r\nAND observation_confidence IN (\"moderate\", \"high\")",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 1,
                        "first_seen": "2021-12-19T16:26:13.821000Z",
                        "last_seen": "2022-08-14T15:26:28.279000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-21T01:01:03.317000Z",
                        "last_seen": "2022-08-09T01:01:05.585000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2022-05-05T02:01:53.830468Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "0de05ba7-d42d-4de8-aff7-aeb4350bb564"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 30240,
                "category": "Attack:Command and Control",
                "confidence": "high",
                "created": "2018-12-28T21:26:43.596000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-01-15T20:36:45.463000Z",
                "description": "This logic is intended to detect a Windows banner over ICMP. This Windows banner appears at the start of a reverse shell session over ICMP, often started with tools such as `icmpsh`. By using ICMP, attackers are often able to circumvent firewall protections.\r\n\r\nGigamon ATR considers a Windows banner over ICMP high severity, as it is indicative of successful malicious code execution. Gigamon ATR considers this detection high confidence due to the uniqueness of the Windows banner string in ICMP traffic.\r\n\r\n## Next Steps\r\n1. Determine if this detection is a true positive by starting packet capture and investigating ICMP traffic produced by the impacted asset, looking for the presence of plaintext shell commands.\r\n2. Quarantine the impacted device.\r\n3. Search for other impacted devices.\r\n4. Block traffic to attacker infrastructure.\r\n5. Begin incident response procedures on the impacted device. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip"
                ],
                "name": "Windows Banner String in ICMP Request",
                "primary_attack_id": "T1095",
                "query_signature": "// alert icmp any any -> any any (msg: \"ATR COMMAND_AND_CONTROL ICMP Windows Banner Shell String in ICMP Request\"; itype:8; icode:0; content:\"Microsoft Windows [Version\"; metadata: DET-4114; classtype:misc-attack; sid:2900086; rev:1;)\r\nsig_id = 2900086 AND sig_rev = 1",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 1,
                        "first_seen": "2021-12-19T16:26:12.008000Z",
                        "last_seen": "2022-08-14T15:26:26.040000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-04-09T22:47:06.093000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "b73126a8-5cd1-4c2f-a0ef-ce12e02e4b31"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2018-05-15T18:08:55.511000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-07-08T21:59:20.870000Z",
                "description": "This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. \n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. \n\n## Next Steps\n1. Determine if this detection is a true positive by checking the host for signs of compromise. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent"
                ],
                "name": "Pony or Hancitor Second Stage Download",
                "primary_attack_id": "T1105",
                "query_signature": "http:method = \"POST\"\r\nAND uri.path LIKE \"%/gate.php\"\r\nAND (\r\n    response_len > 1MB\r\n    OR user_agent LIKE \"%Windows 98%\"\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-19T08:12:15.184000Z",
                        "last_seen": "2022-08-14T11:10:28.642000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 16,
                        "first_seen": "2022-02-06T16:22:18.923000Z",
                        "last_seen": "2022-08-14T15:22:31.910000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": "T1104",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [],
                "specificity": "tool_implementation",
                "updated": "2021-03-17T23:36:35.422000Z",
                "updated_user_uuid": "9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3",
                "uuid": "2d06c01f-5ae4-4346-8d6a-99926dcac4f1"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2018-03-23T22:03:57.728000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-01-22T22:17:56.563000Z",
                "description": "This logic is intended to detect the download of PowerShell scripts from external HTTP servers. While commonly used in systems administration, PowerShell scripts are also used extensively by malware authors for post-exploitation actions.\n\nGigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence, as PowerShell is commonly used for administrative tasks.\n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Determining if the script retrieved was downloaded from a reputable source, and what the purpose may be. \n    2. Investigating the impacted device to determine what initiated the request.\n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:files.sha256"
                ],
                "name": "PowerShell Downloaded from External HTTP Server",
                "primary_attack_id": "T1105",
                "query_signature": "// Looking for powershell (.ps1) downloads over HTTP from external servers.\r\nhttp:dst.internal = false\r\nAND http:uri.path MATCHES \".*\\.ps1([^0-9a-zA-Z].*)?\"\r\n\r\n// Require that the server returned a file and FileTyper identified it as plain text.\r\nAND response_mime LIKE \"%text/plain%\"\r\n\r\n// Whitelist known good domains that commonly serve powershell\r\nAND http:host.domain NOT LIKE \"%.sophosxl.net\"\r\nAND http:host.domain NOT LIKE \"%.microsoft.com\"\r\nAND http:host.domain NOT LIKE \"%.boxstarter.org\"\r\nAND http:host.domain NOT IN (\r\n    \"boxstarter.org\", // Chocolately automation\r\n    \"chocolatey.org\", // Chocolately automation\r\n    \"lt.xamin.com\" // Managed IT Services\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 16,
                        "first_seen": "2022-02-06T12:45:02.956000Z",
                        "last_seen": "2022-08-14T11:45:15.504000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": "T1071",
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-08-27T17:59:57.392000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "65ce4d1e-a7dd-4966-9db1-7c9e0efe6266"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Posture:Potentially Unauthorized Software or Device",
                "confidence": "high",
                "created": "2021-12-18T15:49:48.350000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:49:48.350000Z",
                "description": "This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as \"Deep Web\" or \"Dark Web\" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.\n\nGigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.\n\n## Next Steps\n1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network.\n2. Ensure legitimate and approved use of Tor.\n3. Remove any unapproved software. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Practical Packet Analysis] Tor Connection Initialization",
                "primary_attack_id": null,
                "query_signature": "src.internal = true \nAND (\n    // Random .com SNI\n    server_name MATCHES \"www\\..*\\.com\"\n    // Random .net cert subject\n    AND subject MATCHES \"CN=www\\..*\\.net\"\n    // Random .com cert issuer\n    AND issuer MATCHES \"CN=www\\..*\\.com\"\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 2,
                        "first_seen": "2021-12-19T05:12:21.554000Z",
                        "last_seen": "2022-08-14T11:13:39.732000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "low",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:49:48.350000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "9d838451-4d33-4124-b6fd-43439217bee3"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "high",
                "created": "2021-12-18T15:43:06.963000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:43:06.963000Z",
                "description": "This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network.\n\nGigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity.\n\n## Next Steps\n1. Determine if this detection is a true positive by checking the host for signs of compromise.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Practical Packet Analysis] Pony or Hancitor Second Stage Download",
                "primary_attack_id": null,
                "query_signature": "http:method = \"POST\"\nAND uri.path LIKE \"%/gate.php\"\nAND (\n    response_len > 1MB\n    OR user_agent LIKE \"%Windows 98%\"\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 3,
                        "first_seen": "2021-12-19T08:12:15.184000Z",
                        "last_seen": "2022-08-14T11:10:28.642000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:43:06.963000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "9c5e5aae-b3fb-47e7-998e-4cce5f34dd1e"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "low",
                "created": "2018-03-19T17:46:47.913000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-11-24T17:21:38.868000Z",
                "description": "This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.\r\n\r\nGigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.\r\n\r\n## Next Steps \r\n1. Determine if this detection is a true positive by: \r\n    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. \r\n    2. Verifying that the file is malicious in nature. \r\n2. Quarantine the impacted device. \r\n3. Begin incident response procedures on the impacted device. \r\n4. Block traffic to attacker infrastructure. \r\n5. Search for other impacted devices.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:uri.uri",
                    "http:user_agent",
                    "http:response_mimes",
                    "http:files.sha256"
                ],
                "name": "Executable Binary or Script from VPS",
                "primary_attack_id": "T1105",
                "query_signature": "(  \r\n    // From a select collection of VPS providers.\r\n    // To be replaced with intel matching\r\n    dst.asn.asn_org in (\r\n        \"Choopa, LLC\",\r\n        \"DigitalFyre Internet Solutions, LLC.\",\r\n        \"DigitalOcean, LLC\",\r\n        \"DIGITALOCEAN-ASN\",\r\n        \"Hetzner Online GmbH\",\r\n        \"Host Sailor Ltd.\",\r\n        \"Hosting Solution Ltd.\",\r\n        \"Linode, LLC\",\r\n        \"OVH SAS\",\r\n        \"Relink LTD\",\r\n        \"TimeWeb Ltd.\"\r\n    )\r\n                        \r\n    // Plain executable binaries\r\n    AND (response_mime LIKE \"%executable%\"\r\n    OR response_mime LIKE \"%application/x-dosexec%\"\r\n    OR response_mime LIKE \"%application/x-macbinary%\"\r\n    \r\n    // Commonly malicious\r\n    OR response_mime LIKE \"%application/x-ms-shortcut%\"\r\n    OR response_mime LIKE \"%application/vnd.ms-htmlhelp%\"\r\n    \r\n    // System-level scripts\r\n    OR response_mime LIKE \"%text/x-msdos-batch%\"\r\n    OR response_mime LIKE \"%x-shellscript%\"\r\n    \r\n    // Filetypes not yet positively classified by FileTyper over binary content.\r\n    // Instead match by extension (also to be obviated by future FileTyper features)\r\n    OR (http:status_code >= 200 AND http:status_code <= 300 AND http:response_len > 0\r\n        AND (http:uri.uri MATCHES \".*\\.(([hH][tT][aA])|([vV][bB][sS])|([pP][sS]1)|([jJ][sS][eE])|([wW][sS][fF])|([mM][sS][iI]))\"))\r\n    )\r\n) \r\n\r\n// Whitelist known benign\r\nAND \r\n(\r\n    host.domain NOT IN (\r\n        \"eu-1-downloads.airtame.com\", // Wireless HDMI / Digital Signage application\r\n        \"notepad-plus-plus.org\" // Notepad++ source code editor\r\n    )\r\n    AND host.domain NOT LIKE \"%.wireshark.org\"\r\n    AND response_mime NOT IN (\"application/x-alliant-executable\", \"application/x-alpha-executable\")\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 16,
                        "first_seen": "2022-02-06T10:38:17.519000Z",
                        "last_seen": "2022-08-14T09:38:37.403000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": "procedure",
                "updated": "2021-03-17T23:37:00.727000Z",
                "updated_user_uuid": "9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3",
                "uuid": "e1bb1e78-3a25-4c52-b766-402b4f8e9849"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Posture:Potentially Unauthorized Software or Device",
                "confidence": "high",
                "created": "2018-03-19T17:45:25.580000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2021-03-10T23:10:08.942000Z",
                "description": "This logic is intended to detect active BitTorrent file sharing clients. BitTorrent is a peer-to-peer (P2P) client commonly used for sharing large files. Having the client installed on a host enables the user to both send and receive files. This activity frequently includes the download or sharing of illegally obtained files, and utilizes organizational resources to perform these activities, putting the company at risk.\n\nGigamon ATR considers BitTorrent activity low severity due to the relatively innocuous nature of the software that is installed. Gigamon ATR considers this detection high confidence due to the uniqueness of the user agent strings used in HTTP communications by BitTorrent clients. \n\n## Next Steps \n1. Determine if this detection is a true positive by inspecting the affected asset for installed BitTorrent client software.\n2. Determine legitimate business need for software.\n3. Remove software if unnecessary.",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent"
                ],
                "name": "BitTorrent Client User Agent",
                "primary_attack_id": "T1071",
                "query_signature": "(\r\n    http:src.internal = true\r\n    OR http:source IN (\"Zscaler\")\r\n)\r\n\r\nAND (\r\n   user_agent IN (\"FDM 3.x\", \"Hydra HttpRequest\")\r\n    OR user_agent LIKE \"BTWebClient%\"\r\n    OR user_agent LIKE \"ACEStream/%\"\r\n    OR user_agent LIKE \"Transmission/%\"\r\n    OR user_agent LIKE \"Azureus%\"\r\n    OR user_agent MATCHES \".*?[tT][oO][rR][rR][eE][nN][tT].*\"\r\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 27,
                        "first_seen": "2021-12-18T09:02:11.883000Z",
                        "last_seen": "2022-08-13T08:02:29.949000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "low",
                "shared_account_uuids": null,
                "source_excludes": [],
                "specificity": "tool_implementation",
                "updated": "2021-09-24T15:38:00.786000Z",
                "updated_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "uuid": "7d561d24-7c6a-407f-b14b-8e60ca3b8432"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2021-12-18T15:46:38.978000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:46:38.978000Z",
                "description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.\n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.\n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.\n2. Quarantine the impacted device.\n3. Begin incident response procedures on the impacted device.\n4. Block traffic to attacker infrastructure.\n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 5] Empire Default Profile",
                "primary_attack_id": null,
                "query_signature": "// Default user-agent for Empire \nhttp:user_agent = \"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\"\n// Default URIs for Empire\nAND uri.path IN (\"/admin/get.php\", \"/login/process.php\") \n// Default referrer behavior\nAND http:referrer.uri = null\n",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 46,
                        "first_seen": "2021-12-24T00:02:37.670000Z",
                        "last_seen": "2022-08-12T00:45:11.918000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:46:38.978000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "5cd225d7-1a65-4653-a5be-ae034e5f2934"
            },
            {
                "account_uuid": "b1f533b5-6360-494a-9f8b-9d90f1ad0207",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Command and Control",
                "confidence": "moderate",
                "created": "2018-03-19T17:45:11.192000Z",
                "created_user_uuid": "cd3ea8eb-e014-4f62-905d-78a021c768b2",
                "critical_updated": "2020-12-09T00:15:53.487000Z",
                "description": "This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. \n\nGigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. \n\n## Next Steps \n1. Determine if this detection is a true positive by: \n    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. \n    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. \n2. Quarantine the impacted device. \n3. Begin incident response procedures on the impacted device. \n4. Block traffic to attacker infrastructure. \n5. Search for other impacted devices. ",
                "device_ip_fields": [
                    "src.ip"
                ],
                "enabled": true,
                "indicator_fields": [
                    "dst.ip",
                    "http:host",
                    "http:uri.uri",
                    "http:user_agent"
                ],
                "name": "Empire Default Profile",
                "primary_attack_id": "T1071.001",
                "query_signature": "// Default user-agent for Empire \r\nhttp:user_agent = \"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko\"\r\n// Default URIs for Empire\r\nAND uri.path IN (\"/admin/get.php\", \"/login/process.php\") \r\n// Default referrer behavior\r\nAND http:referrer.uri = null",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 3,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 63,
                        "first_seen": "2021-12-24T00:02:37.670000Z",
                        "last_seen": "2022-08-12T00:45:11.918000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    },
                    {
                        "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                        "detection_count": 0,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 18,
                        "first_seen": "2021-12-19T10:13:11.853000Z",
                        "last_seen": "2022-02-13T15:42:35.898000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": "http:user_agent != 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'"
                    }
                ],
                "run_account_uuids": null,
                "secondary_attack_id": null,
                "severity": "high",
                "shared_account_uuids": null,
                "source_excludes": [],
                "specificity": "tool_implementation",
                "updated": "2021-03-17T23:37:16.914000Z",
                "updated_user_uuid": "9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3",
                "uuid": "c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6"
            },
            {
                "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                "auto_resolution_minutes": 10080,
                "category": "Attack:Installation",
                "confidence": "moderate",
                "created": "2021-12-18T15:45:36.261000Z",
                "created_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "critical_updated": "2021-12-18T15:45:36.261000Z",
                "description": "This logic is intended to detect successful downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.\n\nGigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.\n\n## Next Steps\n1. Determine if this detection is a true positive by:\n      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.\n      2. Inspecting the downloaded application for malicious content.\n2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host. ",
                "device_ip_fields": [
                    "DEFAULT"
                ],
                "enabled": true,
                "indicator_fields": null,
                "name": "[Scenario 5] HTML Application (HTA) Download",
                "primary_attack_id": null,
                "query_signature": "// Look for HTA by URI or by MimeType\n(\n    http:uri.path MATCHES \".*?\\.[hH][tT][aA]\"\n    OR http:response_mime = \"application/hta\"\n)\n\n// Successful external downloads only\nAND (\n    dst.internal = false\n    OR (\n        // Not an internal IP\n        host.ip != null\n        // Proxied traffic\n        AND uri.scheme != null\n    )\n)\nAND status_code >= 200 \nAND status_code < 300\n\n// Whitelist out known good that does this\nAND host.domain NOT LIKE \"%.kaspersky.com\"\nAND host.domain != \"kav8.zonealarm.com\"\nAND (\n    host.domain != \"downloadupdates.axway.com\"\n    OR uri.path NOT MATCHES  \"/kaspersky(86)?/.*\"\n)\nAND (\n    user_agent NOT LIKE \"HelloTalk %\"\n    OR uri.path NOT MATCHES \"/[0-9]{8}/[0-9a-f]{17}_[0-9a-f]{5}\\.hta\"\n)",
                "rule_accounts": [
                    {
                        "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                        "detection_count": 1,
                        "detection_muted_count": 0,
                        "detection_resolved_count": 21,
                        "first_seen": "2021-12-24T00:01:30.364000Z",
                        "last_seen": "2022-08-12T00:01:32.770000Z",
                        "muted": false,
                        "muted_comment": null,
                        "muted_timestamp": null,
                        "muted_user_uuid": null,
                        "query_filter": null
                    }
                ],
                "run_account_uuids": [
                    "a24b62ea-776d-4c62-ac8e-c980689ea71f"
                ],
                "secondary_attack_id": null,
                "severity": "moderate",
                "shared_account_uuids": null,
                "source_excludes": [
                    "Zscaler"
                ],
                "specificity": null,
                "updated": "2021-12-18T15:45:36.261000Z",
                "updated_user_uuid": "2964a059-e470-4622-929e-2cadcccf98f4",
                "uuid": "d1740713-b975-4341-a580-456511fcb784"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|account_uuid|auto_resolution_minutes|category|confidence|created|created_user_uuid|critical_updated|description|device_ip_fields|enabled|indicator_fields|name|primary_attack_id|query_signature|rule_accounts|run_account_uuids|secondary_attack_id|severity|shared_account_uuids|source_excludes|specificity|updated|updated_user_uuid|uuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Discovery | low | 2020-08-17T23:04:31.001000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-05-12T17:34:08.014000Z | This logic is intended to detect devices using LDAP to enumerate domain information. After compromising a network, adversaries may query Active Directory to better understand the layout of the organization and to determine assets to compromise.<br/><br/>Gigamon ATR considers this activity high severity as it could be indicative of active compromise. Gigamon ATR considers this detection low confidence because such queries may be the result of legitimate tools or administrator activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by investigating the cause of the LDAP queries.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Search enumerated objects for signs of compromise.  | src.ip | true |  | Enumeration of Domain Objects | T1087.002 | (sig_id = 2900687 AND sig_rev = 1)<br/>OR (sig_id = 2900688 AND sig_rev = 1)<br/>OR (sig_id = 2900689 AND sig_rev = 1)<br/>OR (sig_id = 2900690 AND sig_rev = 1)<br/>OR (sig_id = 2900691 AND sig_rev = 1)<br/>OR (sig_id = 2900741 AND sig_rev = 2)<br/>OR (sig_id = 2900742 AND sig_rev = 1)<br/>OR (sig_id = 2900746 AND sig_rev = 2)<br/><br/>/*<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory Domain Container Enumeration"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; pcre:"/\xa3\x84\x00\x00\x00\x26\x04\x0eobjectcategory\x04\x14grouppolicycontainer/i"; pcre:"/\xa3\x84\x00\x00\x00\x24\x04\x0eobjectcategory\x04\x12organizationalunit/i"; pcre:"/\xa3\x84\x00\x00\x00\x15\x04\x0bobjectclass\x04\x06domain/i"; classtype: misc-attack; metadata: DET-6003; sid:2900687; rev:1;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory Users, Computers, and OU Enumeration Within OU"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; content:"OU="; distance:7; pcre:"/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09805306368/i"; pcre:"/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09805306369/i"; pcre:"/\xa3\x84\x00\x00\x00\x21\x04\x0bobjectclass\x04\x12organizationalunit/i"; classtype: misc-attack; metadata: DET-6003; sid:2900688; rev:1;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory Users, Computers, and OU Enumeration Within Domain"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; content:"DC="; distance:7; pcre:"/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09805306368/i"; pcre:"/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09805306369/i"; pcre:"/\xa3\x84\x00\x00\x00\x21\x04\x0bobjectclass\x04\x12organizationalunit/i"; classtype: misc-attack; metadata: DET-6003; sid:2900689; rev:1;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory User and Computer Enumeration Within Container"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; content:"CN="; distance:7; pcre:"/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09805306368/i"; pcre:"/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09805306369/i"; classtype: misc-attack; metadata: DET-6003; sid:2900690; rev:1;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory Domain Group Membership Query"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; pcre: "/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09268435456/i"; pcre: "/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09268435457/i"; pcre: "/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09536870912/i"; pcre: "/\xa3\x84\x00\x00\x00\x1b\x04\x0esamaccounttype\x04\x09536870913/i"; pcre: "/\x87\x0eprimarygroupid/i"; classtype: misc-attack; metadata: DET-6003; sid:2900691; rev:1;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory All Group Policy Objects"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; pcre: "/[\x00\x01]\xa3\x84\x00\x00\x00\x26\x04\x0eobjectCategory\x04\x14groupPolicyContainer\x30\x84\x00\x00\x00/i"; classtype: misc-attack; metadata: DET-6003; sid:2900746; rev:2;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory All Objects with SPNs Set"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; pcre: "/(?<!\xa2\x84\x00\x00\x00.)\x87\x14serviceprincipalname/i"; classtype: misc-attack; metadata: DET-6003; sid:2900741; rev:2;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory OUs or Domains With Linked Group Policy Objects"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; pcre: "/\xa0\x84\x00\x00\x00[\x5a\x53]\xa1\x84\x00\x00\x00\x45\xa3\x84\x00\x00\x00\x24\x04\x0eobjectcategory\x04\x12organizationalUnit\xa3\x84\x00\x00\x00\x15\x04\x0bobjectclass\x04\x06domain\x87\x06gplink(\x87\x05flags)?/i"; classtype: misc-attack; metadata: DET-6003; sid:2900742; rev:1;)<br/>* alert tcp $HOME_NET any -> $HOME_NET 389 (msg:"ATR DISCOVERY LDAP Active Directory Users with SID History Set"; flow:established,to_server,no_stream; content:"\|30 84 00 00\|"; content:"\|63\|"; distance:5; pcre: "/(?<!\xa2\x84\x00\x00\x00.)\x87\x0asidHistory\x30\x84\x00\x00\x00/i"; classtype: misc-attack; metadata: DET-6003; sid:2900743; rev:2;)<br/>*/ | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-21T01:01:03.272000Z', 'last_seen': '2022-08-16T01:01:03.814000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-19T16:26:13.601000Z', 'last_seen': '2022-08-18T10:37:04.588000Z'} |  | T1069.002 | high |  | Zscaler | procedure | 2021-05-12T17:42:52.843000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 810076e5-c11e-4948-856e-10e437c563e6 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | moderate | 2018-03-19T17:45:06.418000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2022-01-06T18:00:18.510000Z | This logic is intended to detect downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.<br/><br/>Gigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.<br/>      2. Inspecting the downloaded application for malicious content.<br/>2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host.  | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent | HTML Application (HTA) Download | T1105 | // Look for HTA by URI or by MimeType<br/>(<br/>    http:uri.path MATCHES ".*?\.[hH][tT][aA]"<br/>    OR http:response_mime = "application/hta"<br/>)<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not an internal IP<br/>        host.ip != null<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>)<br/><br/>// Whitelist out known good that does this<br/>AND host.domain NOT LIKE "%.kaspersky.com"<br/>AND host.domain != "kav8.zonealarm.com"<br/>AND (<br/>    host.domain != "downloadupdates.axway.com"<br/>    OR uri.path NOT MATCHES  "/kaspersky(86)?/.*"<br/>)<br/>AND (<br/>    user_agent NOT LIKE "HelloTalk %"<br/>    OR uri.path NOT MATCHES "/[0-9]{8}/[0-9a-f]{17}_[0-9a-f]{5}\.hta"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 21, 'first_seen': '2021-12-24T00:01:30.364000Z', 'last_seen': '2022-08-12T00:01:32.770000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 58, 'first_seen': '2021-12-19T10:38:17.642000Z', 'last_seen': '2022-08-18T08:04:29.641000Z'} |  | T1218.005 | moderate |  | Zscaler | procedure | 2022-08-02T15:09:22.034171Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | f290eaaf-4748-4b35-a32e-0b88e1b0beee |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Exfiltration | moderate | 2019-10-14T20:16:09.935000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-12-10T00:05:15.787000Z | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true | dst.ip,<br/>ssl:server_name_indication,<br/>ssl:subject,<br/>ssl:issuer,<br/>ssl:ja3 | Trickbot Data Exfiltration over SSL | T1048.002 | ssl:subject = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"<br/>AND issuer = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"<br/>AND dst.port IN (447, 449)<br/>AND dst.internal = false | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-20T00:01:04.359000Z', 'last_seen': '2022-08-18T00:02:42.089000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-20T09:04:19.258000Z', 'last_seen': '2022-08-15T08:09:33.210000Z'} |  |  | high |  | Zscaler | tool_implementation | 2021-06-18T17:31:48.655000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | db969564-0ba3-43d6-ad9e-67bf2509006f |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Exfiltration | moderate | 2021-12-18T15:36:46.843000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:36:46.843000Z | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>## Next Steps<br/>1. Determine if this is a true positive by:<br/>    1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>    2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | DEFAULT | true |  | [Scenario 1] Trickbot Data Exfiltration over SSL |  | ssl:subject = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"<br/>AND issuer = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"<br/>AND dst.port IN (447, 449)<br/>AND dst.internal = false | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 68, 'first_seen': '2021-12-20T00:01:04.359000Z', 'last_seen': '2022-08-18T00:02:42.089000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | high |  | Zscaler |  | 2021-12-18T15:36:46.843000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 43030c3b-da2a-4016-9035-5958aaea5b8e |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Command and Control | moderate | 2018-08-01T19:38:43.696000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-12-10T00:03:18.840000Z | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Evaluating the timing of the connections for beacon-like regularity. <br/>    2. Checking the impacted asset for other indicators of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | src.ip | true | dst.ip,<br/>ssl:server_name_indication,<br/>ssl:subject,<br/>ssl:issuer,<br/>ssl:ja3 | Trickbot Banking Trojan SSL Certificate | T1071.001 | ssl:subject = "CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB"<br/>AND ssl:issuer = "CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB" | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-23T00:01:07.921000Z', 'last_seen': '2022-08-18T00:02:07.397000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-20T09:03:23.458000Z', 'last_seen': '2022-08-15T08:09:33.040000Z'} |  |  | high |  | Zscaler | tool_implementation | 2022-08-10T21:51:19.244790Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2bbb5dda-ed01-4f49-888b-057233568abe |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | moderate | 2018-03-22T23:22:11.307000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-11-18T19:38:39.719000Z | This logic is intended to detect malicious executable binaries and scripts downloaded over HTTP from a server referenced by IP (i.e., Dotted Quad). Instead of domain names, threat actors sometimes use hardcoded IPs for communication between compromised devices and attacker infrastructure. When using hardcoded IPs with HTTP, the IP will be present in the Host header field instead of a domain name.<br/><br/>Note that the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded. <br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection moderate confidence because, while rare, some legitimate services host executable binaries and scripts via hardcoded IPs. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the downloaded file is not a benign file from a reputable service.<br/>    2. Verifying that the file is malicious in nature. <br/>2. Determine if the file was executed on the impacted asset.<br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Executable Binary or Script Downloaded from Dotted Quad | T1105 | (<br/>    // Select HTTP dotted-quad requests to an external server<br/>    http:host.ip != null<br/>    AND dst.internal = false<br/>) AND (<br/>    // Executable Binaries or Scripts (x-alliant-executable is not reliable)<br/>    (<br/>        response_mime LIKE "%executable%" <br/>        AND response_mime != "application/x-alliant-executable"<br/>    )<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/><br/>    // Filetypes not yet positively classified by FileTyper over binary content.<br/>    // Instead match by extension (also to be obviated by future FileTyper features)<br/>    OR (<br/>        http:status_code >= 200<br/>        AND http:status_code <= 300<br/>        AND http:response_len > 0<br/>        AND http:uri.path MATCHES ".*\.(([hH][tT][aA])\|([vV][bB][sS])\|([pP][sS]1)\|([jJ][sS][eE])\|([wW][sS][fF])\|([mM][sS][iI]))"<br/>    )<br/>)<br/><br/>// Remove Sophos antivirus<br/>AND http:uri.path NOT LIKE "/SophosUpdate/%" | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 6, 'detection_muted_count': 0, 'detection_resolved_count': 110, 'first_seen': '2021-12-20T09:03:07.538000Z', 'last_seen': '2022-08-16T08:35:57.466000Z'},<br/>{'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 65, 'first_seen': '2021-12-21T00:07:50.553000Z', 'last_seen': '2022-08-18T00:01:41.319000Z'} |  |  | moderate |  | Zscaler | procedure | 2021-12-17T22:37:00.932000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 376a54b4-1456-430d-bceb-4ff58bed65d0 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | low | 2021-12-18T15:38:37.470000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:38:37.470000Z | ## Description<br/><br/>This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/>## Next Steps<br/><br/>1.  Investigate the listed events to determine if the downloaded file was malicious.<br/>2.    Investigate the host for compromise. | DEFAULT | true |  | [Scenario 1] Executable Retrieved with Minimal HTTP Headers |  | // Most malware downloaded via macro or downloader uses short URI's<br/>http:uri.path MATCHES "/.{0,32}"<br/><br/>// No referrer<br/>AND http:referrer.uri = null<br/><br/>AND http:response_mime IN ("application/x-dosexec", "application/x-mach-o-executable", "application/x-executable")<br/>AND http:status_code = 200<br/><br/>// Majority of downloaders use only GET<br/>and http:method = "GET"<br/><br/>// No user agent, uncommon<br/>AND http:user_agent = null<br/><br/>AND http:headers.accept = null<br/>AND http:headers.refresh = null<br/>AND headers.cookie_length IN (0, null)<br/><br/>// Most malicious downloads are small, < 2MB<br/>AND http:response_len<2mb<br/><br/>AND dst.internal = false<br/><br/>// Common distribution / update sites<br/>AND http:host NOT MATCHES ".{0,50}(\.beyondtrust\.com\|\.microsoft\.com\|audiochannel\.net\|\.autodesk\.com\|\.dell\.com\|\,windowsupdate.com\|\.hp\.com\|\.cloudfront\.net\|\.mozilla\.org\|\.windows\.net\|\.dellsupportcenter\.com\|\.lavasoft\.com\|\.bytefence\.com\|\.techsmith\.com\|\.solidworks.com)" <br/><br/>// Various akamai / cdn / hoster / legit software distribution asns <br/>AND dst.asn.asn NOT IN (22611,9891,4249,20940,15133,6461,9498,209,31976) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 65, 'first_seen': '2021-12-20T00:01:02.949000Z', 'last_seen': '2022-08-18T00:01:41.319000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | high |  | Zscaler |  | 2021-12-18T15:38:37.470000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 1d315815-f7c5-4086-83f9-db2ced7d11df |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | low | 2019-04-29T17:52:36.003000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-01-11T19:21:22.305000Z | This logic is intended to detect downloads of executable files with very few HTTP header fields set. This is common among first stage malware downloaders or shellcode, where size is important and many header fields will not be included automatically by an API being used for HTTP requests.<br/><br/>Gigamon ATR considers any code execution to be high severity. Gigamon ATR considers this rule to be low confidence, as installers or updaters will often make similar HTTP requests (see the whitelist included in the detection logic).<br/><br/>## Next Steps<br/>1. Investigate the listed events to determine if the downloaded file was malicious.<br/>2. Investigate the host for compromise. | src.ip | true | dst.ip,<br/>dst.asn.asn_org,<br/>http:host,<br/>http:uri.uri,<br/>http:response_mimes | Executable Retrieved with Minimal HTTP Headers | T1105 | // Most malware downloaded via macro or downloader uses short URI's<br/>http:uri.path MATCHES "/.{0,32}"<br/><br/>// No referrer<br/>AND http:referrer.uri = null<br/><br/>AND http:response_mime IN ("application/x-dosexec", "application/x-mach-o-executable", "application/x-executable")<br/>AND http:status_code = 200<br/><br/>// Majority of downloaders use only GET<br/>and http:method = "GET"<br/><br/>// No user agent, uncommon<br/>AND http:user_agent = null<br/><br/>AND http:headers.accept = null<br/>AND http:headers.refresh = null<br/>AND headers.cookie_length IN (0, null)<br/><br/>// Most malicious downloads are small, < 2MB<br/>AND http:response_len<2mb<br/><br/>AND dst.internal = false<br/><br/>// Common distribution / update sites<br/>AND http:host NOT MATCHES ".{0,50}(\.beyondtrust\.com\|\.microsoft\.com\|audiochannel\.net\|\.autodesk\.com\|\.dell\.com\|\,windowsupdate.com\|\.hp\.com\|\.cloudfront\.net\|\.mozilla\.org\|\.windows\.net\|\.dellsupportcenter\.com\|\.lavasoft\.com\|\.bytefence\.com\|\.techsmith\.com\|\.solidworks.com)" <br/><br/>// Various akamai / cdn / hoster / legit software distribution asns <br/>AND dst.asn.asn NOT IN (22611,9891,4249,20940,15133,6461,9498,209,31976) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 5, 'detection_muted_count': 0, 'detection_resolved_count': 104, 'first_seen': '2021-12-20T09:03:07.538000Z', 'last_seen': '2022-08-15T08:08:48.860000Z'},<br/>{'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 65, 'first_seen': '2021-12-20T00:01:02.949000Z', 'last_seen': '2022-08-18T00:01:41.319000Z'} |  | T1059.001 | high |  | Zscaler | procedure | 2021-12-28T20:15:41.314000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | f01ed7ac-17f8-402a-9d5d-2e2e9617c9e7 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | moderate | 2018-03-19T17:46:13.592000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-09-04T21:01:54.987000Z | This logic is intended to detect malicious executables downloaded over HTTP with a common image file extension. Various threat actors rename executable files in attempts to hide their transfer to and presence on compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads with image file extensions regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity moderate severity due to its historical use in both targeted attacks and exploit kits. Gigamon ATR considers this detection moderate confidence due to the rarity of executable files with image extensions hosted on web servers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Verifying that the file is an executable.<br/>    2. Verifying that the executable is malicious in nature.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | src.ip | true | http:response_mimes,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Executable Binary or Script Downloaded as Image | T1105 | // Select files ending with common image extensions downloaded from external HTTP server<br/>uri.path MATCHES ".*\.(([jJ][pP][gG])\|([jJ][pP][eE][gG])\|([gG][iI][fF])\|([pP][nN][gG]))"<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not internal IP<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>)<br/>                    <br/>AND (<br/>    // Filter for plain executable binary MIME types<br/>    response_mime LIKE "%executable%"<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 45, 'first_seen': '2021-12-23T00:01:14.237000Z', 'last_seen': '2022-08-18T00:01:41.319000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 56, 'first_seen': '2021-12-20T09:03:22.298000Z', 'last_seen': '2022-08-15T08:09:09.640000Z'} |  |  | moderate |  | Zscaler | procedure | 2021-07-23T18:38:06.342000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 3a87c020-a7fe-48bf-b3fd-71aa40072f72 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Installation | high | 2018-04-24T23:39:13.382000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-12-10T00:04:21.861000Z | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan. <br/><br/>## Next Steps <br/>1. Determine if this is a true positive by: <br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task. <br/>3. Quarantine the impacted device. <br/>4. Begin incident response procedures on the impacted device. <br/>5. Block traffic to attacker infrastructure. <br/>6. Search for other impacted devices. | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Trickbot Staging Download | T1105 | http:user_agent = "WinHTTP loader/1.0"<br/>AND response_mime = "application/x-dosexec" | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-23T00:01:21.317000Z', 'last_seen': '2022-08-18T00:01:39.755000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': True, 'muted_comment': None, 'muted_user_uuid': '2964a059-e470-4622-929e-2cadcccf98f4', 'muted_timestamp': '2022-01-05T18:39:07.352000Z', 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-20T09:06:10.558000Z', 'last_seen': '2022-08-15T08:09:09.640000Z'} |  |  | high |  | Zscaler | tool_implementation | 2021-03-19T19:32:19.685000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | aadb155e-712f-481f-9680-482bab5a238d |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Exploitation | moderate | 2018-03-19T17:45:57.463000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2022-08-11T22:50:12.664645Z | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for  a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. <br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | DEFAULT | true | src.ip,<br/>dst.ip | ETERNALBLUE Exploitation | T1203 | // ET EXPLOIT ETERNALBLUE signatures<br/>suricata:sig_id IN (<br/>    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Heap Spray<br/>    // https:<span>//</span>doc.emergingthreats.net/2024217<br/>    2024217,<br/><br/>    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response<br/>    // https:<span>//</span>doc.emergingthreats.net/2024218<br/>    2024218,<br/><br/>    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Request (set)<br/>    // https:<span>//</span>doc.emergingthreats.net/2024220<br/>    2024220, <br/><br/>    // ET EXPLOIT ETERNALBLUE Exploit M2 MS17-010<br/>    // https:<span>//</span>doc.emergingthreats.net/2024297<br/>    2024297,<br/><br/>    // ET EXPLOIT Possible ETERNALBLUE Exploit M3 MS17-010<br/>    // https:<span>//</span>doc.emergingthreats.net/2024430<br/>    2024430,<br/><br/>    // ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010<br/>    // https:<span>//</span>doc.emergingthreats.net/2025650<br/>    2025650<br/>) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 62, 'first_seen': '2021-12-20T09:03:34.058000Z', 'last_seen': '2022-08-15T08:04:04.280000Z'},<br/>{'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 62, 'first_seen': '2021-12-19T08:21:09.561000Z', 'last_seen': '2022-08-18T00:01:13.819000Z'} |  |  | high |  | Zscaler | procedure | 2022-08-11T22:50:12.664645Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | e5bb5bab-e6df-469b-9892-96bf4b84ecae |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Exploitation | moderate | 2021-12-18T15:44:18.716000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:44:18.716000Z | This logic is intended to detect usage of the ETERNALBLUE exploit, a weaponized exploit for a vulnerability (CVE-2017-0144) which exists in the first version of Microsoft's implementation of the Server Message Block protocol (SMBv1). This logic detects packet contents that match those observed in exploitation attempts.<br/><br/>Gigamon ATR considers this detection high severity because signatures within are indicative of successful remote code execution. Gigamon ATR considers this detection to be moderate confidence due to the potential for some signatures to detect unsuccessful exploitation attempts.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by inspecting internal assets for signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/>6. Disable SMBv1 across the domain, if possible.<br/>7. Ensure host operating systems are patched regularly.  | DEFAULT | true |  | [Practical Packet Analysis] ETERNALBLUE Exploitation |  | // ET EXPLOIT ETERNALBLUE signatures<br/>suricata:sig_id IN (<br/>    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Heap Spray<br/>    // http:<span>//</span>doc.emergingthreats.net/2024217<br/>    2024217,<br/><br/>    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response<br/>    // http:<span>//</span>doc.emergingthreats.net/2024218<br/>    2024218,<br/><br/>    // ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Request (set)<br/>    // http:<span>//</span>doc.emergingthreats.net/2024220<br/>    2024220, <br/><br/>    // ET EXPLOIT ETERNALBLUE Exploit M2 MS17-010<br/>    // http:<span>//</span>doc.emergingthreats.net/2024297<br/>    2024297,<br/><br/>    // ET EXPLOIT Possible ETERNALBLUE Exploit M3 MS17-010<br/>    // http:<span>//</span>doc.emergingthreats.net/2024430<br/>    2024430,<br/><br/>    // ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010<br/>    // http:<span>//</span>doc.emergingthreats.net/2025650<br/>    2025650<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 62, 'first_seen': '2021-12-19T08:21:09.561000Z', 'last_seen': '2022-08-18T00:01:13.819000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | moderate |  | Zscaler |  | 2021-12-18T15:44:18.716000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2ad64816-4a7b-41a6-b664-e1b1cf08683f |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Command and Control | moderate | 2021-12-18T15:19:40.254000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:19:40.254000Z | This detection is intended to detect the CKnife Java client interacting with a CKnife Webshell backdoor. CKnife Webshell is commonly used by attackers to establish backdoors on external-facing web servers with unpatched vulnerabilities. CKnife is typically inserted as a PHP or ASPX page on the impacted asset, and accessed via a Java client.<br/><br/>Gigamon ATR considers this detection high severity, as it is indicative of successful malicious code execution on an external-facing server. This detection is considered moderate confidence, as it may coincidentally match similar traffic from uncommon devices or scanners.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Validating that the webpage in the detection exists, is unauthorized, and contains webshell functionality.<br/>   2. Validating that the external entity interacting with the device is unknown or unauthorized.<br/>   3. Inspecting traffic or logs to see if interaction with this webpage is uncommon and recent.<br/>3. Quarantine the impacted device.<br/>4. Begin incident response procedures on the impacted device.<br/>5. Block traffic from attacker infrastructure.<br/>6. Search traffic or logs from the infected web server to identify potential lateral movement by the attackers. | DEFAULT | true |  | CKnife Webshell Activity |  | // Successful external -> internal HTTP POST request<br/>http:src.internal = false <br/>AND dst.internal = true <br/>AND method = "POST" <br/>AND status_code = 200 <br/><br/>// CKnife only supports .php and .aspx filetypes<br/>AND uri.path MATCHES ".*(\.php\|\.aspx)"<br/>AND uri.query = null<br/><br/>// The CKnife client uses a Java user agent by default<br/>AND user_agent LIKE 'Java%'<br/><br/>// CKnife responses are plain text (not HTML)<br/>AND response_mime = "text/plain" | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 28, 'first_seen': '2021-12-22T09:03:30.175000Z', 'last_seen': '2022-08-17T08:06:15.080000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler |  | 2021-12-18T15:19:40.254000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | e9008859-c038-4bd5-a805-21efffd58355 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Discovery | moderate | 2021-12-18T15:28:38.093000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:28:38.093000Z | This rule is designed to use the TCP Device Enumeration Observation event generated from a DMZ host that is not a scanner.  This would indicate a potentially compromised DMZ host scanning for other assets within the environment.  <br/> | DEFAULT | true |  | TCP Device Enumeration from DMZ host |  | observation_uuid = '941428b8-fb88-454c-8f7e-19b26c64e998' | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 24, 'first_seen': '2022-02-02T09:04:35.714000Z', 'last_seen': '2022-08-17T08:04:36.650000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | moderate |  | Zscaler |  | 2021-12-18T15:28:38.093000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2d719a2b-4efb-4ba6-8555-0cd0f9636729 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | PUA:Unauthorized Resource Use | moderate | 2018-04-02T20:12:13.486000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-04-17T01:03:41.513000Z | This signature is intended to detect a cryptocurrency mining client performing a login or check-in to a cryptocurrency server. Cryptocurrency mining is a popular method of monetizing unauthorized access to hosts; however, it is also possible that this activity is the result of deliberate user behavior. To prevent unwanted expenditures of both power and system resources, Gigamon ATR recommends preventing cryptocurrency mining on company assets. <br/><br/>Gigamon ATR considers cryptocurrency mining to be moderate severity. While it poses no direct threat, it can indicate a compromised host. Gigamon ATR considers this detection moderate confidence due to the potential for these signatures to detect benign traffic with similar strings in the packet contents.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying the presence of coinmining software on the impacted asset.<br/>2. Determine if this is legitimate and approved use of coinmining software.<br/>3. Remove software if unnecessary. | src.ip | true | dst.ip | Cryptocurrency Mining Client Check-in | T1095 | suricata:sig_id IN (<br/>    // ET POLICY Crypto Coin Miner Login<br/>    // https:<span>//</span>doc.emergingthreats.net/2022886<br/>    2022886,<br/><br/>    // ET POLICY Cryptocurrency Miner Checkin<br/>    // https:<span>//</span>doc.emergingthreats.net/2024792<br/>    2024792,<br/><br/>    // ETPRO POLICY XMR CoinMiner Usage<br/>    // https:<span>//</span>doc.emergingthreats.net/2826930<br/>    2826930 <br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 0, 'detection_muted_count': 0, 'detection_resolved_count': 21, 'first_seen': '2021-12-21T00:07:54.839000Z', 'last_seen': '2022-08-09T00:07:54.399000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 32, 'first_seen': '2021-12-21T09:36:19.449000Z', 'last_seen': '2022-08-16T08:36:18.896000Z'} |  |  | moderate |  | Zscaler | tool_implementation | 2022-08-11T22:41:24.071679Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | bfcb4b76-96ef-4b33-9812-58158c871f99 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 20160 | Attack:Installation | high | 2019-05-06T13:00:29.165000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-01-16T00:27:43.540000Z | This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Executable or Script Download From External Python SimpleHTTPServer | T1105 | http:headers.server LIKE "SimpleHTTP/% Python/%"<br/>// Filter for plain executable binary MIME types<br/>AND (<br/>    response_mime LIKE "%executable%"<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/>)<br/><br/>// Outbound traffic<br/>AND src.internal = true<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not internal IP address<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 5, 'first_seen': '2021-12-21T00:07:50.553000Z', 'last_seen': '2022-08-16T00:07:50.615000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 4, 'detection_muted_count': 0, 'detection_resolved_count': 12, 'first_seen': '2022-02-01T09:35:58.269000Z', 'last_seen': '2022-08-16T08:35:57.466000Z'} |  |  | moderate |  | Zscaler | procedure | 2022-04-27T16:26:03.115153Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | fe4d55b4-7293-425a-b549-43a22472923d |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | low | 2018-03-20T21:27:02.337000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2022-01-07T17:29:49.377000Z | This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the downloaded executable is malicious in nature. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | DEFAULT | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:files.sha256 | Executable Binary or Script Download via Wget or cURL | T1105 | // User Agent is Wget or cURL<br/>http:user_agent MATCHES "([wW][gG][eE][tT]\|[cC][uU][rR][lL]).*"<br/><br/>// Internal downloading from external<br/>AND src.internal = true<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not internal IP address<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>)<br/><br/>AND (<br/>    // Plain executable binaries<br/>    response_mime LIKE "%executable%" <br/>    OR response_mime LIKE "%application/x-dosexec%" <br/>    OR response_mime LIKE "%application/x-macbinary%" <br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%" <br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%" <br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%" <br/>    OR response_mime LIKE "%x-shellscript%" <br/><br/>    // Filetypes not yet positively classified by FileTyper over binary content.<br/>    // Instead match by extension (also to be obviated by future FileTyper features)<br/>    OR (<br/>        status_code >= 200<br/>        AND status_code <= 300<br/>        AND response_len > 0<br/>        AND (<br/>            uri.path MATCHES ".*\.([hH][tT][aA]\|[vV][bB][sS]\|[pP][sS]1\|[jJ][sS][eE]\|[wW][sS][fF]\|[mM][sS][iI])"<br/>            OR uri.query MATCHES ".*\.([hH][tT][aA]\|[vV][bB][sS]\|[pP][sS]1\|[jJ][sS][eE]\|[wW][sS][fF]\|[mM][sS][iI])(&.+)?"<br/>        )<br/>    )<br/>)<br/><br/>// Ignore some well-known sources that push down executable content<br/>AND http:host.domain NOT LIKE "%.nodesource.com" <br/>AND http:host.domain NOT LIKE "%.chef.io" <br/>AND http:host.domain NOT LIKE "%.cloudera.com" <br/>AND http:host.domain NOT LIKE "%.oracle.com" <br/>AND http:host.domain NOT LIKE "%.microsoft.com" <br/>AND http:host.domain NOT LIKE "%.windowsupdate.com" <br/>AND http:host.domain NOT LIKE "%.dell.com" <br/>AND http:host.domain NOT LIKE "%.sourceforge.net" <br/>AND http:host.domain NOT LIKE "%.portableapps.com" <br/>AND http:host.domain NOT LIKE "%.virtualbox.org"<br/>AND http:host.domain != "cygwin.com" | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 19, 'first_seen': '2022-02-01T09:35:58.269000Z', 'last_seen': '2022-08-16T08:35:57.466000Z'},<br/>{'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 20, 'first_seen': '2021-12-21T00:07:50.553000Z', 'last_seen': '2022-08-16T00:07:50.615000Z'} |  |  | high |  | Zscaler | procedure | 2022-07-01T20:09:34.695569Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 22c9ee01-2cbd-418d-bebf-c0cb3a175602 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | low | 2021-12-18T15:39:39.100000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:39:39.100000Z | This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.<br/> | DEFAULT | true |  | [Scenario 2] Executable Binary or Script from VPS |  | (  <br/>    // From a select collection of VPS providers.<br/>    // To be replaced with intel matching<br/>    dst.asn.asn_org in ('AS-CHOOPA',<br/>                        'Hosting Solution Ltd.', <br/>                        'Linode, LLC',<br/>                        'Digital Ocean, Inc.',<br/>                        'Choopa, LLC',<br/>                        'DigitalFyre Internet Solutions, LLC.',<br/>                        'OVH SAS',<br/>                        'Relink LTD',<br/>                        'Hetzner Online GmbH',<br/>                        'Host Sailor Ltd.',<br/>                        'TimeWeb Ltd.')<br/>                        <br/>    // Plain executable binaries<br/>    AND (response_mime LIKE "%executable%"<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/>    <br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/>    <br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/>    <br/>    // Filetypes not yet positively classified by FileTyper over binary content.<br/>    // Instead match by extension (also to be obviated by future FileTyper features)<br/>    OR (http:status_code >= 200 AND http:status_code <= 300 AND http:response_len > 0<br/>        AND (http:uri.uri MATCHES ".*\.(([hH][tT][aA])\|([vV][bB][sS])\|([pP][sS]1)\|([jJ][sS][eE])\|([wW][sS][fF])\|([mM][sS][iI]))"))<br/>    )<br/>) <br/><br/>// Whitelist known benign<br/>AND host.domain NOT IN (<br/>    'notepad-plus-plus.org' // Notepad++ source code editor<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 41, 'first_seen': '2021-12-21T00:07:50.553000Z', 'last_seen': '2022-08-16T00:07:50.615000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | high |  | Zscaler |  | 2021-12-18T15:39:39.100000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | bc828199-03c2-45cb-99ff-6d2713c4de60 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | high | 2021-12-18T15:48:43.904000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:48:43.904000Z | # Description<br/><br/>This logic is intended to detect executable binaries and scripts downloaded from a Python SimpleHTTPServer. SimpleHTTPServer is part of Python's standard library and allows users to quickly setup a basic HTTP server. It is typically used for prototyping and not commonly used in production systems.<br/><br/>Gigamon ATR considers this activity moderate severity, as an executable or script is not inherently malicious simply because it is hosted on a Python SimpleHTTPServer, but it is unlikely that a legitimate service would host executable binaries or scripts on a Python SimpleHTTPServer. Gigamon ATR considers this detection high confidence because the server field in the HTTP response header is highly unique to Python SimpleHTTPServer.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | DEFAULT | true |  | [Scenario 2] Executable or Script Download From External Python SimpleHTTPServer |  | http:headers.server LIKE "SimpleHTTP/% Python/%"<br/>// Filter for plain executable binary MIME types<br/>AND (<br/>    response_mime LIKE "%executable%"<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/>)<br/><br/>// Outbound traffic<br/>AND src.internal = true<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not internal IP address<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 20, 'first_seen': '2021-12-21T00:07:50.553000Z', 'last_seen': '2022-08-16T00:07:50.615000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | moderate |  | Zscaler |  | 2021-12-18T15:48:43.904000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 85360e3a-93a7-40d0-9db5-e1beafa80ef3 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | low | 2021-12-18T15:40:55.346000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:40:55.346000Z | This logic is intended to detect malicious executable binaries or scripts downloaded over HTTP using cURL or Wget. Both utilities are common to *nix operating systems, and used legitimately to download files. However, some threat actors use these utilities to download tools for post-exploitation usage.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence because, while it is uncommon for executable binaries and scripts to be downloaded using cURL or Wget, it does occur in benign activity.<br/><br/>## Next Steps<br/>1.  Determine if this detection is a true positive by:<br/>    1.  Checking that the HTTP event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the downloaded executable is malicious in nature.<br/>3.  Quarantine the impacted device.<br/>3.  Begin incident response procedures on the impacted device.<br/>4.  Block traffic to attacker infrastructure.<br/>5.  Search for other impacted devices. | DEFAULT | true |  | [Scenario 2] Executable Binary or Script Download via Wget or cURL |  | ( // user-agent string checks<br/>    http:user_agent MATCHES "[wW][gG][eE][tT].*"<br/>    OR http:user_agent MATCHES "[cC][uU][rR][lL].*"<br/>)<br/>AND ( // Internal downloading from external<br/>    http:src.internal = true<br/>    AND http:dst.internal = false<br/>)<br/>AND ( // Plain executable binaries<br/>    response_mime LIKE "%executable%" <br/>    OR response_mime LIKE "%application/x-dosexec%" <br/>    OR response_mime LIKE "%application/x-macbinary%" <br/><br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%" <br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%" <br/><br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%" <br/>    OR response_mime LIKE "%x-shellscript%" <br/><br/>    // Filetypes not yet positively classified by FileTyper over binary content.<br/>    // Instead match by extension (also to be obviated by future FileTyper features)<br/>    OR (http:status_code >= 200 AND http:status_code <= 300 AND http:response_len > 0<br/>    AND (http:uri.uri MATCHES ".*\.(([hH][tT][aA])\|([vV][bB][sS])\|([pP][sS]1)\|([jJ][sS][eE])\|([wW][sS][fF])\|([mM][sS][iI]))"))<br/>) <br/>AND ( // Ignore some well-known sources that push down executable content<br/>    http:host.domain NOT LIKE "%.nodesource.com" <br/>    AND http:host.domain NOT LIKE "%.chef.io" <br/>    AND http:host.domain NOT LIKE "%.cloudera.com" <br/>    AND http:host.domain NOT LIKE "%.oracle.com" <br/>    AND http:host.domain NOT LIKE "%.microsoft.com" <br/>    AND http:host.domain NOT LIKE "%.windowsupdate.com" <br/>    AND http:host.domain NOT LIKE "%.dell.com" <br/>    AND http:host.domain NOT LIKE "%.sourceforge.net" <br/>    AND http:host.domain NOT LIKE "%.portableapps.com" <br/>    AND http:host.domain NOT LIKE "%.virtualbox.org"<br/>)<br/> | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 20, 'first_seen': '2021-12-21T00:07:50.553000Z', 'last_seen': '2022-08-16T00:07:50.615000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | high |  | Zscaler |  | 2021-12-18T15:40:55.346000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | ee538666-4159-4edf-b611-b507f40ac628 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Exfiltration | moderate | 2021-12-18T15:26:31.390000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:26:31.390000Z | This logic is intended to detect data exfiltration by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot typically exfiltrates data to its C2 servers using a self-signed certificate and communicates over non-standard ports such as 447 or 449.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to have false positives, certificate subjects are easy to change and impersonate.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Checking the server name indication as most malicious traffic will be directly to a compromised IP address, rather than a domain.<br/>   2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true |  | Trickbot Data Exfiltration | T1048.001 | //Trickbot certificate subject and issue fields the same<br/>ssl:subject = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"<br/>AND issuer = "O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"<br/>//non-standard destination ports for SSL<br/>AND dst.port IN (447, 449)<br/>//outbound traffic<br/>AND dst.internal = false | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 56, 'first_seen': '2021-12-20T09:04:19.258000Z', 'last_seen': '2022-08-15T08:09:33.210000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler | tool_implementation | 2021-12-18T15:26:31.390000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 732df04c-fdbc-4715-93ce-809a6b9ebd74 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Command and Control | moderate | 2021-12-18T15:27:31.150000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:27:31.150000Z | This logic is intended to detect SSL certificates used by the Trickbot banking trojan. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. Trickbot has also been observed performing lateral movement by exploiting the SMB vulnerability MS17-010.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and potential compromise of user credentials. Gigamon ATR considers this detection to be moderate confidence because, while it has not been seen to false positive, certificate subjects are easy to change and impersonate.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Evaluating the timing of the connections for beacon-like regularity.<br/>   2. Checking the impacted asset for other indicators of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true |  | Trickbot Banking Trojan C2 |  | //Trickbot C2 traffic certificate information<br/>ssl:subject = "CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB"<br/>AND ssl:issuer = "CN=example.com,OU=IT Department,O=Global Security,L=London,ST=London,C=GB" | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 56, 'first_seen': '2021-12-20T09:03:23.458000Z', 'last_seen': '2022-08-15T08:09:33.040000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler |  | 2021-12-18T15:27:31.150000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | caab7261-ee92-4b78-aa29-4e47e89d7276 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Installation | moderate | 2021-12-18T15:17:51.538000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:17:51.538000Z | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. Gigamon ATR considers this detection to be high confidence due to the uniqueness of the user agent used in HTTP requests by the trojan.<br/><br/>### Next Steps<br/>1. Determine if this is a true positive by:<br/>   1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>   2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>   3. Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true |  | Trickbot Staging Download | T1105 | //Trickbot user agent<br/>http:user_agent = "WinHTTP loader/1.0"<br/>//executable download<br/>AND response_mime = "application/x-dosexec" | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 56, 'first_seen': '2021-12-20T09:06:10.558000Z', 'last_seen': '2022-08-15T08:09:09.640000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler | tool_implementation | 2021-12-18T15:17:51.538000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 4727a9aa-8f71-487f-8fd6-c7f64d925443 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Command and Control | moderate | 2021-12-18T15:23:48.348000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:23:48.348000Z | https://us-cert.cisa.gov/ncas/alerts/aa20-302a<br/><br/>CISA MALWARE IOCs for Hospitals 28 OCT 2020 | DEFAULT | true |  | Custom: CISA Malware IOCs |  | ip in ('93.119.208.86', // 13 October 2020<br/>'92.223.89.0/24',       //August - September 2020<br/>'92.223.89.224',        //12 September 2020<br/>'92.223.89.212',        //6 September 2020<br/>'88.202.178.104',       //20 October 2020<br/>'70.32.0.107',          //21 October 2020<br/>'64.44.81.36',          //12 September  2020<br/>'45.131.211.246',       //21 October 2020<br/>'37.235.103.27',        //16 October 2020 – 17 October 2020<br/>'212.102.45.0/24',      //October 2020<br/>'212.102.45.23',        //21 October 2020<br/>'212.102.45.13',        // 12 October 2020<br/>'185.191.207.0/24',     // February - September 2020<br/>'185.191.207.164',      //19 September 2020<br/>'184.170.241.13',       //17 October 2020 - 19 October 2020<br/>'156.46.54.0/24',       //October 2020<br/>'156.146.55.0/24',      //October 2020<br/>'156.146.55.195',       //15 October 2020<br/>'156.146.54.0/24',      // October 2020<br/>'156.146.54.58',        //20 October 2020<br/>'156.146.54.45',        //18 October 2020<br/>'154.3.251.56',         //16 October 2020 -21 October 2020<br/>'145.239.110.112',      //20 October 2020<br/>'104.237.232.153',      //13 October 2020 – 19 October 2020<br/>'103.205.140.0/24',     //October 2020<br/>'185.183.32.177',       //October 2020<br/>'92.223.89.191',        //19 August 2020 -25 August 2020<br/>'92.223.89.187',        //26 August 2020<br/>'92.223.89.172',        //26 August 2020<br/>'212.102.45.63',        //24 August 2020<br/>'185.191.207.179',      // 29 July 2020<br/>'128.90.56.147',        // 23 June 2020<br/>'104.140.54.91',        //23 August 2020<br/>'91.239.206.181',       // 23 April 2019<br/>'91.223.106.201',       // 10 March 2020<br/>'91.223.106.148',       // 22 February 2020<br/>'89.165.43.244',        //24 February 2020<br/>'5.160.253.152',        // 24 February 2020<br/>'46.45.138.100',        //3 May 2020<br/>'185.191.207.36',       //  17 September 2019<br/>'185.191.207.184',      //18 February 2020<br/>'176.53.23.252',        //31 May 2020<br/>'103.205.140.30',       //11 March 2020<br/>'103.205.140.177'      //10 March 2020 <br/>) OR<br/>server_name_indication matches '.*([Kk][Oo][Ss][Tt][Uu][Nn][Ii][Vv][Oo].[Cc][Oo][Mm]\|[Cc][Hh][Ii][Ss][Hh][Ii][Rr].[Cc][Oo][Mm]\|[Mm][Aa][Nn][Gg][Oo][Cc][Ll][Oo][Nn][Ee].[Cc][Oo][Mm]\|[Oo][Nn][Ii][Xx][Cc][Ee][Ll][Ll][Ee][Nn][Tt].[Cc][Oo][Mm]).*'<br/>// anchdorDNS c2 domain 28 OCT 2020<br/>OR<br/>ip IN ('23.95.97.59','51.254.25.115','193.183.98.66','91.217.137.37','87.98.175.85')<br/> //anchdorDNS c2 IP 28 OCT 2020<br/>OR<br/>ip IN ('45.148.10.92','170.238.117.187','177.74.232.124','185.68.93.17','203.176.135.102','96.9.73.73','96.9.77.142','37.187.3.176','45.89.127.92','62.108.35.103','91.200.103.242','103.84.238.3','36.89.106.69','103.76.169.213','36.91.87.227','105.163.17.83','185.117.73.163','5.2.78.118','185.90.61.69','185.90.61.62','86.104.194.30','31.131.21.184','46.28.64.8','104.161.32.111','107.172.140.171','131.153.22.148','195.123.240.219','195.123.242.119','195.123.242.120','51.81.113.25','74.222.14.27')<br/>//trickbot 28 OCT 2020 | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 62, 'first_seen': '2021-12-20T09:03:54.818000Z', 'last_seen': '2022-08-15T08:07:11.350000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler |  | 2021-12-18T15:23:48.348000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | c76aff9b-0f65-48d6-8312-cc5eac8b81ba |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Installation | low | 2021-12-18T15:21:10.880000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:21:10.880000Z | This logic is intended to detect malicious Windows executable files fetched from the root of a web directory. Malicious files are often hosted in the root folder of web servers to enable ease of use for threat actors. However, the transfer of a malicious executable does not necessarily indicate that an attacker has achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and un-targeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries from the root of the web hosting directory.<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>   2. Verifying that the file is malicious in nature.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true |  | Executable in Root of Web Directory |  | // Outbound traffic<br/>http:src.internal = true<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not internal IP address<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>)<br/><br/>// File is Windows executable<br/>AND response_mime = "application/x-dosexec"<br/>// File is approx 100KB to 1MB<br/>AND response_len > 100kb AND response_len < 1mb<br/>// Requests a file ending in .exe from the web root<br/>AND uri.path MATCHES "\/[a-zA-Z0-9_\-]+\.[eE][xX][eE]"<br/><br/>// Query and Referer parameters are frequently empty<br/>AND uri.query = null<br/>AND referrer.host = null<br/><br/>// Whitelist of acceptable sites<br/>AND host.domain NOT IN ("live.sysinternals.com") | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 4, 'detection_muted_count': 0, 'detection_resolved_count': 76, 'first_seen': '2021-12-20T09:03:07.538000Z', 'last_seen': '2022-08-15T08:03:06.980000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler |  | 2021-12-18T15:21:10.880000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | cb90239f-8a7f-4ec8-a7c1-9e6d7c8ba12a |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Installation | low | 2021-12-18T15:24:45.996000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:24:45.996000Z | This logic is intended to detect the banking trojan, Emotet. This trojan is typically loaded as a second-stage payload by other malware<br/><br/>Gigamon ATR considers Emotet high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection low confidence as the detection logic may be triggered by a non-standard executable download<br/><br/>### Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>   2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true |  | Emotet Banking Trojan Download |  | //Successful outbound GET request to dotted quad<br/>dst.internal=false AND method = 'GET' AND status_code = 200 AND http:host.ip != null AND<br/>//Executable<br/>headers.content_type = 'application/octet-stream' AND response_mimes = 'application/x-dosexec' AND  <br/>//Missing user agent<br/>user_agent=NULL | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 28, 'first_seen': '2021-12-20T09:03:07.538000Z', 'last_seen': '2022-08-15T08:03:06.980000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler |  | 2021-12-18T15:24:45.996000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 1709f5a2-1563-4592-b430-16444399bb2a |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Command and Control | moderate | 2019-01-25T22:54:36.060000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-02-25T20:45:05.475000Z | This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.<br/><br/>Gigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>    2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | src.ip | true | dst.ip,<br/>dst.asn.asn_org,<br/>http:host,<br/>http:uri.uri | IcedID Banking Trojan HTTP GET Request | T1071.001 | // Outbound traffic<br/>(<br/>    (<br/>        http:src.internal = true<br/>        OR http:source IN ("Zscaler")<br/>    )<br/>AND (<br/>        dst.internal = false<br/>    OR (<br/>        // Not internal IP address<br/>        host.internal != true<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>        )<br/>    )<br/>)<br/><br/>AND method = "GET"<br/>AND uri.path LIKE "/%.php"<br/>AND uri.query MATCHES "[A-F0-9]{16}"<br/><br/>// Change to SSL<br/>AND status_code = 101 | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-20T09:02:17.328000Z', 'last_seen': '2022-08-15T08:02:16.710000Z'} |  |  | high |  |  | tool_implementation | 2022-08-10T21:50:30.442195Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 3e8c54a6-1934-4517-b217-e98f342b6c5a |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Command and Control | moderate | 2021-12-18T15:22:27.041000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | 2021-12-18T15:22:27.041000Z | This logic is intended to detect the banking trojan, IcedID. As is typical of banking trojans, it hooks into users' browser sessions and can take screenshots in order to steal credentials for financial institutions. It is typically loaded as a second-stage payload by Emotet.<br/><br/>Gigamon ATR considers IcedID high severity due to the level of access it grants malicious actors to both the environment and information. Gigamon ATR considers this detection moderate confidence due to the uniqueness of the URI.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>   1. Checking for TLS connections from the same source to a server (generally the same server as the HTTP connections) using a self-signed certificate containing strings consisting of apparently random english words in place of a meaningful Common Name, Organizational Unit, and Organization.<br/>   2. Checking the affected asset for additional signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices. | DEFAULT | true |  | IcedID Banking Trojan Traffic |  | // Outbound traffic<br/>http: src.internal = true<br/>AND (<br/>    // Proxied traffic<br/>    dst.internal != true<br/>    OR uri.scheme != null <br/>)<br/><br/>AND method = "GET"<br/>AND uri.path LIKE "/%.php"<br/>AND uri.query MATCHES "[A-F0-9]{16}"<br/><br/>// Change to SSL<br/>AND status_code = 101 | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 28, 'first_seen': '2021-12-20T09:02:17.328000Z', 'last_seen': '2022-08-15T08:02:16.710000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | high |  | Zscaler |  | 2021-12-18T15:22:27.041000Z | b7943c6c-d6a7-421f-b2be-cc0a5134932d | c559f79e-0ca7-48ac-875b-fe226308ef4d |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | high | 2021-12-18T15:41:57.247000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:41:57.247000Z | This logic is intended to detect the Trickbot banking trojan downloading separate executable files to update or extend the functionality of the main trojan. Trickbot is generally delivered by spam campaigns via malicious Microsoft Office documents. Trickbot attempts to harvest credentials for web sites, primarily for financial institutions. As well as gathering credentials for any user accounts used on affected hosts, it can also be used as a backdoor which enables access to the network.<br/><br/><br/>ICEBRG considers this detection to be high severity, as it is indicative of successful malicious code execution and allows for unauthorized access to the network. ICEBRG considers this detection to be high confidence due to the uniqueness of the issuer of the SSL certificate used in the SSL requests by the trojan.<br/><br/>## Next Steps<br/>1.  Determine if this is a true positive by:<br/>    1. Investigating for connections outbound to ports 447 and 449 from the affected host.<br/>    2. Checking the affected host for earlier executable downloads with no user agent set, or connectivity checks such as public IP lookups (e.g. HTTP requests to checkip.amazonaws.com).<br/>    3.  Checking the impacted asset for other indicators of compromise. Persistence is generally achieved via a scheduled task.<br/>2.  Quarantine the impacted device.<br/>3.  Begin incident response procedures on the impacted device.<br/>4.  Block traffic to attacker infrastructure.<br/>5.  Search for other impacted devices. | DEFAULT | true |  | [Scenario 1] Trickbot Staging Download |  | ssl:issuer like '%sd-97597.dedibox.fr%' | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 22, 'first_seen': '2021-12-20T00:01:04.391000Z', 'last_seen': '2022-08-15T00:01:08.494000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | high |  | Zscaler |  | 2021-12-18T15:41:57.247000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 37e8edaa-ef2e-478b-a2cf-dfc85aae38c6 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Posture:Potentially Unauthorized Software or Device | high | 2018-03-16T19:49:01.018000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-02-18T01:01:03.282000Z | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.  <br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network. <br/>2. Ensure legitimate and approved use of Tor. <br/>3. Remove any unapproved software. | src.ip | true | dst.ip,<br/>ssl:server_name_indication,<br/>ssl:subject,<br/>ssl:issuer,<br/>ssl:ja3 | Tor Connection Initialization | T1090 | src.internal = true <br/>AND (<br/>    // Random .com SNI<br/>    server_name_indication MATCHES "www\..*\.com"<br/>    // Random .net cert subject<br/>    AND subject MATCHES "CN=www\..*\.net"<br/>    // Random .com cert issuer<br/>    AND issuer MATCHES "CN=www\..*\.com"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': 'src.internal != false // just testing something out -- vien y', 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-19T05:12:21.554000Z', 'last_seen': '2022-08-14T11:13:39.732000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 56, 'first_seen': '2021-12-19T16:25:16.927000Z', 'last_seen': '2022-08-14T15:31:13.353000Z'} |  |  | low |  | Zscaler | tool_implementation | 2021-03-17T23:36:21.343000Z | 9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3 | 7108db9b-6158-458f-b5b4-082f2ebae0f7 |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Infection Vector | low | 2022-01-28T20:06:48.014343Z | 46b5401c-82a2-44ac-8d87-fa45340d5a64 | 2022-01-28T20:06:48.014343Z | Important! | DEFAULT | true |  | Detection rule 2022.1.2 |  | src.ip = '172.16.99.131' | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 52, 'first_seen': '2022-01-23T16:26:16.783000Z', 'last_seen': '2022-08-14T15:26:29.489000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | moderate |  | Zscaler |  | 2022-01-28T20:06:48.014343Z | 46b5401c-82a2-44ac-8d87-fa45340d5a64 | 421af990-caf9-4f4b-9fc5-339c53016e4b |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 10080 | Attack:Exploitation | low | 2022-01-24T20:28:14.614000Z | 46b5401c-82a2-44ac-8d87-fa45340d5a64 | 2022-01-24T20:28:14.614000Z |  | DEFAULT | true |  | Test rule from investigation 2022.1.1 |  | src.ip = '172.16.99.131' | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 2, 'detection_muted_count': 0, 'detection_resolved_count': 52, 'first_seen': '2022-01-23T16:26:16.783000Z', 'last_seen': '2022-08-14T15:26:29.489000Z'} | dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 |  | moderate |  | Zscaler |  | 2022-01-24T20:28:14.614000Z | 46b5401c-82a2-44ac-8d87-fa45340d5a64 | e67675e7-3914-4d4c-9dd5-f239b4defae2 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Infection Vector | moderate | 2019-10-01T18:06:44.469000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-02-26T00:32:08.625000Z | This logic is intended to detect an attack known as Kerberoasting, by looking for higher confidence observations which identify high service diversity in Kerberos ticket-granting service (TGS) requests with RC4 encryption. Certain domain services require that a domain account is associated to them via a Service Principle Name (SPN). Any authenticated domain user can request a TGS ticket for accounts with an SPN set and if that ticket is encrypted with ciphers such as RC4, the service's password hash may be vulnerable to an offline brute force attack.<br/><br/>Kerberoasting attacks often involve an adversary requesting tickets for many of these service accounts in hopes that one of them uses a weak password.<br/><br/>Gigamon ATR considers activity indicative of active compromise to be high severity. Gigamon ATR considers this detection moderate confidence because certain instances may be normal domain activity.<br/><br/>## Next Steps<br/>1. Review the services requested and determine if an SPN should be set for a given account.<br/>2. Ensure that service accounts have strong passwords.<br/>3. Review Kerberos logs to determine the user account involved.<br/>4. Verify that the activity was authorized. | src.ip | true |  | Kerberoasting | T1558.003 | // High Service Diversity in Kerberos TGS Requests<br/>observation_uuid = "2bd4a1d2-729d-47fc-b767-c471b456775e"<br/>AND observation_confidence IN ("moderate", "high") | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 1, 'first_seen': '2021-12-19T16:26:13.821000Z', 'last_seen': '2022-08-14T15:26:28.279000Z'},<br/>{'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-21T01:01:03.317000Z', 'last_seen': '2022-08-09T01:01:05.585000Z'} |  |  | high |  | Zscaler | procedure | 2022-05-05T02:01:53.830468Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 0de05ba7-d42d-4de8-aff7-aeb4350bb564 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 30240 | Attack:Command and Control | high | 2018-12-28T21:26:43.596000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-01-15T20:36:45.463000Z | This logic is intended to detect a Windows banner over ICMP. This Windows banner appears at the start of a reverse shell session over ICMP, often started with tools such as \`icmpsh\`. By using ICMP, attackers are often able to circumvent firewall protections.<br/><br/>Gigamon ATR considers a Windows banner over ICMP high severity, as it is indicative of successful malicious code execution. Gigamon ATR considers this detection high confidence due to the uniqueness of the Windows banner string in ICMP traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by starting packet capture and investigating ICMP traffic produced by the impacted asset, looking for the presence of plaintext shell commands.<br/>2. Quarantine the impacted device.<br/>3. Search for other impacted devices.<br/>4. Block traffic to attacker infrastructure.<br/>5. Begin incident response procedures on the impacted device.  | src.ip | true | dst.ip | Windows Banner String in ICMP Request | T1095 | // alert icmp any any -> any any (msg: "ATR COMMAND_AND_CONTROL ICMP Windows Banner Shell String in ICMP Request"; itype:8; icode:0; content:"Microsoft Windows [Version"; metadata: DET-4114; classtype:misc-attack; sid:2900086; rev:1;)<br/>sig_id = 2900086 AND sig_rev = 1 | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 1, 'first_seen': '2021-12-19T16:26:12.008000Z', 'last_seen': '2022-08-14T15:26:26.040000Z'} |  |  | high |  | Zscaler | procedure | 2021-04-09T22:47:06.093000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | b73126a8-5cd1-4c2f-a0ef-ce12e02e4b31 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | high | 2018-05-15T18:08:55.511000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-07-08T21:59:20.870000Z | This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network. <br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity. <br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by checking the host for signs of compromise. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent | Pony or Hancitor Second Stage Download | T1105 | http:method = "POST"<br/>AND uri.path LIKE "%/gate.php"<br/>AND (<br/>    response_len > 1MB<br/>    OR user_agent LIKE "%Windows 98%"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-19T08:12:15.184000Z', 'last_seen': '2022-08-14T11:10:28.642000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 16, 'first_seen': '2022-02-06T16:22:18.923000Z', 'last_seen': '2022-08-14T15:22:31.910000Z'} |  | T1104 | high |  |  | tool_implementation | 2021-03-17T23:36:35.422000Z | 9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3 | 2d06c01f-5ae4-4346-8d6a-99926dcac4f1 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | low | 2018-03-23T22:03:57.728000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-01-22T22:17:56.563000Z | This logic is intended to detect the download of PowerShell scripts from external HTTP servers. While commonly used in systems administration, PowerShell scripts are also used extensively by malware authors for post-exploitation actions.<br/><br/>Gigamon ATR considers this activity high severity because it implies that an attacker has achieved code execution on the impacted device. Gigamon ATR considers this detection low confidence, as PowerShell is commonly used for administrative tasks.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Determining if the script retrieved was downloaded from a reputable source, and what the purpose may be. <br/>    2. Investigating the impacted device to determine what initiated the request.<br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:files.sha256 | PowerShell Downloaded from External HTTP Server | T1105 | // Looking for powershell (.ps1) downloads over HTTP from external servers.<br/>http:dst.internal = false<br/>AND http:uri.path MATCHES ".*\.ps1([^0-9a-zA-Z].*)?"<br/><br/>// Require that the server returned a file and FileTyper identified it as plain text.<br/>AND response_mime LIKE "%text/plain%"<br/><br/>// Whitelist known good domains that commonly serve powershell<br/>AND http:host.domain NOT LIKE "%.sophosxl.net"<br/>AND http:host.domain NOT LIKE "%.microsoft.com"<br/>AND http:host.domain NOT LIKE "%.boxstarter.org"<br/>AND http:host.domain NOT IN (<br/>    "boxstarter.org", // Chocolately automation<br/>    "chocolatey.org", // Chocolately automation<br/>    "lt.xamin.com" // Managed IT Services<br/>) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 16, 'first_seen': '2022-02-06T12:45:02.956000Z', 'last_seen': '2022-08-14T11:45:15.504000Z'} |  | T1071 | high |  | Zscaler | procedure | 2021-08-27T17:59:57.392000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 65ce4d1e-a7dd-4966-9db1-7c9e0efe6266 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Posture:Potentially Unauthorized Software or Device | high | 2021-12-18T15:49:48.350000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:49:48.350000Z | This logic is intended to detect internal assets connecting to the Tor network. Tor is a routing service that enables anonymous Internet usage. This permits unrestricted Internet access not monitored or protected by enterprise security or data loss prevention systems. While using Tor, a user can access what are sometimes referred to as "Deep Web" or "Dark Web" sites. Dark Web sites use domains under the .onion Top Level Domain (TLD). Furthermore, Tor has been used as a command and control mechanism by various types of malware.<br/><br/>Gigamon ATR considers this detection to be low severity, as it does not enlarge the organizational attack surface and is more commonly indicative of employee usage than malware communications. Gigamon ATR considers this detection to be high confidence, due to the uniqueness of SSL certificates used in connecting to the Tor network.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by verifying that the affected host has software installed for accessing the Tor network.<br/>2. Ensure legitimate and approved use of Tor.<br/>3. Remove any unapproved software.  | DEFAULT | true |  | [Practical Packet Analysis] Tor Connection Initialization |  | src.internal = true <br/>AND (<br/>    // Random .com SNI<br/>    server_name MATCHES "www\..*\.com"<br/>    // Random .net cert subject<br/>    AND subject MATCHES "CN=www\..*\.net"<br/>    // Random .com cert issuer<br/>    AND issuer MATCHES "CN=www\..*\.com"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 2, 'first_seen': '2021-12-19T05:12:21.554000Z', 'last_seen': '2022-08-14T11:13:39.732000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | low |  | Zscaler |  | 2021-12-18T15:49:48.350000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 9d838451-4d33-4124-b6fd-43439217bee3 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | high | 2021-12-18T15:43:06.963000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:43:06.963000Z | This logic is intended to detect Pony or Hancitor second stage downloads. Hancitor and Pony are banking trojans that attempt to harvest credentials for web sites, primarily for financial institutions. As well as harvesting credentials for any user accounts used on affected hosts, they can also be used as a remote access tool that enables access to the network.<br/><br/>Gigamon ATR considers this detection to be high severity, as it is indicative of successful malicious code execution, and allows for unauthorized access to the network. Gigamon ATR considers this detection high confidence, as these requests are unlikely to be the result of legitimate activity.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by checking the host for signs of compromise.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | DEFAULT | true |  | [Practical Packet Analysis] Pony or Hancitor Second Stage Download |  | http:method = "POST"<br/>AND uri.path LIKE "%/gate.php"<br/>AND (<br/>    response_len > 1MB<br/>    OR user_agent LIKE "%Windows 98%"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 3, 'first_seen': '2021-12-19T08:12:15.184000Z', 'last_seen': '2022-08-14T11:10:28.642000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | high |  | Zscaler |  | 2021-12-18T15:43:06.963000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 9c5e5aae-b3fb-47e7-998e-4cce5f34dd1e |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Installation | low | 2018-03-19T17:46:47.913000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-11-24T17:21:38.868000Z | This logic is intended to detect malicious executable binaries and scripts downloaded from Virtual Private Servers (VPSes). Various threat actors use VPSes to deliver payloads and tools to compromised devices. However, the transfer of a malicious executable does not necessarily indicate that an attacker achieved privileged code execution. For example, some exploit kits deliver executable payloads regardless of whether the exploit succeeded.<br/><br/>Gigamon ATR considers this activity high severity due to its historical use in both targeted and untargeted attacks. Gigamon ATR considers this detection low confidence because, while rare, some legitimate services host executable binaries and scripts using VPS providers.<br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the event is not downloading a benign file from a reputable domain. If the domain is reputable, and the resource name is thematically consistent, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the file is malicious in nature. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices. | src.ip | true | dst.ip,<br/>http:uri.uri,<br/>http:user_agent,<br/>http:response_mimes,<br/>http:files.sha256 | Executable Binary or Script from VPS | T1105 | (  <br/>    // From a select collection of VPS providers.<br/>    // To be replaced with intel matching<br/>    dst.asn.asn_org in (<br/>        "Choopa, LLC",<br/>        "DigitalFyre Internet Solutions, LLC.",<br/>        "DigitalOcean, LLC",<br/>        "DIGITALOCEAN-ASN",<br/>        "Hetzner Online GmbH",<br/>        "Host Sailor Ltd.",<br/>        "Hosting Solution Ltd.",<br/>        "Linode, LLC",<br/>        "OVH SAS",<br/>        "Relink LTD",<br/>        "TimeWeb Ltd."<br/>    )<br/>                        <br/>    // Plain executable binaries<br/>    AND (response_mime LIKE "%executable%"<br/>    OR response_mime LIKE "%application/x-dosexec%"<br/>    OR response_mime LIKE "%application/x-macbinary%"<br/>    <br/>    // Commonly malicious<br/>    OR response_mime LIKE "%application/x-ms-shortcut%"<br/>    OR response_mime LIKE "%application/vnd.ms-htmlhelp%"<br/>    <br/>    // System-level scripts<br/>    OR response_mime LIKE "%text/x-msdos-batch%"<br/>    OR response_mime LIKE "%x-shellscript%"<br/>    <br/>    // Filetypes not yet positively classified by FileTyper over binary content.<br/>    // Instead match by extension (also to be obviated by future FileTyper features)<br/>    OR (http:status_code >= 200 AND http:status_code <= 300 AND http:response_len > 0<br/>        AND (http:uri.uri MATCHES ".*\.(([hH][tT][aA])\|([vV][bB][sS])\|([pP][sS]1)\|([jJ][sS][eE])\|([wW][sS][fF])\|([mM][sS][iI]))"))<br/>    )<br/>) <br/><br/>// Whitelist known benign<br/>AND <br/>(<br/>    host.domain NOT IN (<br/>        "eu-1-downloads.airtame.com", // Wireless HDMI / Digital Signage application<br/>        "notepad-plus-plus.org" // Notepad++ source code editor<br/>    )<br/>    AND host.domain NOT LIKE "%.wireshark.org"<br/>    AND response_mime NOT IN ("application/x-alliant-executable", "application/x-alpha-executable")<br/>) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 16, 'first_seen': '2022-02-06T10:38:17.519000Z', 'last_seen': '2022-08-14T09:38:37.403000Z'} |  |  | high |  | Zscaler | procedure | 2021-03-17T23:37:00.727000Z | 9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3 | e1bb1e78-3a25-4c52-b766-402b4f8e9849 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Posture:Potentially Unauthorized Software or Device | high | 2018-03-19T17:45:25.580000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2021-03-10T23:10:08.942000Z | This logic is intended to detect active BitTorrent file sharing clients. BitTorrent is a peer-to-peer (P2P) client commonly used for sharing large files. Having the client installed on a host enables the user to both send and receive files. This activity frequently includes the download or sharing of illegally obtained files, and utilizes organizational resources to perform these activities, putting the company at risk.<br/><br/>Gigamon ATR considers BitTorrent activity low severity due to the relatively innocuous nature of the software that is installed. Gigamon ATR considers this detection high confidence due to the uniqueness of the user agent strings used in HTTP communications by BitTorrent clients. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by inspecting the affected asset for installed BitTorrent client software.<br/>2. Determine legitimate business need for software.<br/>3. Remove software if unnecessary. | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent | BitTorrent Client User Agent | T1071 | (<br/>    http:src.internal = true<br/>    OR http:source IN ("Zscaler")<br/>)<br/><br/>AND (<br/>   user_agent IN ("FDM 3.x", "Hydra HttpRequest")<br/>    OR user_agent LIKE "BTWebClient%"<br/>    OR user_agent LIKE "ACEStream/%"<br/>    OR user_agent LIKE "Transmission/%"<br/>    OR user_agent LIKE "Azureus%"<br/>    OR user_agent MATCHES ".*?[tT][oO][rR][rR][eE][nN][tT].*"<br/>) | {'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 27, 'first_seen': '2021-12-18T09:02:11.883000Z', 'last_seen': '2022-08-13T08:02:29.949000Z'} |  |  | low |  |  | tool_implementation | 2021-09-24T15:38:00.786000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 7d561d24-7c6a-407f-b14b-8e60ca3b8432 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Command and Control | moderate | 2021-12-18T15:46:38.978000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:46:38.978000Z | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings.<br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain.<br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior.<br/>2. Quarantine the impacted device.<br/>3. Begin incident response procedures on the impacted device.<br/>4. Block traffic to attacker infrastructure.<br/>5. Search for other impacted devices.  | DEFAULT | true |  | [Scenario 5] Empire Default Profile |  | // Default user-agent for Empire <br/>http:user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"<br/>// Default URIs for Empire<br/>AND uri.path IN ("/admin/get.php", "/login/process.php") <br/>// Default referrer behavior<br/>AND http:referrer.uri = null<br/> | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 46, 'first_seen': '2021-12-24T00:02:37.670000Z', 'last_seen': '2022-08-12T00:45:11.918000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | moderate |  | Zscaler |  | 2021-12-18T15:46:38.978000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 5cd225d7-1a65-4653-a5be-ae034e5f2934 |
>| b1f533b5-6360-494a-9f8b-9d90f1ad0207 | 10080 | Attack:Command and Control | moderate | 2018-03-19T17:45:11.192000Z | cd3ea8eb-e014-4f62-905d-78a021c768b2 | 2020-12-09T00:15:53.487000Z | This logic is intended to detect the Empire threat emulation software communicating over the HTTP protocol as it does with the default configuration options. Empire is an open-source framework used by both red teams and threat actors to operate compromised endpoints. Command and control traffic is encrypted and transmitted as HTTP payload data. The configuration can be modified to change default header settings. <br/><br/>Gigamon ATR considers Empire high severity because it is a fully featured backdoor that has historically been used in targeted attacks. Gigamon ATR considers this detection moderate confidence because the logic combines multiple criteria corresponding to typical Empire behavior, but may coincidentally match benign traffic. <br/><br/>## Next Steps <br/>1. Determine if this detection is a true positive by: <br/>    1. Checking that the HTTP event does not involve a known or reputable domain. If the domain is reputable, and the source device regularly communicates with the involved user-agent string, the detection could be a false positive or a well concealed attack using a compromised domain. <br/>    2. Verifying that the host is exhibiting suspicious Python or PowerShell behavior. <br/>2. Quarantine the impacted device. <br/>3. Begin incident response procedures on the impacted device. <br/>4. Block traffic to attacker infrastructure. <br/>5. Search for other impacted devices.  | src.ip | true | dst.ip,<br/>http:host,<br/>http:uri.uri,<br/>http:user_agent | Empire Default Profile | T1071.001 | // Default user-agent for Empire <br/>http:user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"<br/>// Default URIs for Empire<br/>AND uri.path IN ("/admin/get.php", "/login/process.php") <br/>// Default referrer behavior<br/>AND http:referrer.uri = null | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 3, 'detection_muted_count': 0, 'detection_resolved_count': 63, 'first_seen': '2021-12-24T00:02:37.670000Z', 'last_seen': '2022-08-12T00:45:11.918000Z'},<br/>{'account_uuid': 'dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8', 'query_filter': "http:user_agent != 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'", 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 0, 'detection_muted_count': 0, 'detection_resolved_count': 18, 'first_seen': '2021-12-19T10:13:11.853000Z', 'last_seen': '2022-02-13T15:42:35.898000Z'} |  |  | high |  |  | tool_implementation | 2021-03-17T23:37:16.914000Z | 9128e5ed-4ee4-4b29-a7f4-ea9f9f092dc3 | c4a5dcc9-8ae6-4845-bbf9-a8ef04849bb6 |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 10080 | Attack:Installation | moderate | 2021-12-18T15:45:36.261000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | 2021-12-18T15:45:36.261000Z | This logic is intended to detect successful downloads of an HTML Application (HTA) from external servers. HTAs allow for arbitrary code execution on Microsoft Windows systems and are commonly used by threat actors to install malware.<br/><br/>Gigamon ATR considers this activity to be moderate severity due to the fact that an HTA download and execution could indicate that a threat actor has remote access to your environment, but Gigamon ATR is unable to determine successful execution from network traffic analysis alone. Gigamon ATR considers this detection moderate confidence due to the unknown nature of the applications being downloaded and potential benign use of HTAs.<br/><br/>## Next Steps<br/>1. Determine if this detection is a true positive by:<br/>      1. Validating the server involved in the HTA download is not a known or trusted server for application downloads.<br/>      2. Inspecting the downloaded application for malicious content.<br/>2. If the HTA is not validated, begin incident response procedures on the impacted device and identify any additional malware downloaded to the host.  | DEFAULT | true |  | [Scenario 5] HTML Application (HTA) Download |  | // Look for HTA by URI or by MimeType<br/>(<br/>    http:uri.path MATCHES ".*?\.[hH][tT][aA]"<br/>    OR http:response_mime = "application/hta"<br/>)<br/><br/>// Successful external downloads only<br/>AND (<br/>    dst.internal = false<br/>    OR (<br/>        // Not an internal IP<br/>        host.ip != null<br/>        // Proxied traffic<br/>        AND uri.scheme != null<br/>    )<br/>)<br/>AND status_code >= 200 <br/>AND status_code < 300<br/><br/>// Whitelist out known good that does this<br/>AND host.domain NOT LIKE "%.kaspersky.com"<br/>AND host.domain != "kav8.zonealarm.com"<br/>AND (<br/>    host.domain != "downloadupdates.axway.com"<br/>    OR uri.path NOT MATCHES  "/kaspersky(86)?/.*"<br/>)<br/>AND (<br/>    user_agent NOT LIKE "HelloTalk %"<br/>    OR uri.path NOT MATCHES "/[0-9]{8}/[0-9a-f]{17}_[0-9a-f]{5}\.hta"<br/>) | {'account_uuid': 'a24b62ea-776d-4c62-ac8e-c980689ea71f', 'query_filter': None, 'muted': False, 'muted_comment': None, 'muted_user_uuid': None, 'muted_timestamp': None, 'detection_count': 1, 'detection_muted_count': 0, 'detection_resolved_count': 21, 'first_seen': '2021-12-24T00:01:30.364000Z', 'last_seen': '2022-08-12T00:01:32.770000Z'} | a24b62ea-776d-4c62-ac8e-c980689ea71f |  | moderate |  | Zscaler |  | 2021-12-18T15:45:36.261000Z | 2964a059-e470-4622-929e-2cadcccf98f4 | d1740713-b975-4341-a580-456511fcb784 |


### insight-resolve-detection
***
Resolve a specific detection.


#### Base Command

`insight-resolve-detection`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_uuid | Detection UUID to resolve. | Required | 
| resolution | Resolution state. Options: true_positive_mitigated, true_posititve_no_action, false_positive, unknown. Possible values are: true_positive_mitigated, true_positive_no_action, false_positive, unknown. | Required | 
| resolution_comment | Optional comment for the resolution. | Optional | 


#### Context Output

There is no context output for this command.
### insight-get-detection-rule-events
***
Get a list of the events that matched on a specific rule.


#### Base Command

`insight-get-detection-rule-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_uuid | Rule UUID to get events for. | Required | 
| offset | The number of records to skip past. | Optional | 
| limit | The number of records to return, default: 100, max: 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Events.src_ip | string | Source IP address | 
| Insight.Events.dst_ip | string | Destination IP address | 
| Insight.Events.src_port | number | Source port number | 
| Insight.Events.dst_port | number | Destination port number | 
| Insight.Events.host_domain | string | Domain name | 
| Insight.Events.flow_id | string | Unique ID of the flow record | 
| Insight.Events.event_type | string | Event type | 
| Insight.Events.sensor_id | string | ID code of the sensor | 
| Insight.Events.timestamp | date | Date the event occurred | 
| Insight.Events.customer_id | string | ID code of the customer account | 
| Insight.Events.uuid | string | Unique ID for the event | 

### insight-create-detection-rule
***
Create a new detection rule.


#### Base Command

`insight-create-detection-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_uuid | Account where the rule will be created. | Required | 
| name | The name of the rule. | Required | 
| category | The category of the rule. Possible values are: Attack:Command and Control, Attack:Exploitation, Attack:Exfiltration, Attack:Installation, Attack:Lateral Movement, Attack:Infection Vector, Attack:Miscellaneous, Miscellaneous, Posture:Anomalous Activity, Posture:Insecure Configuration, Posture:Potentially Unauthorized Software or Device, Posture:Miscellaneous, PUA:Adware, PUA:Spyware, PUA:Unauthorized Resource Use, PUA:Miscellaneous. | Required | 
| query_signature | The IQL query for the rule. | Required | 
| description | A description for the rule. | Required | 
| severity | The severity of the rule. Possible values are: low, moderate, high. | Required | 
| confidence | The confidence of the rule. Possible values are: low, moderate, high. | Required | 
| run_account_uuids | Account UUIDs on which this rule will run. This will usually be just your own account UUID. (separate multiple accounts by comma). | Required | 
| auto_resolution_minutes | The number of minutes after which detections will be auto-resolved. If 0 then detections have to be manually resolved. | Optional | 
| device_ip_fields | List of event fields to check for impacted devices. Possible values are: DEFAULT, src.ip, dst.ip, dhcp:assignment.ip, dns:answers.ip, http:host.ip, http:uri.host.ip, http:referrer.host.ip, http:headers.location.host.ip, http:headers.origin.host.ip, http:headers.proxied_client_ips.ip, http:headers.refresh.uri.host.ip, smtp:helo.ip, smtp:x_originating_ip.ip, smtp:path.ip, software:host.ip, ssl:server_name_indication.ip, suricata:http.host.ip, x509:san_dns.ip, x509:san_ip.ip. | Required | 


#### Context Output

There is no context output for this command.
### insight-get-entity-summary
***
Get summary information about an IP or domain.


#### Base Command

`insight-get-entity-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP or Domain to get entity data for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.Summary.entity | string | Entity identifier | 
| Insight.Entity.Summary.first_seen | date | First seen date for this entity | 
| Insight.Entity.Summary.last_seen | date | Last seen date for this entity | 
| Insight.Entity.Summary.prevalence_count_internal | number | Prevalence for this entity within the environment | 

#### Command example
```!insight-get-entity-summary entity=8.8.8.8```
#### Context Example
```json
{
    "Insight": {
        "Entity": {
            "Summary": {
                "entity": "8.8.8.8",
                "first_seen": "2021-12-17T21:30:02.000Z",
                "last_seen": "2022-08-18T17:09:59.594Z",
                "prevalence_count_internal": 2,
                "tags": []
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|entity|first_seen|last_seen|prevalence_count_internal|tags|
>|---|---|---|---|---|
>| 8.8.8.8 | 2021-12-17T21:30:02.000Z | 2022-08-18T17:09:59.594Z | 2 |  |


### insight-get-entity-pdns
***
Get passive DNS information about an IP or domain.


#### Base Command

`insight-get-entity-pdns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP or Domain to get passive DNS data for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.PDNS.account_uuid | string | Unique ID for the customer account | 
| Insight.Entity.PDNS.first_seen | date | First seen date for matching dns information | 
| Insight.Entity.PDNS.last_seen | date | Last seen date for matching dns information | 
| Insight.Entity.PDNS.record_type | string | DNS record type | 
| Insight.Entity.PDNS.resolved | string | Domain name resolved from the DNS record | 
| Insight.Entity.PDNS.sensor_id | string | ID code of the sensor | 
| Insight.Entity.PDNS.source | string | Source of the DNS record | 

#### Command example
```!insight-get-entity-pdns entity=google.com```
#### Context Example
```json
{
    "Insight": {
        "Entity": {
            "PDNS": [
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-06T00:00:00.000Z",
                    "last_seen": "2022-08-17T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.12.206",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2021-12-22T00:00:00.000Z",
                    "last_seen": "2022-03-16T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.12.206",
                    "sensor_id": "gdm1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-03T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.5.238",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-03-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.5.238",
                    "sensor_id": "gdm1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-03-30T00:00:00.000Z",
                    "last_seen": "2022-08-18T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.7.238",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2021-12-17T00:00:00.000Z",
                    "last_seen": "2022-03-28T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.7.238",
                    "sensor_id": "gdm1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-03-31T00:00:00.000Z",
                    "last_seen": "2022-08-18T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.8.14",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-20T00:00:00.000Z",
                    "last_seen": "2022-08-12T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.8.14",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2021-12-23T00:00:00.000Z",
                    "last_seen": "2022-03-17T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.8.14",
                    "sensor_id": "gdm1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-24T00:00:00.000Z",
                    "last_seen": "2022-02-25T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "172.217.8.14",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-16T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.100",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-02-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.100",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-16T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.101",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-02-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.101",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-16T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.102",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-02-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.102",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-16T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.113",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-02-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.113",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-16T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.138",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-02-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.138",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2022-05-16T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.139",
                    "sensor_id": "tma2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "a24b62ea-776d-4c62-ac8e-c980689ea71f",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-02-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "173.194.211.139",
                    "sensor_id": "tma1",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2022-04-03T00:00:00.000Z",
                    "last_seen": "2022-08-14T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "216.58.218.238",
                    "sensor_id": "gdm2",
                    "source": "icebrg_dns"
                },
                {
                    "account_uuid": "dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8",
                    "first_seen": "2021-12-19T00:00:00.000Z",
                    "last_seen": "2022-03-27T00:00:00.000Z",
                    "record_type": "a",
                    "resolved": "216.58.218.238",
                    "sensor_id": "gdm1",
                    "source": "icebrg_dns"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|account_uuid|first_seen|last_seen|record_type|resolved|sensor_id|source|
>|---|---|---|---|---|---|---|
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-06T00:00:00.000Z | 2022-08-17T00:00:00.000Z | a | 172.217.12.206 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2021-12-22T00:00:00.000Z | 2022-03-16T00:00:00.000Z | a | 172.217.12.206 | gdm1 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 172.217.5.238 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2021-12-19T00:00:00.000Z | 2022-03-27T00:00:00.000Z | a | 172.217.5.238 | gdm1 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-03-30T00:00:00.000Z | 2022-08-18T00:00:00.000Z | a | 172.217.7.238 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2021-12-17T00:00:00.000Z | 2022-03-28T00:00:00.000Z | a | 172.217.7.238 | gdm1 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-03-31T00:00:00.000Z | 2022-08-18T00:00:00.000Z | a | 172.217.8.14 | gdm2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-20T00:00:00.000Z | 2022-08-12T00:00:00.000Z | a | 172.217.8.14 | tma2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2021-12-23T00:00:00.000Z | 2022-03-17T00:00:00.000Z | a | 172.217.8.14 | gdm1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-24T00:00:00.000Z | 2022-02-25T00:00:00.000Z | a | 172.217.8.14 | tma1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-16T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 173.194.211.100 | tma2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-19T00:00:00.000Z | 2022-02-27T00:00:00.000Z | a | 173.194.211.100 | tma1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-16T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 173.194.211.101 | tma2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-19T00:00:00.000Z | 2022-02-27T00:00:00.000Z | a | 173.194.211.101 | tma1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-16T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 173.194.211.102 | tma2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-19T00:00:00.000Z | 2022-02-27T00:00:00.000Z | a | 173.194.211.102 | tma1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-16T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 173.194.211.113 | tma2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-19T00:00:00.000Z | 2022-02-27T00:00:00.000Z | a | 173.194.211.113 | tma1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-16T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 173.194.211.138 | tma2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-19T00:00:00.000Z | 2022-02-27T00:00:00.000Z | a | 173.194.211.138 | tma1 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2022-05-16T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 173.194.211.139 | tma2 | icebrg_dns |
>| a24b62ea-776d-4c62-ac8e-c980689ea71f | 2021-12-19T00:00:00.000Z | 2022-02-27T00:00:00.000Z | a | 173.194.211.139 | tma1 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2022-04-03T00:00:00.000Z | 2022-08-14T00:00:00.000Z | a | 216.58.218.238 | gdm2 | icebrg_dns |
>| dc9ab97f-9cdf-46af-8ca2-e71e8e8243c8 | 2021-12-19T00:00:00.000Z | 2022-03-27T00:00:00.000Z | a | 216.58.218.238 | gdm1 | icebrg_dns |


### insight-get-entity-dhcp
***
Get DHCP information about an IP address.


#### Base Command

`insight-get-entity-dhcp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | IP to get DHCP data for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.DHCP.customer_id | string | ID code of the customer account | 
| Insight.Entity.DHCP.hostnames | string | Hostname of the entity | 
| Insight.Entity.DHCP.ip | string | IP Address of the entity | 
| Insight.Entity.DHCP.lease_end | date | DHCP lease end date | 
| Insight.Entity.DHCP.lease_start | date | DHCP lease start date | 
| Insight.Entity.DHCP.mac | string | MAC address of the entity | 
| Insight.Entity.DHCP.sensor_id | string | Sensor ID that recorded the entity data | 
| Insight.Entity.DHCP.start_lease_as_long | number | Start Date as a long value | 

#### Command example
```!insight-get-entity-dhcp entity=10.1.2.3```
#### Human Readable Output

>No result found.

### insight-get-entity-file
***
Get information about a file.


#### Base Command

`insight-get-entity-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | File hash. Can be an MD5, SHA1, or SHA256 hash of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Entity.File.entity | string | The entity identifier | 
| Insight.Entity.File.sha1 | string | The entity SHA1 hash | 
| Insight.Entity.File.sha256 | string | The entity SHA256 hash | 
| Insight.Entity.File.md5 | string | The entity MD5 hash | 
| Insight.Entity.File.customer_id | string | ID code of the customer account | 
| Insight.Entity.File.names | string | File names for the entity | 
| Insight.Entity.File.prevalence_count_internal | number | Prevalence for this file within the environment | 
| Insight.Entity.File.last_seen | date | Last seen date for this file | 
| Insight.Entity.File.mime_type | string | File MIME type | 
| Insight.Entity.File.first_seen | date | First seen date for this file | 
| Insight.Entity.File.bytes | number | File size | 
| Insight.Entity.File.pe | string | File Portable Executable attributes | 

#### Command example
```!insight-get-entity-file hash=2b7a609371b2a844181c2f79f1b45cf7```
#### Human Readable Output

>No result found.

### insight-get-telemetry-events
***
Get event telemetry data grouped by time.


#### Base Command

`insight-get-telemetry-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval | Interval to group by: hour (default) or day. Possible values are: hour, day. | Optional | 
| start_date | Start date/time to query for. The default is 1 day ago for interval=hour or 30 days ago for interval=day. | Optional | 
| end_date | End date/time to query for. The default is the current time. | Optional | 
| account_uuid | Account uuid to filter by. | Optional | 
| account_code | Account code to filter by. | Optional | 
| sensor_id | Sensor id to filter by. | Optional | 
| event_type | The type of event. Limited to flow, dns, http, ssl, and x509. Possible values are: flow, dns, http, ssl, x509. | Optional | 
| group_by | Optionally group results by: sensor_id, event_type. Possible values are: sensor_id, event_type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Telemetry.Events.timestamp | date | Timestamp of the grouped data | 
| Insight.Telemetry.Events.event_count | number | Number of events | 
| Insight.Telemetry.Events.sensor_id | string | Sensor name \(if grouped by sensor_id\) | 
| Insight.Telemetry.Events.event_type | string | Type of event \(if grouped by event_type\) | 

### insight-get-telemetry-packetstats
***
Get packetstats telemetry data grouped by time.


#### Base Command

`insight-get-telemetry-packetstats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | Scopes the returned metrics to the interfaces of the specified sensor ID. | Optional | 
| start_date | Scopes the returned metrics to dates after the given start_date. If empty returns most current packet stats. | Optional | 
| end_date | Scopes the returned metrics to dates before the given end_date. If empty returns most current packet stats. | Optional | 
| interval | Aggregation interval. 1 hr is not specified by default. | Optional | 
| group_by | Option to group by the following fields: interface_name, sensor_id, account_code. Possible values are: interface_name, sensor_id, account_code. | Optional | 
| account_code | Account code to filter by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Telemetry.Packetstats.account_code | string | Account code the data was filtered by | 
| Insight.Telemetry.Packetstats.timestamp | date | Timestamp of the grouped data | 
| Insight.Telemetry.Packetstats.interface_name | string | Interface the packet data was recorded from | 
| Insight.Telemetry.Packetstats.rx_bits_per_second | number | Receive throughput \(bits per second\) | 
| Insight.Telemetry.Packetstats.rx_bytes | number | Receive data size \(bytes\) | 
| Insight.Telemetry.Packetstats.rx_errors | number | Number of receive errors | 
| Insight.Telemetry.Packetstats.rx_packets | number | Number of receive packets | 
| Insight.Telemetry.Packetstats.sensor_id | string | Sensor ID packet data was recorded from | 
| Insight.Telemetry.Packetstats.tx_bytes | number | Transmit data size \(bytes\) | 
| Insight.Telemetry.Packetstats.tx_errors | number | Number of transmit errors | 
| Insight.Telemetry.Packetstats.tx_packets | number | Number of transmit packets | 

### insight-get-telemetry-network
***
Get network telemetry data grouped by time


#### Base Command

`insight-get-telemetry-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_code | Account code to filter by. | Optional | 
| interval | The interval to filter by (day, month_to_day). Possible values are: hour, day. | Optional | 
| latest_each_month | latest_each_month	No	No	Filters out all but the latest day and month_to_date for each month. | Optional | 
| sort_order | Sorts by account code first, then timestamp. asc or desc. The default is desc. | Optional | 
| limit | The maximum number of records to return, default: 100, max: 1000. Default is 1000. | Optional | 
| offset | The number of records to skip past. Default: 0. | Optional | 
| start_date | Start date to filter by. | Optional | 
| end_date | End date to filter by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Insight.Telemetry.NetworkUsage.account_code | string | The account code for the network usage. | 
| Insight.Telemetry.NetworkUsage.percentile_bps | long | The top percentile BPS value across sensors. | 
| Insight.Telemetry.NetworkUsage.percentile | int | Percentile of BPS records to calculate for percentile_bps. | 
| Insight.Telemetry.NetworkUsage.interval | unknown | Time span the calculation was performed over \(day, month_to_day\). | 
| Insight.Telemetry.Packetstats.timestamp | date | The date the calculation was performed until. | 
