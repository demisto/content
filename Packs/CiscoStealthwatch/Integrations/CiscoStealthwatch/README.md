Scalable visibility and security analytics.
This integration was integrated and tested with version 7.2.1 of Cisco Secure Network Analytics (Stealthwatch). Due to changes in the product API, versions grater than 7.3.2 (including) are currently not supported.

## Configure Cisco Stealthwatch in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Server URL for Cisco Stealthwatch console e.g.: https://ip:port/. | True |
| User Credentials |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cisco-stealthwatch-query-flows-initialize
***
Initializes the flow search based on specified arguments. Must provide a start time, time range, or start time and end time.


#### Base Command

`cisco-stealthwatch-query-flows-initialize`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to initialize its flow search. | Required | 
| start_time | Start time in the format: YYYY-mm-ddTHH:MM:SSZ. If start_time is provided but end_time is not provided, the end_time will be set to the current time. | Optional | 
| end_time | End time in the format: YYYY-mm-ddTHH:MM:SSZ. . | Optional | 
| time_range | An optional time range, for example: 3 months, 1 week, 1 day ago, etc. | Optional | 
| limit | The maximum number of records to retrieve. Default is 20. | Optional | 
| ip_addresses | The IP address by which to filter the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.FlowStatus.id | str | The ID of the flow. | 
| CiscoStealthwatch.FlowStatus.searchJobStatus | str | The search job status of the flow. | 
| CiscoStealthwatch.FlowStatus.percentComplete | str | The percent of the flow that was completed. | 


#### Command Example
```!cisco-stealthwatch-query-flows-initialize tenant_id=102 limit=3 time_range="1 week"```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "FlowStatus": {
            "domainId": "102",
            "id": "604f7115e4b0bbedc8c77d8d",
            "percentComplete": 100,
            "status": "IN_PROGRESS"
        }
    }
}
```

#### Human Readable Output

>### Query Flows Initializing Information:
>|Id|Status|Percent Complete|
>|---|---|---|
>| 604f7115e4b0bbedc8c77d8d | IN_PROGRESS | 100.0 |


### cisco-stealthwatch-query-flows-status
***
Checks the flow search status.


#### Base Command

`cisco-stealthwatch-query-flows-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to check its flow search status. | Required | 
| search_id | The ID of the search from the cisco-stealthwatch-query-flows-initialize command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.FlowStatus.id | str | The ID of the flow. | 
| CiscoStealthwatch.FlowStatus.percentComplete | str | The percent of the flow that was completed. | 


#### Command Example
```!cisco-stealthwatch-query-flows-status tenant_id=102 search_id=604f64afe4b0bbedc8c77a9d```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "FlowStatus": {
            "domainId": "102",
            "id": "604f64afe4b0bbedc8c77a9d",
            "percentComplete": 100,
            "status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### Query Flows Status Information:
>|Id|Percent Complete|
>|---|---|
>| 604f64afe4b0bbedc8c77a9d | 100.0 |


### cisco-stealthwatch-query-flows-results
***
Retrieves the flow search results. Use this command after the search job completes.


#### Base Command

`cisco-stealthwatch-query-flows-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to retrieve its flow search results. | Required | 
| search_id | The ID of the search from the cisco-stealthwatch-query-flows-initialize command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.FlowResults.id | str | The ID of the flow. | 
| CiscoStealthwatch.FlowResults.tenantId | str | The tenant ID of the flow. | 
| CiscoStealthwatch.FlowResults.flowCollectorId | str | The collector ID of the flow. | 
| CiscoStealthwatch.FlowResults.protocol | str | The protocol of the flow. | 
| CiscoStealthwatch.FlowResults.serviceId | str | The service ID of the flow. | 
| CiscoStealthwatch.FlowResults.statistics | str | The statistics of the flow. | 
| CiscoStealthwatch.FlowResults.peer | str | The peer of the flow. | 
| CiscoStealthwatch.FlowResults.subject | str | The subject of the flow. | 


#### Command Example
```!cisco-stealthwatch-query-flows-results tenant_id=102 search_id=604f64afe4b0bbedc8c77a9d```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "FlowResults": [
            {
                "applicationId": 170,
                "cipherSuite": {
                    "authAlgorithm": "N/A",
                    "encAlgorithm": "N/A",
                    "id": "N/A",
                    "keyExchange": "N/A",
                    "keyLength": "N/A",
                    "messageAuthCode": "N/A",
                    "name": "N/A",
                    "protocol": "N/A"
                },
                "flowCollectorId": 121,
                "id": 10142775,
                "mplsLabel": -1,
                "peer": {
                    "byteRate": 0,
                    "bytes": 0,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "x.x.x.x",
                    "natPort": -1,
                    "orientation": "server",
                    "packetRate": 0,
                    "packets": 0,
                    "percentBytes": 0,
                    "portProtocol": {
                        "port": 2055,
                        "protocol": "UDP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "protocol": "UDP",
                "serviceId": 38,
                "statistics": {
                    "activeDuration": 320000,
                    "byteCount": 21403751,
                    "byteRate": 267546.8875,
                    "firstActiveTime": "2021-03-15T13:36:15.000+0000",
                    "flowTimeSinceStart": 240673,
                    "lastActiveTime": "2021-03-15T13:41:35.000+0000",
                    "numCombinedFlowRecords": 2,
                    "packetCount": 15667,
                    "packetRate": 195.8375,
                    "roundTripTime": 0,
                    "rttAverage": -1,
                    "rttMaximum": -1,
                    "rttMinimum": -1,
                    "serverResponseTime": 0,
                    "srtAverage": -1,
                    "srtMaximum": -1,
                    "srtMinimum": -1,
                    "subjectPeerRatio": 100,
                    "tcpConnections": 0,
                    "tcpRetransmissions": -1,
                    "tcpRetransmissionsRatio": -0.006382842918235782
                },
                "subject": {
                    "byteRate": 267546.8875,
                    "bytes": 21403751,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "x.x.x.x",
                    "natPort": -1,
                    "orientation": "client",
                    "packetRate": 195.8375,
                    "packets": 15667,
                    "percentBytes": 100,
                    "portProtocol": {
                        "port": 59315,
                        "protocol": "UDP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "tenantId": 102,
                "tlsVersion": "NONE",
                "vlanId": -1
            },
            {
                "applicationId": 170,
                "cipherSuite": {
                    "authAlgorithm": "N/A",
                    "encAlgorithm": "N/A",
                    "id": "N/A",
                    "keyExchange": "N/A",
                    "keyLength": "N/A",
                    "messageAuthCode": "N/A",
                    "name": "N/A",
                    "protocol": "N/A"
                },
                "flowCollectorId": 121,
                "id": 10142776,
                "mplsLabel": -1,
                "peer": {
                    "byteRate": 0,
                    "bytes": 0,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "x.x.x.x",
                    "natPort": -1,
                    "orientation": "server",
                    "packetRate": 0,
                    "packets": 0,
                    "percentBytes": 0,
                    "portProtocol": {
                        "port": 2055,
                        "protocol": "UDP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "protocol": "UDP",
                "serviceId": 38,
                "statistics": {
                    "activeDuration": 320000,
                    "byteCount": 21403751,
                    "byteRate": 267546.8875,
                    "firstActiveTime": "2021-03-15T13:36:15.000+0000",
                    "flowTimeSinceStart": 240673,
                    "lastActiveTime": "2021-03-15T13:41:35.000+0000",
                    "numCombinedFlowRecords": 2,
                    "packetCount": 15667,
                    "packetRate": 195.8375,
                    "roundTripTime": 0,
                    "rttAverage": -1,
                    "rttMaximum": -1,
                    "rttMinimum": -1,
                    "serverResponseTime": 0,
                    "srtAverage": -1,
                    "srtMaximum": -1,
                    "srtMinimum": -1,
                    "subjectPeerRatio": 100,
                    "tcpConnections": 0,
                    "tcpRetransmissions": -1,
                    "tcpRetransmissionsRatio": -0.006382842918235782
                },
                "subject": {
                    "byteRate": 267546.8875,
                    "bytes": 21403751,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "x.x.x.x",
                    "natPort": -1,
                    "orientation": "client",
                    "packetRate": 195.8375,
                    "packets": 15667,
                    "percentBytes": 100,
                    "portProtocol": {
                        "port": 52656,
                        "protocol": "UDP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "tenantId": 102,
                "tlsVersion": "NONE",
                "vlanId": -1
            },
            {
                "applicationId": 176,
                "cipherSuite": {
                    "authAlgorithm": "N/A",
                    "encAlgorithm": "N/A",
                    "id": "N/A",
                    "keyExchange": "N/A",
                    "keyLength": "N/A",
                    "messageAuthCode": "N/A",
                    "name": "N/A",
                    "protocol": "N/A"
                },
                "flowCollectorId": 121,
                "id": 10142778,
                "mplsLabel": -1,
                "peer": {
                    "byteRate": 0,
                    "bytes": 0,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "x.x.x.x",
                    "natPort": -1,
                    "orientation": "server",
                    "packetRate": 0,
                    "packets": 0,
                    "percentBytes": 0,
                    "portProtocol": {
                        "port": 514,
                        "protocol": "UDP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "protocol": "UDP",
                "serviceId": 73,
                "statistics": {
                    "activeDuration": 320000,
                    "byteCount": 213807311,
                    "byteRate": 2672591.3875,
                    "firstActiveTime": "2021-03-15T13:36:15.000+0000",
                    "flowTimeSinceStart": 240673,
                    "lastActiveTime": "2021-03-15T13:41:35.000+0000",
                    "numCombinedFlowRecords": 2,
                    "packetCount": 173345,
                    "packetRate": 2166.8125,
                    "roundTripTime": 0,
                    "rttAverage": -1,
                    "rttMaximum": -1,
                    "rttMinimum": -1,
                    "serverResponseTime": 0,
                    "srtAverage": -1,
                    "srtMaximum": -1,
                    "srtMinimum": -1,
                    "subjectPeerRatio": 100,
                    "tcpConnections": 0,
                    "tcpRetransmissions": -1,
                    "tcpRetransmissionsRatio": -0.0005768842481756036
                },
                "subject": {
                    "byteRate": 2672591.3875,
                    "bytes": 213807311,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "x.x.x.x",
                    "natPort": -1,
                    "orientation": "client",
                    "packetRate": 2166.8125,
                    "packets": 173345,
                    "percentBytes": 100,
                    "portProtocol": {
                        "port": 48861,
                        "protocol": "UDP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "tenantId": 102,
                "tlsVersion": "NONE",
                "vlanId": -1
            }
        ]
    }
}
```

#### Human Readable Output

>### Query Flows Results Information:
>|Id|Tenant Id|Flow Collector Id|Protocol|Service Id|Statistics|Peer|Subject|
>|---|---|---|---|---|---|---|---|
>| 10142775 | 102 | 121 | UDP | 38 | activeDuration: 320000<br/>numCombinedFlowRecords: 2<br/>firstActiveTime: 2021-03-15T13:36:15.000+0000<br/>lastActiveTime: 2021-03-15T13:41:35.000+0000<br/>tcpRetransmissions: -1<br/>byteCount: 21403751<br/>packetCount: 15667<br/>byteRate: 267546.8875<br/>packetRate: 195.8375<br/>tcpConnections: 0<br/>roundTripTime: 0<br/>serverResponseTime: 0<br/>subjectPeerRatio: 100.0<br/>rttAverage: -1<br/>rttMaximum: -1<br/>rttMinimum: -1<br/>srtAverage: -1<br/>srtMaximum: -1<br/>srtMinimum: -1<br/>flowTimeSinceStart: 240673<br/>tcpRetransmissionsRatio: -0.006382842918235782 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: x.x.x.x<br/>natPort: -1<br/>portProtocol: {"port": 2055, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 0.0<br/>bytes: 0<br/>packets: 0<br/>byteRate: 0.0<br/>packetRate: 0.0<br/>orientation: server<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: x.x.x.x<br/>natPort: -1<br/>portProtocol: {"port": 59315, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 100.0<br/>bytes: 21403751<br/>packets: 15667<br/>byteRate: 267546.8875<br/>packetRate: 195.8375<br/>orientation: client<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 |
>| 10142776 | 102 | 121 | UDP | 38 | activeDuration: 320000<br/>numCombinedFlowRecords: 2<br/>firstActiveTime: 2021-03-15T13:36:15.000+0000<br/>lastActiveTime: 2021-03-15T13:41:35.000+0000<br/>tcpRetransmissions: -1<br/>byteCount: 21403751<br/>packetCount: 15667<br/>byteRate: 267546.8875<br/>packetRate: 195.8375<br/>tcpConnections: 0<br/>roundTripTime: 0<br/>serverResponseTime: 0<br/>subjectPeerRatio: 100.0<br/>rttAverage: -1<br/>rttMaximum: -1<br/>rttMinimum: -1<br/>srtAverage: -1<br/>srtMaximum: -1<br/>srtMinimum: -1<br/>flowTimeSinceStart: 240673<br/>tcpRetransmissionsRatio: -0.006382842918235782 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: x.x.x.x<br/>natPort: -1<br/>portProtocol: {"port": 2055, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 0.0<br/>bytes: 0<br/>packets: 0<br/>byteRate: 0.0<br/>packetRate: 0.0<br/>orientation: server<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: x.x.x.x<br/>natPort: -1<br/>portProtocol: {"port": 52656, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 100.0<br/>bytes: 21403751<br/>packets: 15667<br/>byteRate: 267546.8875<br/>packetRate: 195.8375<br/>orientation: client<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 |
>| 10142778 | 102 | 121 | UDP | 73 | activeDuration: 320000<br/>numCombinedFlowRecords: 2<br/>firstActiveTime: 2021-03-15T13:36:15.000+0000<br/>lastActiveTime: 2021-03-15T13:41:35.000+0000<br/>tcpRetransmissions: -1<br/>byteCount: 213807311<br/>packetCount: 173345<br/>byteRate: 2672591.3875<br/>packetRate: 2166.8125<br/>tcpConnections: 0<br/>roundTripTime: 0<br/>serverResponseTime: 0<br/>subjectPeerRatio: 100.0<br/>rttAverage: -1<br/>rttMaximum: -1<br/>rttMinimum: -1<br/>srtAverage: -1<br/>srtMaximum: -1<br/>srtMinimum: -1<br/>flowTimeSinceStart: 240673<br/>tcpRetransmissionsRatio: -0.0005768842481756036 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: x.x.x.x<br/>natPort: -1<br/>portProtocol: {"port": 514, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 0.0<br/>bytes: 0<br/>packets: 0<br/>byteRate: 0.0<br/>packetRate: 0.0<br/>orientation: server<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: x.x.x.x<br/>natPort: -1<br/>portProtocol: {"port": 48861, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 100.0<br/>bytes: 213807311<br/>packets: 173345<br/>byteRate: 2672591.3875<br/>packetRate: 2166.8125<br/>orientation: client<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 |


### cisco-stealthwatch-list-tags
***
Lists the host groups (called tags in the API).


#### Base Command

`cisco-stealthwatch-list-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to get its tags. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.Tag.id | str | The ID of the tag. | 
| CiscoStealthwatch.Tag.displayName | str | The display name of the tag. | 


#### Command Example
```!cisco-stealthwatch-list-tags tenant_id=102```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "Tag": [
            {
                "displayName": "Internal Host Tags",
                "id": 1
            },
            {
                "displayName": "Servers",
                "id": 2
            },
            {
                "displayName": "Employee Wired",
                "id": 3
            },
            {
                "displayName": "Client IP Ranges (DHCP Range)",
                "id": 5
            },
            {
                "displayName": "Other",
                "id": 6
            },
            {
                "displayName": "Protected Asset Monitoring",
                "id": 10
            },
            {
                "displayName": "Proxies",
                "id": 11
            },
            {
                "displayName": "VoIP",
                "id": 12
            },
            {
                "displayName": "VoIP Gateways",
                "id": 13
            },
            {
                "displayName": "Multicast",
                "id": 14
            },
            {
                "displayName": "Link-Local",
                "id": 17
            },
            {
                "displayName": "Broadcast",
                "id": 18
            },
            {
                "displayName": "Localhost",
                "id": 19
            },
            {
                "displayName": "By Function",
                "id": 23
            },
            {
                "displayName": "DMZ",
                "id": 24
            },
            {
                "displayName": "Antivirus Servers",
                "id": 25
            },
            {
                "displayName": "Backup Servers",
                "id": 26
            },
            {
                "displayName": "DNS Servers",
                "id": 27
            },
            {
                "displayName": "File Servers",
                "id": 28
            },
            {
                "displayName": "Mail Servers",
                "id": 30
            },
            {
                "displayName": "NTP Servers",
                "id": 31
            },
            {
                "displayName": "Employee VPN ",
                "id": 33
            },
            {
                "displayName": "Web Servers",
                "id": 34
            },
            {
                "displayName": "DHCP Servers",
                "id": 36
            },
            {
                "displayName": "VoIP Endpoints",
                "id": 37
            },
            {
                "displayName": "Domain Controllers",
                "id": 38
            },
            {
                "displayName": "By Location",
                "id": 43
            },
            {
                "displayName": "Employee Wireless",
                "id": 44
            },
            {
                "displayName": "Guest Wireless",
                "id": 45
            },
            {
                "displayName": "Network Scanners",
                "id": 48
            },
            {
                "displayName": "SMS Servers",
                "id": 50
            },
            {
                "displayName": "NAT Gateway",
                "id": 51
            },
            {
                "displayName": "Internet Facing Load Balancer VIPs",
                "id": 50067
            },
            {
                "displayName": "Internet Services",
                "id": 50068
            },
            {
                "displayName": "Protected Trapped Hosts - Honeypot",
                "id": 50069
            },
            {
                "displayName": "Database Servers",
                "id": 50075
            },
            {
                "displayName": "Trusted Users",
                "id": 50076
            },
            {
                "displayName": "Untrusted Users",
                "id": 50077
            },
            {
                "displayName": "Load Balancer VIPs",
                "id": 50079
            },
            {
                "displayName": "Internal Facing Load Balancer VIPs",
                "id": 50080
            },
            {
                "displayName": "Catch All",
                "id": 65534
            }
        ]
    }
}
```

#### Human Readable Output

>### Tags for tenant_id: 102:
>|Display Name|Id|
>|---|---|
>| Internal Host Tags | 1 |
>| Servers | 2 |
>| Employee Wired | 3 |
>| Client IP Ranges (DHCP Range) | 5 |
>| Other | 6 |
>| Protected Asset Monitoring | 10 |
>| Proxies | 11 |
>| VoIP | 12 |
>| VoIP Gateways | 13 |
>| Multicast | 14 |
>| Link-Local | 17 |
>| Broadcast | 18 |
>| Localhost | 19 |
>| By Function | 23 |
>| DMZ | 24 |
>| Antivirus Servers | 25 |
>| Backup Servers | 26 |
>| DNS Servers | 27 |
>| File Servers | 28 |
>| Mail Servers | 30 |
>| NTP Servers | 31 |
>| Employee VPN  | 33 |
>| Web Servers | 34 |
>| DHCP Servers | 36 |
>| VoIP Endpoints | 37 |
>| Domain Controllers | 38 |
>| By Location | 43 |
>| Employee Wireless | 44 |
>| Guest Wireless | 45 |
>| Network Scanners | 48 |
>| SMS Servers | 50 |
>| NAT Gateway | 51 |
>| Internet Facing Load Balancer VIPs | 50067 |
>| Internet Services | 50068 |
>| Protected Trapped Hosts - Honeypot | 50069 |
>| Database Servers | 50075 |
>| Trusted Users | 50076 |
>| Untrusted Users | 50077 |
>| Load Balancer VIPs | 50079 |
>| Internal Facing Load Balancer VIPs | 50080 |
>| Catch All | 65534 |


### cisco-stealthwatch-get-tag
***
Gets a single host group (called tag in the API).


#### Base Command

`cisco-stealthwatch-get-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to get its tag. | Required | 
| tag_id | The tag for which to get more information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.Tag.id | str | The name of the tag. | 
| CiscoStealthwatch.Tag.name | str | The ID of the tag. | 
| CiscoStealthwatch.Tag.location | str | The location of the tag. | 
| CiscoStealthwatch.Tag.domainId | str | The domain ID of the tag. | 


#### Command Example
```!cisco-stealthwatch-get-tag tenant_id=102 tag_id=1```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "Tag": {
            "display": {
                "domainId": 102,
                "editable": false,
                "id": 1,
                "idPath": [
                    1
                ],
                "location": "INSIDE",
                "name": "Inside Hosts",
                "path": []
            },
            "domainId": 102,
            "hostBaselines": true,
            "hostTrap": false,
            "id": 1,
            "inverseSuppression": false,
            "location": "INSIDE",
            "name": "Inside Hosts",
            "parentId": 2147483647,
            "sendToCognitiveFilter": "CROSS_PERIMETER",
            "sendToCta": false,
            "suppressExcludedServices": true
        }
    }
}
```

#### Human Readable Output

>### Tag 1 with tenant id 102 results:
>|Id|Name|Location|Domain Id|
>|---|---|---|---|
>| 1 | Inside Hosts | INSIDE | 102 |


### cisco-stealthwatch-list-tenants
***
Lists all domains if no domain is specified or gets a specified domain (called tenant(s) in the API).


#### Base Command

`cisco-stealthwatch-list-tenants`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to retrieve information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.Tenant.id | str | The ID of the tenant. | 
| CiscoStealthwatch.Tenant.displayName | str | The display name of the tenant. | 


#### Command Example
```!cisco-stealthwatch-list-tenants```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "Tenant": {
            "displayName": "companyname",
            "id": 102
        }
    }
}
```

#### Human Readable Output

>### Tenants:
>|Id|Display Name|
>|---|---|
>| 102 | companyname |


### cisco-stealthwatch-get-tag-hourly-traffic-report
***
Gets the hourly traffic summary of the byte count for a single host group (called tenant in the API).


#### Base Command

`cisco-stealthwatch-get-tag-hourly-traffic-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to get its host information. | Required | 
| tag_id | The ID of the tag for which to get its information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.TagHourlyTraffic.timestamp | str | Timestamp of the hourly traffic summary for a single host group \(called tag on the API\). | 
| CiscoStealthwatch.TagHourlyTraffic.inboundByteCount | str | Inbound byte count of the hourly traffic summary for a single host group \(called tag on the API\). | 
| CiscoStealthwatch.TagHourlyTraffic.outboundByteCount | str | Outbound byte count of the hourly traffic summary for a single host group \(called tag on the API\). | 
| CiscoStealthwatch.TagHourlyTraffic.withinByteCount | str | Within the byte count of the hourly traffic summary for a single host group \(called tag on the API\). | 
| CiscoStealthwatch.TagHourlyTraffic.tenant_id | str | The tenant ID of the hourly traffic summary for a single host group \(called tag on the API\). | 
| CiscoStealthwatch.TagHourlyTraffic.tag_id | str | The tag ID of the hourly traffic summary for a single host group \(called tag on the API\). | 


#### Command Example
```!cisco-stealthwatch-get-tag-hourly-traffic-report tenant_id=102 tag_id=1```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "TagHourlyTraffic": [
            {
                "inboundByteCount": 0,
                "outboundByteCount": 150258936,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T14:00:00Z",
                "withinByteCount": 1945701335
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 463352098,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T13:00:00Z",
                "withinByteCount": 3505279985
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 262327649,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T12:00:00Z",
                "withinByteCount": 3529956221
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 1122353436,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T11:00:00Z",
                "withinByteCount": 3457833934
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 984529611,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T10:00:00Z",
                "withinByteCount": 3386016372
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 733104221,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T09:00:00Z",
                "withinByteCount": 3412418846
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 1918126235,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T08:00:00Z",
                "withinByteCount": 3637012947
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 237026285,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T07:00:00Z",
                "withinByteCount": 3280803860
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 72918411,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T06:00:00Z",
                "withinByteCount": 3192625646
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 41484822,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T05:00:00Z",
                "withinByteCount": 3562885609
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 35827947,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T04:00:00Z",
                "withinByteCount": 3164436072
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 38951660,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T03:00:00Z",
                "withinByteCount": 3157242110
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 45113923,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T02:00:00Z",
                "withinByteCount": 3198141336
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 41711097,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T01:00:00Z",
                "withinByteCount": 3494995049
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 37973773,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-15T00:00:00Z",
                "withinByteCount": 3107836498
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 140825173,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T23:00:00Z",
                "withinByteCount": 3101452647
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 41105061,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T22:00:00Z",
                "withinByteCount": 3076750873
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 43776335,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T21:00:00Z",
                "withinByteCount": 3467001185
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 41122986,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T20:00:00Z",
                "withinByteCount": 3158945548
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 42376273,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T19:00:00Z",
                "withinByteCount": 3231715048
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 44179386,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T18:00:00Z",
                "withinByteCount": 3205740036
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 120232010,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T17:00:00Z",
                "withinByteCount": 3668568860
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 163284711,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T16:00:00Z",
                "withinByteCount": 3246202946
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 674875684,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T15:00:00Z",
                "withinByteCount": 3313179934
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 2049252448,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-03-14T14:00:00Z",
                "withinByteCount": 3410264173
            }
        ]
    }
}
```

#### Human Readable Output

>### Hourly Tag Traffic Report for tenant id 102 and tag id 1:
>|Timestamp|Inbound Byte Count|Outbound Byte Count|Within Byte Count|
>|---|---|---|---|
>| 2021-03-15T14:00:00Z | 0 | 150258936 | 1945701335 |
>| 2021-03-15T13:00:00Z | 0 | 463352098 | 3505279985 |
>| 2021-03-15T12:00:00Z | 0 | 262327649 | 3529956221 |
>| 2021-03-15T11:00:00Z | 0 | 1122353436 | 3457833934 |
>| 2021-03-15T10:00:00Z | 0 | 984529611 | 3386016372 |
>| 2021-03-15T09:00:00Z | 0 | 733104221 | 3412418846 |
>| 2021-03-15T08:00:00Z | 0 | 1918126235 | 3637012947 |
>| 2021-03-15T07:00:00Z | 0 | 237026285 | 3280803860 |
>| 2021-03-15T06:00:00Z | 0 | 72918411 | 3192625646 |
>| 2021-03-15T05:00:00Z | 0 | 41484822 | 3562885609 |
>| 2021-03-15T04:00:00Z | 0 | 35827947 | 3164436072 |
>| 2021-03-15T03:00:00Z | 0 | 38951660 | 3157242110 |
>| 2021-03-15T02:00:00Z | 0 | 45113923 | 3198141336 |
>| 2021-03-15T01:00:00Z | 0 | 41711097 | 3494995049 |
>| 2021-03-15T00:00:00Z | 0 | 37973773 | 3107836498 |
>| 2021-03-14T23:00:00Z | 0 | 140825173 | 3101452647 |
>| 2021-03-14T22:00:00Z | 0 | 41105061 | 3076750873 |
>| 2021-03-14T21:00:00Z | 0 | 43776335 | 3467001185 |
>| 2021-03-14T20:00:00Z | 0 | 41122986 | 3158945548 |
>| 2021-03-14T19:00:00Z | 0 | 42376273 | 3231715048 |
>| 2021-03-14T18:00:00Z | 0 | 44179386 | 3205740036 |
>| 2021-03-14T17:00:00Z | 0 | 120232010 | 3668568860 |
>| 2021-03-14T16:00:00Z | 0 | 163284711 | 3246202946 |
>| 2021-03-14T15:00:00Z | 0 | 674875684 | 3313179934 |
>| 2021-03-14T14:00:00Z | 0 | 2049252448 | 3410264173 |


### cisco-stealthwatch-get-top-alarming-tags
***
Gets the top alarming host groups (called tags on the API) for a specific domain (called tenant in the API).


#### Base Command

`cisco-stealthwatch-get-top-alarming-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to get its top alarming hosts. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.AlarmingTag.ipAddress | str | The IP address of the alarming tag. | 
| CiscoStealthwatch.AlarmingTag.hostGroupIds | str | The host group IDs of the alarming tag. | 
| CiscoStealthwatch.AlarmingTag.typeId | str | The type ID of the alarming tag. | 
| CiscoStealthwatch.AlarmingTag.severity | str | The severity of the alarming tag. | 
| CiscoStealthwatch.AlarmingTag.alwaysBadCount | str | The always bad count of the alarming tag. | 


#### Command Example
```!cisco-stealthwatch-get-top-alarming-tags tenant_id=102```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "AlarmingTag": [
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.3333333333333333,
                        "typeId": 1028
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0.058823529411764705,
                        "typeId": 1028
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    },
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 286
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            },
            {
                "hostGroupIds": [
                    1,
                    65534
                ],
                "ipAddress": "x.x.x.x",
                "sourceCategoryEvents": [],
                "sourceSecurityEvents": [
                    {
                        "alwaysBadCount": 0,
                        "severity": 0,
                        "typeId": 276
                    }
                ],
                "targetCategoryEvents": [],
                "targetSecurityEvents": [],
                "tenant_id": "102"
            }
        ]
    }
}
```

#### Human Readable Output

>### Top Alarming Tags for tenant id 102:
>|Host Group Ids|Ip Address|
>|---|---|
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |
>| 1,<br/>65534 | x.x.x.x |


### cisco-stealthwatch-list-security-events-initialize
***
Initializes the list of security events for a domain (called tenant on the API).


#### Base Command

`cisco-stealthwatch-list-security-events-initialize`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to initialize its list security events. | Required | 
| start_time | Start time. Format: YYYY-mm-ddTHH:MM:SSZ. Given only the start_time, the end_time will be set to the current time. | Optional | 
| end_time | End time. Format: YYYY-mm-ddTHH:MM:SSZ. | Optional | 
| time_range | An optional time range. For example: 3 months, 1 week, 1 day ago, etc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.SecurityEventStatus.id | str | The ID of the security event. | 
| CiscoStealthwatch.SecurityEventStatus.searchJobStatus | str | The status of the search job for the security event. | 
| CiscoStealthwatch.SecurityEventStatus.percentComplete | str | The percent of the security event that is completed. | 


#### Command Example
```!cisco-stealthwatch-list-security-events-initialize tenant_id=102 time_range="5 minute"```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "SecurityEventStatus": {
            "id": "604f7130e4b0bbedc8c77d92",
            "percentComplete": 0,
            "searchJobStatus": "IN_PROGRESS"
        }
    }
}
```

#### Human Readable Output

>### Security Events Initializing Information:
>|Id|Search Job Status|Percent Complete|
>|---|---|---|
>| 604f7130e4b0bbedc8c77d92 | IN_PROGRESS | 0 |


### cisco-stealthwatch-list-security-events-status
***
Lists the security events status.


#### Base Command

`cisco-stealthwatch-list-security-events-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to get its list of security events status. | Required | 
| search_id | The ID of the search from the initialize command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.SecurityEventStatus.id | str | The ID of the security event. | 
| CiscoStealthwatch.SecurityEventStatus.percentComplete | str | The percent of the security event that is completed. | 


#### Command Example
```!cisco-stealthwatch-list-security-events-status tenant_id=102 search_id=604f64e1e4b0bbedc8c77aa4```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "SecurityEventStatus": {
            "id": "604f64e1e4b0bbedc8c77aa4",
            "percentComplete": 100,
            "status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### Security Events Status Information:
>|Id|Percent Complete|
>|---|---|
>| 604f64e1e4b0bbedc8c77aa4 | 100.0 |


### cisco-stealthwatch-list-security-events-results
***
Lists the security events results. Use this command after the search job completes.


#### Base Command

`cisco-stealthwatch-list-security-events-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The ID of the tenant for which to retrieve its list security events results. | Required | 
| search_id | The ID of the search from the initialize command. | Required | 
| limit | The maximum number of security events. Default is 50. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.SecurityEventResults.id | str | The ID of the security event. | 
| CiscoStealthwatch.SecurityEventResults.domainId | str | The domain ID of the security event. | 
| CiscoStealthwatch.SecurityEventResults.deviceId | str | The device ID of the security event. | 
| CiscoStealthwatch.SecurityEventResults.securityEventType | str | The type of the security event. | 
| CiscoStealthwatch.SecurityEventResults.firstActiveTime | str | The first active time of the security event. | 
| CiscoStealthwatch.SecurityEventResults.lastActiveTime | str | The last active time of the security event. | 
| CiscoStealthwatch.SecurityEventResults.source | str | The source of the security event. | 
| CiscoStealthwatch.SecurityEventResults.target | str | The target of the security event. | 
| CiscoStealthwatch.SecurityEventResults.details | str | The details of the security event. | 
| CiscoStealthwatch.SecurityEventResults.hitCount | str | The hit count of the security event. | 


#### Command Example
```!cisco-stealthwatch-list-security-events-results tenant_id=102 limit=5 search_id=604f64e1e4b0bbedc8c77aa4```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "SecurityEventResults": [
            {
                "details": [
                    {
                        "key": "source_host@username",
                        "value": ""
                    },
                    {
                        "key": "source_host@policy_id",
                        "value": "1"
                    },
                    {
                        "key": "source_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "target_host@username",
                        "value": ""
                    },
                    {
                        "key": "target_host@policy_id",
                        "value": "0"
                    },
                    {
                        "key": "target_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "category_points@high-concern-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-target-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-recon-index",
                        "value": "162"
                    },
                    {
                        "key": "baseline@baseline",
                        "value": "0"
                    },
                    {
                        "key": "baseline@threshold",
                        "value": "0"
                    },
                    {
                        "key": "baseline@current_value",
                        "value": "0"
                    },
                    {
                        "key": "baseline@tolerance",
                        "value": "0"
                    },
                    {
                        "key": "flow@protocol",
                        "value": "17"
                    },
                    {
                        "key": "flow@service",
                        "value": "16"
                    },
                    {
                        "key": "flow@source_port",
                        "value": "0"
                    },
                    {
                        "key": "flow@target_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@event_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@flow_id",
                        "value": "0"
                    },
                    {
                        "key": "flow@source_is_server",
                        "value": "false"
                    },
                    {
                        "key": "targetIPAddress",
                        "value": "x.x.x.x"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-03-15T13:44:29.000+0000",
                "hitCount": 1,
                "id": 88195,
                "lastActiveTime": "2021-03-15T13:44:29.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "x.x.x.x",
                    "port": 0,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 65534,
                            "name": "Catch All"
                        }
                    ]
                },
                "target": {
                    "ipAddress": "x.x.x.x",
                    "port": 137,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 61627,
                            "name": "United States"
                        }
                    ]
                }
            },
            {
                "details": [
                    {
                        "key": "source_host@username",
                        "value": ""
                    },
                    {
                        "key": "source_host@policy_id",
                        "value": "1"
                    },
                    {
                        "key": "source_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "target_host@username",
                        "value": ""
                    },
                    {
                        "key": "target_host@policy_id",
                        "value": "0"
                    },
                    {
                        "key": "target_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "category_points@high-concern-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-target-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-recon-index",
                        "value": "162"
                    },
                    {
                        "key": "baseline@baseline",
                        "value": "0"
                    },
                    {
                        "key": "baseline@threshold",
                        "value": "0"
                    },
                    {
                        "key": "baseline@current_value",
                        "value": "0"
                    },
                    {
                        "key": "baseline@tolerance",
                        "value": "0"
                    },
                    {
                        "key": "flow@protocol",
                        "value": "17"
                    },
                    {
                        "key": "flow@service",
                        "value": "16"
                    },
                    {
                        "key": "flow@source_port",
                        "value": "0"
                    },
                    {
                        "key": "flow@target_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@event_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@flow_id",
                        "value": "0"
                    },
                    {
                        "key": "flow@source_is_server",
                        "value": "false"
                    },
                    {
                        "key": "targetIPAddress",
                        "value": "x.x.x.x"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-03-15T13:44:27.000+0000",
                "hitCount": 1,
                "id": 88194,
                "lastActiveTime": "2021-03-15T13:44:27.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "x.x.x.x",
                    "port": 0,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 65534,
                            "name": "Catch All"
                        }
                    ]
                },
                "target": {
                    "ipAddress": "x.x.x.x",
                    "port": 137,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 61627,
                            "name": "United States"
                        }
                    ]
                }
            },
            {
                "details": [
                    {
                        "key": "source_host@username",
                        "value": ""
                    },
                    {
                        "key": "source_host@policy_id",
                        "value": "1"
                    },
                    {
                        "key": "source_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "target_host@username",
                        "value": ""
                    },
                    {
                        "key": "target_host@policy_id",
                        "value": "0"
                    },
                    {
                        "key": "target_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "category_points@high-concern-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-target-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-recon-index",
                        "value": "162"
                    },
                    {
                        "key": "baseline@baseline",
                        "value": "0"
                    },
                    {
                        "key": "baseline@threshold",
                        "value": "0"
                    },
                    {
                        "key": "baseline@current_value",
                        "value": "0"
                    },
                    {
                        "key": "baseline@tolerance",
                        "value": "0"
                    },
                    {
                        "key": "flow@protocol",
                        "value": "17"
                    },
                    {
                        "key": "flow@service",
                        "value": "16"
                    },
                    {
                        "key": "flow@source_port",
                        "value": "0"
                    },
                    {
                        "key": "flow@target_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@event_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@flow_id",
                        "value": "0"
                    },
                    {
                        "key": "flow@source_is_server",
                        "value": "false"
                    },
                    {
                        "key": "targetIPAddress",
                        "value": "x.x.x.x"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-03-15T13:44:26.000+0000",
                "hitCount": 1,
                "id": 88193,
                "lastActiveTime": "2021-03-15T13:44:26.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "x.x.x.x",
                    "port": 0,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 65534,
                            "name": "Catch All"
                        }
                    ]
                },
                "target": {
                    "ipAddress": "x.x.x.x",
                    "port": 137,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 61627,
                            "name": "United States"
                        }
                    ]
                }
            },
            {
                "details": [
                    {
                        "key": "source_host@username",
                        "value": ""
                    },
                    {
                        "key": "source_host@policy_id",
                        "value": "1"
                    },
                    {
                        "key": "source_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "target_host@username",
                        "value": ""
                    },
                    {
                        "key": "target_host@policy_id",
                        "value": "0"
                    },
                    {
                        "key": "target_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "category_points@high-concern-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-target-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-recon-index",
                        "value": "162"
                    },
                    {
                        "key": "baseline@baseline",
                        "value": "0"
                    },
                    {
                        "key": "baseline@threshold",
                        "value": "0"
                    },
                    {
                        "key": "baseline@current_value",
                        "value": "0"
                    },
                    {
                        "key": "baseline@tolerance",
                        "value": "0"
                    },
                    {
                        "key": "flow@protocol",
                        "value": "17"
                    },
                    {
                        "key": "flow@service",
                        "value": "16"
                    },
                    {
                        "key": "flow@source_port",
                        "value": "0"
                    },
                    {
                        "key": "flow@target_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@event_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@flow_id",
                        "value": "0"
                    },
                    {
                        "key": "flow@source_is_server",
                        "value": "false"
                    },
                    {
                        "key": "targetIPAddress",
                        "value": "x.x.x.x"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-03-15T13:44:25.000+0000",
                "hitCount": 1,
                "id": 88192,
                "lastActiveTime": "2021-03-15T13:44:25.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "x.x.x.x",
                    "port": 0,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 65534,
                            "name": "Catch All"
                        }
                    ]
                },
                "target": {
                    "ipAddress": "x.x.x.x",
                    "port": 137,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 61627,
                            "name": "United States"
                        }
                    ]
                }
            },
            {
                "details": [
                    {
                        "key": "source_host@username",
                        "value": ""
                    },
                    {
                        "key": "source_host@policy_id",
                        "value": "1"
                    },
                    {
                        "key": "source_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "target_host@username",
                        "value": ""
                    },
                    {
                        "key": "target_host@policy_id",
                        "value": "0"
                    },
                    {
                        "key": "target_host@mac_address",
                        "value": ""
                    },
                    {
                        "key": "category_points@high-concern-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-target-index",
                        "value": "162"
                    },
                    {
                        "key": "category_points@high-recon-index",
                        "value": "162"
                    },
                    {
                        "key": "baseline@baseline",
                        "value": "0"
                    },
                    {
                        "key": "baseline@threshold",
                        "value": "0"
                    },
                    {
                        "key": "baseline@current_value",
                        "value": "0"
                    },
                    {
                        "key": "baseline@tolerance",
                        "value": "0"
                    },
                    {
                        "key": "flow@protocol",
                        "value": "17"
                    },
                    {
                        "key": "flow@service",
                        "value": "16"
                    },
                    {
                        "key": "flow@source_port",
                        "value": "0"
                    },
                    {
                        "key": "flow@target_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@event_port",
                        "value": "137"
                    },
                    {
                        "key": "flow@flow_id",
                        "value": "0"
                    },
                    {
                        "key": "flow@source_is_server",
                        "value": "false"
                    },
                    {
                        "key": "targetIPAddress",
                        "value": "x.x.x.x"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-03-15T13:44:25.000+0000",
                "hitCount": 1,
                "id": 88191,
                "lastActiveTime": "2021-03-15T13:44:25.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "x.x.x.x",
                    "port": 0,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 65534,
                            "name": "Catch All"
                        }
                    ]
                },
                "target": {
                    "ipAddress": "x.x.x.x",
                    "port": 137,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 61627,
                            "name": "United States"
                        }
                    ]
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Showing 5 Security Events:
>|Id|Domain Id|Device Id|Security Event Type|First Active Time|Last Active Time|Source|Target|Details|Hit Count|
>|---|---|---|---|---|---|---|---|---|---|
>| 88195 | 102 | 121 | 310 | 2021-03-15T13:44:29.000+0000 | 2021-03-15T13:44:29.000+0000 | ipAddress: x.x.x.x<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: x.x.x.x<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': 'x.x.x.x'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 88194 | 102 | 121 | 310 | 2021-03-15T13:44:27.000+0000 | 2021-03-15T13:44:27.000+0000 | ipAddress: x.x.x.x<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: x.x.x.x<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': 'x.x.x.x'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 88193 | 102 | 121 | 310 | 2021-03-15T13:44:26.000+0000 | 2021-03-15T13:44:26.000+0000 | ipAddress: x.x.x.x<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: x.x.x.x<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': 'x.x.x.x'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 88192 | 102 | 121 | 310 | 2021-03-15T13:44:25.000+0000 | 2021-03-15T13:44:25.000+0000 | ipAddress: x.x.x.x<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: x.x.x.x<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': 'x.x.x.x'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 88191 | 102 | 121 | 310 | 2021-03-15T13:44:25.000+0000 | 2021-03-15T13:44:25.000+0000 | ipAddress: x.x.x.x<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: x.x.x.x<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': 'x.x.x.x'},<br/>{'key': 'points', 'value': '162'} | 1 |
