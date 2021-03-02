Scalable visibility and security analytics
This integration was integrated and tested with version 1.0.0 of Cisco Stealthwatch
## Configure Cisco Stealthwatch on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Stealthwatch.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Server URL for Cisco Stealthwatch console. e.g: https://ip:port/ | True |
    | User Credentials |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cisco-stealthwatch-query-flows-initialize
***
Initialize flow search based on parameters. Please provide start time, time range, or start time and end time.


#### Base Command

`cisco-stealthwatch-query-flows-initialize`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant we want to initialize its flow search. | Required | 
| start_time | Start time. format: YYYY-mm-ddTHH:MM:SSZ.Given only start_time, end_time will be set to the current time. | Optional | 
| end_time | End time. format: YYYY-mm-ddTHH:MM:SSZ. | Optional | 
| time_range | An optional time range. i.e: 3 months, 1 week, 1 day ago, etc. | Optional | 
| limit | Record limit. Default is 20. | Optional | 
| ip_addresses | Filter based on IP Address. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.FlowStatus.id | str | The id of the flow | 
| CiscoStealthwatch.FlowStatus.searchJobStatus | str | The searchJobStatus of the flow | 
| CiscoStealthwatch.FlowStatus.percentComplete | str | The percentComplete of the flow | 


#### Command Example
```!cisco-stealthwatch-query-flows-initialize tenant_id=102 limit=3 time_range="1 week"```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "FlowStatus": {
            "domainId": "102",
            "id": "603b47e0e4b0d6d2a2037b37",
            "percentComplete": 100,
            "status": "IN_PROGRESS"
        }
    }
}
```

#### Human Readable Output

>### Query Flows Initializing Information:
>|id|status|percentComplete|
>|---|---|---|
>| 603b47e0e4b0d6d2a2037b37 | IN_PROGRESS | 100.0 |


### cisco-stealthwatch-query-flows-status
***
Flow search check status


#### Base Command

`cisco-stealthwatch-query-flows-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant we want to check its flow search status. | Required | 
| search_id | The id of the search from the initialize command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.FlowStatus.id | str | The id of the flow | 
| CiscoStealthwatch.FlowStatus.percentComplete | str | The percentComplete of the flow | 


#### Command Example
```!cisco-stealthwatch-query-flows-status tenant_id=102 search_id=603b4667e4b0d6d2a2037973```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "FlowStatus": {
            "domainId": "102",
            "id": "603b4667e4b0d6d2a2037973",
            "percentComplete": 100,
            "status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### Query Flows Status Information:
>|id|percentComplete|
>|---|---|
>| 603b4667e4b0d6d2a2037973 | 100.0 |


### cisco-stealthwatch-query-flows-results
***
Flow search results, use this command after the search job is over.


#### Base Command

`cisco-stealthwatch-query-flows-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant we want to retrieve its flow search results. | Required | 
| search_id | The id of the search from the initialize command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.FlowResults.id | str | The id of the flow | 
| CiscoStealthwatch.FlowResults.tenantId | str | The tenant id of the flow | 
| CiscoStealthwatch.FlowResults.flowCollectorId | str | The collector id of the flow | 
| CiscoStealthwatch.FlowResults.protocol | str | The protocol of the flow | 
| CiscoStealthwatch.FlowResults.serviceId | str | The service id of the flow | 
| CiscoStealthwatch.FlowResults.statistics | str | The statistics of the flow | 
| CiscoStealthwatch.FlowResults.peer | str | The peer of the flow | 
| CiscoStealthwatch.FlowResults.subject | str | The subject of the flow | 


#### Command Example
```!cisco-stealthwatch-query-flows-results tenant_id=102 search_id=603b4667e4b0d6d2a2037973```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "FlowResults": [
            {
                "applicationId": 169,
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
                "id": 1837284,
                "mplsLabel": -1,
                "peer": {
                    "byteRate": 0,
                    "bytes": 0,
                    "countryCode": "US",
                    "finPackets": 0,
                    "hostGroupIds": [
                        61627
                    ],
                    "ipAddress": "157.240.1.54",
                    "natPort": -1,
                    "orientation": "server",
                    "packetRate": 0,
                    "packets": 0,
                    "percentBytes": 0,
                    "portProtocol": {
                        "port": 5222,
                        "protocol": "TCP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "protocol": "TCP",
                "serviceId": 128,
                "statistics": {
                    "activeDuration": 200000,
                    "byteCount": 1814323,
                    "byteRate": 23562.6363636364,
                    "firstActiveTime": "2021-02-28T07:23:39.000+0000",
                    "flowTimeSinceStart": 241376,
                    "lastActiveTime": "2021-02-28T07:26:59.000+0000",
                    "numCombinedFlowRecords": 1,
                    "packetCount": 1340,
                    "packetRate": 17.4025974025974,
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
                    "tcpRetransmissionsRatio": -0.07462686567164178
                },
                "subject": {
                    "byteRate": 23562.6363636364,
                    "bytes": 1814323,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "192.168.91.2",
                    "natAddress": "192.117.142.58",
                    "natHostName": "mail.team3.co.il",
                    "natPort": 7513,
                    "orientation": "client",
                    "packetRate": 17.4025974025974,
                    "packets": 1340,
                    "percentBytes": 100,
                    "portProtocol": {
                        "port": 37310,
                        "protocol": "TCP",
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
                "applicationId": 190,
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
                "id": 592310,
                "mplsLabel": -1,
                "peer": {
                    "byteRate": 40701.7662337662,
                    "bytes": 3134036,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        38,
                        27
                    ],
                    "ipAddress": "192.168.10.1",
                    "natPort": -1,
                    "orientation": "server",
                    "packetRate": 678.909090909091,
                    "packets": 52276,
                    "percentBytes": 50,
                    "portProtocol": {
                        "port": 53,
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
                "serviceId": 1,
                "statistics": {
                    "activeDuration": 1456213000,
                    "byteCount": 6268072,
                    "byteRate": 81403.5324675325,
                    "firstActiveTime": "2021-02-11T10:56:46.000+0000",
                    "flowTimeSinceStart": 241376,
                    "lastActiveTime": "2021-02-28T07:26:59.000+0000",
                    "numCombinedFlowRecords": 2,
                    "packetCount": 104552,
                    "packetRate": 1357.81818181818,
                    "roundTripTime": 0,
                    "rttAverage": -1,
                    "rttMaximum": -1,
                    "rttMinimum": -1,
                    "serverResponseTime": 0,
                    "srtAverage": -1,
                    "srtMaximum": -1,
                    "srtMinimum": -1,
                    "subjectPeerRatio": 50,
                    "tcpConnections": 0,
                    "tcpRetransmissions": -1,
                    "tcpRetransmissionsRatio": -0.0009564618563011707
                },
                "subject": {
                    "byteRate": 40701.7662337662,
                    "bytes": 3134036,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "192.168.30.19",
                    "natPort": -1,
                    "orientation": "client",
                    "packetRate": 678.909090909091,
                    "packets": 52276,
                    "percentBytes": 50,
                    "portProtocol": {
                        "port": 35219,
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
                "id": 1837567,
                "mplsLabel": -1,
                "peer": {
                    "byteRate": 48693.6470588235,
                    "bytes": 827792,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        65534
                    ],
                    "ipAddress": "192.168.30.2",
                    "natPort": -1,
                    "orientation": "server",
                    "packetRate": 45.1764705882353,
                    "packets": 768,
                    "percentBytes": 50,
                    "portProtocol": {
                        "port": 514,
                        "protocol": "TCP",
                        "serviceId": 0
                    },
                    "rstPackets": 0,
                    "synAckPackets": 0,
                    "synPackets": 0,
                    "tlsVersion": "NONE",
                    "trustSecId": -1
                },
                "protocol": "TCP",
                "serviceId": 543,
                "statistics": {
                    "activeDuration": 326000,
                    "byteCount": 1655584,
                    "byteRate": 97387.2941176471,
                    "firstActiveTime": "2021-02-28T07:20:33.000+0000",
                    "flowTimeSinceStart": 241376,
                    "lastActiveTime": "2021-02-28T07:25:59.000+0000",
                    "numCombinedFlowRecords": 2,
                    "packetCount": 1536,
                    "packetRate": 90.3529411764706,
                    "roundTripTime": 0,
                    "rttAverage": -1,
                    "rttMaximum": -1,
                    "rttMinimum": -1,
                    "serverResponseTime": 0,
                    "srtAverage": -1,
                    "srtMaximum": -1,
                    "srtMinimum": -1,
                    "subjectPeerRatio": 50,
                    "tcpConnections": 0,
                    "tcpRetransmissions": -1,
                    "tcpRetransmissionsRatio": -0.06510416666666667
                },
                "subject": {
                    "byteRate": 48693.6470588235,
                    "bytes": 827792,
                    "countryCode": "XR",
                    "finPackets": 0,
                    "hostGroupIds": [
                        38,
                        27
                    ],
                    "ipAddress": "192.168.10.1",
                    "natPort": -1,
                    "orientation": "client",
                    "packetRate": 45.1764705882353,
                    "packets": 768,
                    "percentBytes": 50,
                    "portProtocol": {
                        "port": 54793,
                        "protocol": "TCP",
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
>|id|tenantId|flowCollectorId|protocol|serviceId|statistics|peer|subject|
>|---|---|---|---|---|---|---|---|
>| 1837284 | 102 | 121 | TCP | 128 | activeDuration: 200000<br/>numCombinedFlowRecords: 1<br/>firstActiveTime: 2021-02-28T07:23:39.000+0000<br/>lastActiveTime: 2021-02-28T07:26:59.000+0000<br/>tcpRetransmissions: -1<br/>byteCount: 1814323<br/>packetCount: 1340<br/>byteRate: 23562.6363636364<br/>packetRate: 17.4025974025974<br/>tcpConnections: 0<br/>roundTripTime: 0<br/>serverResponseTime: 0<br/>subjectPeerRatio: 100.0<br/>rttAverage: -1<br/>rttMaximum: -1<br/>rttMinimum: -1<br/>srtAverage: -1<br/>srtMaximum: -1<br/>srtMinimum: -1<br/>flowTimeSinceStart: 241376<br/>tcpRetransmissionsRatio: -0.07462686567164178 | hostGroupIds: 61627<br/>countryCode: US<br/>ipAddress: 157.240.1.54<br/>natPort: -1<br/>portProtocol: {"port": 5222, "protocol": "TCP", "serviceId": 0}<br/>percentBytes: 0.0<br/>bytes: 0<br/>packets: 0<br/>byteRate: 0.0<br/>packetRate: 0.0<br/>orientation: server<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: 192.168.91.2<br/>natAddress: 192.117.142.58<br/>natHostName: mail.team3.co.il<br/>natPort: 7513<br/>portProtocol: {"port": 37310, "protocol": "TCP", "serviceId": 0}<br/>percentBytes: 100.0<br/>bytes: 1814323<br/>packets: 1340<br/>byteRate: 23562.6363636364<br/>packetRate: 17.4025974025974<br/>orientation: client<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 |
>| 592310 | 102 | 121 | UDP | 1 | activeDuration: 1456213000<br/>numCombinedFlowRecords: 2<br/>firstActiveTime: 2021-02-11T10:56:46.000+0000<br/>lastActiveTime: 2021-02-28T07:26:59.000+0000<br/>tcpRetransmissions: -1<br/>byteCount: 6268072<br/>packetCount: 104552<br/>byteRate: 81403.5324675325<br/>packetRate: 1357.81818181818<br/>tcpConnections: 0<br/>roundTripTime: 0<br/>serverResponseTime: 0<br/>subjectPeerRatio: 50.0<br/>rttAverage: -1<br/>rttMaximum: -1<br/>rttMinimum: -1<br/>srtAverage: -1<br/>srtMaximum: -1<br/>srtMinimum: -1<br/>flowTimeSinceStart: 241376<br/>tcpRetransmissionsRatio: -0.0009564618563011707 | hostGroupIds: 38,<br/>27<br/>countryCode: XR<br/>ipAddress: 192.168.10.1<br/>natPort: -1<br/>portProtocol: {"port": 53, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 50.0<br/>bytes: 3134036<br/>packets: 52276<br/>byteRate: 40701.7662337662<br/>packetRate: 678.909090909091<br/>orientation: server<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: 192.168.30.19<br/>natPort: -1<br/>portProtocol: {"port": 35219, "protocol": "UDP", "serviceId": 0}<br/>percentBytes: 50.0<br/>bytes: 3134036<br/>packets: 52276<br/>byteRate: 40701.7662337662<br/>packetRate: 678.909090909091<br/>orientation: client<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 |
>| 1837567 | 102 | 121 | TCP | 543 | activeDuration: 326000<br/>numCombinedFlowRecords: 2<br/>firstActiveTime: 2021-02-28T07:20:33.000+0000<br/>lastActiveTime: 2021-02-28T07:25:59.000+0000<br/>tcpRetransmissions: -1<br/>byteCount: 1655584<br/>packetCount: 1536<br/>byteRate: 97387.2941176471<br/>packetRate: 90.3529411764706<br/>tcpConnections: 0<br/>roundTripTime: 0<br/>serverResponseTime: 0<br/>subjectPeerRatio: 50.0<br/>rttAverage: -1<br/>rttMaximum: -1<br/>rttMinimum: -1<br/>srtAverage: -1<br/>srtMaximum: -1<br/>srtMinimum: -1<br/>flowTimeSinceStart: 241376<br/>tcpRetransmissionsRatio: -0.06510416666666667 | hostGroupIds: 65534<br/>countryCode: XR<br/>ipAddress: 192.168.30.2<br/>natPort: -1<br/>portProtocol: {"port": 514, "protocol": "TCP", "serviceId": 0}<br/>percentBytes: 50.0<br/>bytes: 827792<br/>packets: 768<br/>byteRate: 48693.6470588235<br/>packetRate: 45.1764705882353<br/>orientation: server<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 | hostGroupIds: 38,<br/>27<br/>countryCode: XR<br/>ipAddress: 192.168.10.1<br/>natPort: -1<br/>portProtocol: {"port": 54793, "protocol": "TCP", "serviceId": 0}<br/>percentBytes: 50.0<br/>bytes: 827792<br/>packets: 768<br/>byteRate: 48693.6470588235<br/>packetRate: 45.1764705882353<br/>orientation: client<br/>finPackets: 0<br/>rstPackets: 0<br/>synPackets: 0<br/>synAckPackets: 0<br/>tlsVersion: NONE<br/>trustSecId: -1 |


### cisco-stealthwatch-list-tags
***
List host groups (called Tags on the API)


#### Base Command

`cisco-stealthwatch-list-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant which we want to get its tags. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.Tag.id | str | The id of the tag | 
| CiscoStealthwatch.Tag.displayName | str | The displayName of the tag | 


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

>### Tags (for tenant_id: 102):
>|displayName|id|
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
Get a single host group (called Tag on the API)


#### Base Command

`cisco-stealthwatch-get-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant which we want to get its tag. | Required | 
| tag_id | The tag we want to get more information about. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.Tag.id | str | The name of the tag | 
| CiscoStealthwatch.Tag.name | str | The id of the tag | 
| CiscoStealthwatch.Tag.location | str | The location of the tag | 
| CiscoStealthwatch.Tag.domainId | str | The domainId of the tag | 


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

>### Tag (tenant_id: 102, tag_id: 1):
>|id|name|location|domainId|
>|---|---|---|---|
>| 1 | Inside Hosts | INSIDE | 102 |


### cisco-stealthwatch-list-tenants
***
List all domains or Get a single domain (called Tenant(s) on the API)


#### Base Command

`cisco-stealthwatch-list-tenants`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant which we want to retrieve information about. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.Tenant.id | str | The id of the tenant | 
| CiscoStealthwatch.Tenant.displayName | str | The displayName of the tenant | 


#### Command Example
```!cisco-stealthwatch-list-tenants```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "Tenant": {
            "displayName": "qmasters",
            "id": 102
        }
    }
}
```

#### Human Readable Output

>### Tenants:
>|id|displayName|
>|---|---|
>| 102 | qmasters |


### cisco-stealthwatch-get-tag-hourly-traffic-report
***
Hourly traffic summary of ByteCount for a single host group (called Tenent on the API)


#### Base Command

`cisco-stealthwatch-get-tag-hourly-traffic-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant which we want to get its host information. | Required | 
| tag_id | The tag we want to get its information . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.TagHourlyTraffic.timestamp | str | The timestamp of the TagHourlyTraffic | 
| CiscoStealthwatch.TagHourlyTraffic.inboundByteCount | str | The inboundByteCount of the TagHourlyTraffic | 
| CiscoStealthwatch.TagHourlyTraffic.outboundByteCount | str | The outboundByteCount of the TagHourlyTraffic | 
| CiscoStealthwatch.TagHourlyTraffic.withinByteCount | str | The withinByteCount of the TagHourlyTraffic | 
| CiscoStealthwatch.TagHourlyTraffic.tenant_id | str | The tenant_idof the TagHourlyTraffic | 
| CiscoStealthwatch.TagHourlyTraffic.tag_id | str | The tag_id of the TagHourlyTraffic | 


#### Command Example
```!cisco-stealthwatch-get-tag-hourly-traffic-report tenant_id=102 tag_id=1```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "TagHourlyTraffic": [
            {
                "inboundByteCount": 0,
                "outboundByteCount": 291048598,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T07:00:00Z",
                "withinByteCount": 1567052996
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 203032760,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T06:00:00Z",
                "withinByteCount": 3436018534
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 47538899,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T05:00:00Z",
                "withinByteCount": 3603501448
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 49114086,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T04:00:00Z",
                "withinByteCount": 3406898697
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 45791660,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T03:00:00Z",
                "withinByteCount": 3270417523
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 47745710,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T02:00:00Z",
                "withinByteCount": 3487003235
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 46587449,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T01:00:00Z",
                "withinByteCount": 3647554497
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 47360587,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-28T00:00:00Z",
                "withinByteCount": 3407208147
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 47293648,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T23:00:00Z",
                "withinByteCount": 3351739160
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 151106736,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T22:00:00Z",
                "withinByteCount": 3325365484
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 60103310,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T21:00:00Z",
                "withinByteCount": 3871282272
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 53440498,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T20:00:00Z",
                "withinByteCount": 3606645372
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 50552248,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T19:00:00Z",
                "withinByteCount": 3395068198
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 54788099,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T18:00:00Z",
                "withinByteCount": 3443621209
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 51259347,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T17:00:00Z",
                "withinByteCount": 3699318523
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 51617923,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T16:00:00Z",
                "withinByteCount": 3453042484
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 56498548,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T15:00:00Z",
                "withinByteCount": 3396818922
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 56778747,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T14:00:00Z",
                "withinByteCount": 3489771709
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 62141472,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T13:00:00Z",
                "withinByteCount": 3750390108
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 64282723,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T12:00:00Z",
                "withinByteCount": 3661873084
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 65242422,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T11:00:00Z",
                "withinByteCount": 3483765523
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 72138185,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T10:00:00Z",
                "withinByteCount": 3455481561
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 47761348,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T09:00:00Z",
                "withinByteCount": 3732010759
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 49763585,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T08:00:00Z",
                "withinByteCount": 3488886111
            },
            {
                "inboundByteCount": 0,
                "outboundByteCount": 63774449,
                "tag_id": "1",
                "tenant_id": "102",
                "timestamp": "2021-02-27T07:00:00Z",
                "withinByteCount": 3476653122
            }
        ]
    }
}
```

#### Human Readable Output

>### Hourly Tag Traffic Report (tenant_id: 102, tag_id: 1):
>|timestamp|inboundByteCount|outboundByteCount|withinByteCount|
>|---|---|---|---|
>| 2021-02-28T07:00:00Z | 0 | 291048598 | 1567052996 |
>| 2021-02-28T06:00:00Z | 0 | 203032760 | 3436018534 |
>| 2021-02-28T05:00:00Z | 0 | 47538899 | 3603501448 |
>| 2021-02-28T04:00:00Z | 0 | 49114086 | 3406898697 |
>| 2021-02-28T03:00:00Z | 0 | 45791660 | 3270417523 |
>| 2021-02-28T02:00:00Z | 0 | 47745710 | 3487003235 |
>| 2021-02-28T01:00:00Z | 0 | 46587449 | 3647554497 |
>| 2021-02-28T00:00:00Z | 0 | 47360587 | 3407208147 |
>| 2021-02-27T23:00:00Z | 0 | 47293648 | 3351739160 |
>| 2021-02-27T22:00:00Z | 0 | 151106736 | 3325365484 |
>| 2021-02-27T21:00:00Z | 0 | 60103310 | 3871282272 |
>| 2021-02-27T20:00:00Z | 0 | 53440498 | 3606645372 |
>| 2021-02-27T19:00:00Z | 0 | 50552248 | 3395068198 |
>| 2021-02-27T18:00:00Z | 0 | 54788099 | 3443621209 |
>| 2021-02-27T17:00:00Z | 0 | 51259347 | 3699318523 |
>| 2021-02-27T16:00:00Z | 0 | 51617923 | 3453042484 |
>| 2021-02-27T15:00:00Z | 0 | 56498548 | 3396818922 |
>| 2021-02-27T14:00:00Z | 0 | 56778747 | 3489771709 |
>| 2021-02-27T13:00:00Z | 0 | 62141472 | 3750390108 |
>| 2021-02-27T12:00:00Z | 0 | 64282723 | 3661873084 |
>| 2021-02-27T11:00:00Z | 0 | 65242422 | 3483765523 |
>| 2021-02-27T10:00:00Z | 0 | 72138185 | 3455481561 |
>| 2021-02-27T09:00:00Z | 0 | 47761348 | 3732010759 |
>| 2021-02-27T08:00:00Z | 0 | 49763585 | 3488886111 |
>| 2021-02-27T07:00:00Z | 0 | 63774449 | 3476653122 |


### cisco-stealthwatch-get-top-alarming-tags
***
Get top alarming host groups (called Tags on the API) for a specific domain (called Tenent on the API)


#### Base Command

`cisco-stealthwatch-get-top-alarming-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant which we want to get its top alarming hosts. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.AlarmingTag.ipAddress | str | The IP address of the AlarmingTag | 
| CiscoStealthwatch.AlarmingTag.hostGroupIds | str | The hostGroupIds of the AlarmingTag | 
| CiscoStealthwatch.AlarmingTag.typeId | str | The typeId of the AlarmingTag | 
| CiscoStealthwatch.AlarmingTag.severity | str | The severity of the AlarmingTag | 
| CiscoStealthwatch.AlarmingTag.alwaysBadCount | str | The alwaysBadCount of the AlarmingTag | 


#### Command Example
```!cisco-stealthwatch-get-top-alarming-tags tenant_id=102```

#### Human Readable Output

>### Top Alarming Tags (tenant_id: 102):
>**No entries.**


### cisco-stealthwatch-list-security-events-initialize
***
Initialize listing security events for a domain (called Tenant on the API)


#### Base Command

`cisco-stealthwatch-list-security-events-initialize`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant we want to initialize its list security events . | Required | 
| start_time | Start time. format: YYYY-mm-ddTHH:MM:SSZ.Given only start_time, end_time will be set to the current time. | Optional | 
| end_time | End time. format: YYYY-mm-ddTHH:MM:SSZ. | Optional | 
| time_range | An optional time range. i.e: 3 months, 1 week, 1 day ago, etc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.SecurityEventStatus.id | str | The id of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventStatus.searchJobStatus | str | The searchJobStatusof the SecurityEvent | 
| CiscoStealthwatch.SecurityEventStatus.percentComplete  | str | The percentComplete of the SecurityEvent | 


#### Command Example
```!cisco-stealthwatch-list-security-events-initialize tenant_id=102 time_range="1 minute"```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "SecurityEventStatus": {
            "id": "603b47f2e4b0d6d2a2037b3c",
            "percentComplete": 0,
            "searchJobStatus": "IN_PROGRESS"
        }
    }
}
```

#### Human Readable Output

>### Security Events Initializing Information:
>|id|searchJobStatus|percentComplete|
>|---|---|---|
>| 603b47f2e4b0d6d2a2037b3c | IN_PROGRESS | 0 |


### cisco-stealthwatch-list-security-events-status
***
List security events status


#### Base Command

`cisco-stealthwatch-list-security-events-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant we want to get its list security events status. | Required | 
| search_id | The id of the search from the initialize command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.SecurityEventStatus.id | str | The id of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventStatus.percentComplete | str | The percentCompleteof the SecurityEvent | 


#### Command Example
```!cisco-stealthwatch-list-security-events-status tenant_id=102 search_id=603b4696e4b0d6d2a203797a```

#### Context Example
```json
{
    "CiscoStealthwatch": {
        "SecurityEventStatus": {
            "id": "603b4696e4b0d6d2a203797a",
            "percentComplete": 100,
            "status": "COMPLETED"
        }
    }
}
```

#### Human Readable Output

>### Security Events Status Information:
>|id|percentComplete|
>|---|---|
>| 603b4696e4b0d6d2a203797a | 100.0 |


### cisco-stealthwatch-list-security-events-results
***
List security events results, use this command after the search job is over.


#### Base Command

`cisco-stealthwatch-list-security-events-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The tenant we want to retrieve its list security events results. | Required | 
| search_id | The id of the search from the initialize command. | Required | 
| limit | security events limit. Default is 50. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoStealthwatch.SecurityEventResults.id | str | The id of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.domainId | str | The domainId of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.deviceId | str | The deviceId of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.securityEventType | str | The securityEventType of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.firstActiveTime | str | The firstActiveTime of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.lastActiveTime | str | The lastActiveTime of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.source | str | The source of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.target | str | The target of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.details | str | The details of the SecurityEvent | 
| CiscoStealthwatch.SecurityEventResults.hitCount | str | The hitCount of the SecurityEvent | 


#### Command Example
```!cisco-stealthwatch-list-security-events-results tenant_id=102 limit=5 search_id=603b4696e4b0d6d2a203797a```

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
                        "value": "40.101.121.34"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-02-28T06:32:21.000+0000",
                "hitCount": 1,
                "id": 52573,
                "lastActiveTime": "2021-02-28T06:32:21.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "192.168.91.7",
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
                    "ipAddress": "40.101.121.34",
                    "port": 137,
                    "protocol": "udp",
                    "tags": [
                        {
                            "id": 61319,
                            "name": "Netherlands"
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
                        "value": "52.97.201.114"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-02-28T06:32:46.000+0000",
                "hitCount": 1,
                "id": 52574,
                "lastActiveTime": "2021-02-28T06:32:46.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "192.168.91.7",
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
                    "ipAddress": "52.97.201.114",
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
                        "value": "52.114.159.33"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-02-28T06:32:54.000+0000",
                "hitCount": 1,
                "id": 52575,
                "lastActiveTime": "2021-02-28T06:32:54.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "192.168.91.7",
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
                    "ipAddress": "52.114.159.33",
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
                        "value": "52.109.12.19"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-02-28T06:33:07.000+0000",
                "hitCount": 1,
                "id": 52576,
                "lastActiveTime": "2021-02-28T06:33:07.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "192.168.91.7",
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
                    "ipAddress": "52.109.12.19",
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
                        "value": "40.77.18.167"
                    },
                    {
                        "key": "points",
                        "value": "162"
                    }
                ],
                "deviceId": 121,
                "domainId": 102,
                "firstActiveTime": "2021-02-28T06:33:51.000+0000",
                "hitCount": 1,
                "id": 52577,
                "lastActiveTime": "2021-02-28T06:33:51.000+0000",
                "securityEventType": 310,
                "source": {
                    "ipAddress": "192.168.91.7",
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
                    "ipAddress": "40.77.18.167",
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
>|id|domainId|deviceId|securityEventType|firstActiveTime|lastActiveTime|source|target|details|hitCount|
>|---|---|---|---|---|---|---|---|---|---|
>| 52573 | 102 | 121 | 310 | 2021-02-28T06:32:21.000+0000 | 2021-02-28T06:32:21.000+0000 | ipAddress: 192.168.91.7<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: 40.101.121.34<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'Netherlands', 'id': 61319} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': '40.101.121.34'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 52574 | 102 | 121 | 310 | 2021-02-28T06:32:46.000+0000 | 2021-02-28T06:32:46.000+0000 | ipAddress: 192.168.91.7<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: 52.97.201.114<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': '52.97.201.114'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 52575 | 102 | 121 | 310 | 2021-02-28T06:32:54.000+0000 | 2021-02-28T06:32:54.000+0000 | ipAddress: 192.168.91.7<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: 52.114.159.33<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': '52.114.159.33'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 52576 | 102 | 121 | 310 | 2021-02-28T06:33:07.000+0000 | 2021-02-28T06:33:07.000+0000 | ipAddress: 192.168.91.7<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: 52.109.12.19<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': '52.109.12.19'},<br/>{'key': 'points', 'value': '162'} | 1 |
>| 52577 | 102 | 121 | 310 | 2021-02-28T06:33:51.000+0000 | 2021-02-28T06:33:51.000+0000 | ipAddress: 192.168.91.7<br/>port: 0<br/>protocol: udp<br/>tags: {'name': 'Catch All', 'id': 65534} | ipAddress: 40.77.18.167<br/>port: 137<br/>protocol: udp<br/>tags: {'name': 'United States', 'id': 61627} | {'key': 'source_host@username', 'value': ''},<br/>{'key': 'source_host@policy_id', 'value': '1'},<br/>{'key': 'source_host@mac_address', 'value': ''},<br/>{'key': 'target_host@username', 'value': ''},<br/>{'key': 'target_host@policy_id', 'value': '0'},<br/>{'key': 'target_host@mac_address', 'value': ''},<br/>{'key': 'category_points@high-concern-index', 'value': '162'},<br/>{'key': 'category_points@high-target-index', 'value': '162'},<br/>{'key': 'category_points@high-recon-index', 'value': '162'},<br/>{'key': 'baseline@baseline', 'value': '0'},<br/>{'key': 'baseline@threshold', 'value': '0'},<br/>{'key': 'baseline@current_value', 'value': '0'},<br/>{'key': 'baseline@tolerance', 'value': '0'},<br/>{'key': 'flow@protocol', 'value': '17'},<br/>{'key': 'flow@service', 'value': '16'},<br/>{'key': 'flow@source_port', 'value': '0'},<br/>{'key': 'flow@target_port', 'value': '137'},<br/>{'key': 'flow@event_port', 'value': '137'},<br/>{'key': 'flow@flow_id', 'value': '0'},<br/>{'key': 'flow@source_is_server', 'value': 'false'},<br/>{'key': 'targetIPAddress', 'value': '40.77.18.167'},<br/>{'key': 'points', 'value': '162'} | 1 |

