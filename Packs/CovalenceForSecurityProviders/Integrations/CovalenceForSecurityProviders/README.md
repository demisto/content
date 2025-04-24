Triggers by any alert from endpoint, cloud, and network security monitoring, with mitigation steps where applicable. Query Covalence for more detail.
This integration was integrated and tested with version 3.0 of Covalence For Security Providers

## Configure Covalence For Security Providers in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Broker | Set to true if connections are made through a broker | False |
| Host | Covalence's host \(IP or domain\) or broker's socket \(ip:port\) if using broker | True |
| Credentials |  | True |
| Password |  | True |
| Verify SSL | If set to false, will trust any certificate \(not secure\) | False |
| Timeout | Timeout in seconds | False |
| First run time range | When fetching incidents for the first time, this parameter specifies in days how far the integration looks for incidents. For instance if set to "2", it will pull all alerts in Covalence for the last 2 days and will create corresponding incidents. | False |
| Fetch limit | Maximum number of alerts to be fetch per fetch command. It is advised to not fetch more than 200 alerts. | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| None |  | False |
| Incident type |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cov-secpr-list-alerts
***
Lists Covalence alerts


#### Base Command

`cov-secpr-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| max_count | Maximum number of alerts to be returned, if none provided will be set to 1000. | Optional | 
| initial_index | Initial index where to start listing alerts. | Optional | 
| alert_type | Alert type to be listed. | Optional | 
| alert_time_min | Minimal alert time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| alert_time_max | Maximal alert time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| advanced_filter | Advanced filter query. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.Alert.acknowledgedStatus | String | Acknowledged Status | 
| Covalence.Alert.alertCount | Number | Alert Count | 
| Covalence.Alert.alertHash | String | Alert Hash | 
| Covalence.Alert.analystDescription | String | Analyst Description | 
| Covalence.Alert.analystTitle | String | Analyst Title | 
| Covalence.Alert.assignee | String | Assignee | 
| Covalence.Alert.blacklistDetails.blacklistedEntity | String | Blacklisted Entity | 
| Covalence.Alert.blacklistDetails.bytesIn | Number | Bytes In | 
| Covalence.Alert.blacklistDetails.bytesOut | Number | Bytes Out | 
| Covalence.Alert.blacklistDetails.listLabels | String | List Labels | 
| Covalence.Alert.blacklistDetails.listUuids | String | List Uuids | 
| Covalence.Alert.createdTime | Number | Created Time | 
| Covalence.Alert.destCiscoUmbrellaRanking | Number | Dest Cisco Umbrella Ranking | 
| Covalence.Alert.destCiscoUmbrellaTopLevelDomainRanking | Number | Dest Cisco Umbrella Top Level Domain Ranking | 
| Covalence.Alert.destCityName | String | Dest City Name | 
| Covalence.Alert.destCountryName | unknown | Dest Country Name | 
| Covalence.Alert.destDomainName | String | Dest Domain Name | 
| Covalence.Alert.destGeoX | Number | Dest Geo X | 
| Covalence.Alert.destGeoY | Number | Dest Geo Y | 
| Covalence.Alert.destIp | String | Dest Ip | 
| Covalence.Alert.destIpAttributes.k | String | Key | 
| Covalence.Alert.destIpAttributes.t | Number | Type | 
| Covalence.Alert.destIpAttributes.v | String | Value | 
| Covalence.Alert.destMajesticMillionRanking | Number | Dest Majestic Million Ranking | 
| Covalence.Alert.destMajesticMillionTopLevelDomainRanking | Number | Dest Majestic Million Top Level Domain Ranking | 
| Covalence.Alert.destPort | String | Dest Port | 
| Covalence.Alert.endpointAgentUuid | String | Endpoint Agent Uuid | 
| Covalence.Alert.facility | String | Facility | 
| Covalence.Alert.id | String | Id | 
| Covalence.Alert.isFavorite | Boolean | Is Favorite | 
| Covalence.Alert.lastAlertedTime | Number | Last Alerted Time | 
| Covalence.Alert.notes | String | Notes | 
| Covalence.Alert.organizationId | String | Organization Id | 
| Covalence.Alert.pcapResourceUuid | String | Pcap Resource Uuid | 
| Covalence.Alert.priority | unknown | Priority | 
| Covalence.Alert.protocol | String | Protocol | 
| Covalence.Alert.sensorId | String | Sensor Id | 
| Covalence.Alert.severity | String | Severity | 
| Covalence.Alert.sigEvalDetails.id | Number | Id | 
| Covalence.Alert.sigEvalDetails.message | String | Message | 
| Covalence.Alert.sourceCiscoUmbrellaRanking | Number | Source Cisco Umbrella Ranking | 
| Covalence.Alert.sourceCiscoUmbrellaTopLevelDomainRanking | Number | Source Cisco Umbrella Top Level Domain Ranking | 
| Covalence.Alert.sourceCityName | String | Source City Name | 
| Covalence.Alert.sourceCountryName | String | Source Country Name | 
| Covalence.Alert.sourceDomainName | String | Source Domain Name | 
| Covalence.Alert.sourceGeoX | Number | Source Geo X | 
| Covalence.Alert.sourceGeoY | Number | Source Geo Y | 
| Covalence.Alert.sourceIp | String | Source Ip | 
| Covalence.Alert.sourceIpAttributes.k | String | Key | 
| Covalence.Alert.sourceIpAttributes.t | Number | Type | 
| Covalence.Alert.sourceIpAttributes.v | String | Value | 
| Covalence.Alert.sourceMajesticMillionRanking | Number | Source Majestic Million Ranking | 
| Covalence.Alert.sourceMajesticMillionTopLevelDomainRanking | Number | Source Majestic Million Top Level Domain Ranking | 
| Covalence.Alert.sourcePort | String | Source Port | 
| Covalence.Alert.subType | String | Sub Type | 
| Covalence.Alert.title | String | Title | 
| Covalence.Alert.type | String | Type | 


#### Command Example
```!cov-secpr-list-alerts```

#### Context Example
```json
{
    "Covalence": {
        "Alert": [
            {
                "acknowledgedStatus": "None",
                "analystDescription": "We've detected suspicious persistent software, C:\\\\test.ps1, on the following system: DESKTOP-1.",
                "analystTitle": "Suspicious persistent software detected",
                "destIp": null,
                "sourceIp": null,
                "subType": "Analytic",
                "title": "Analyst alert",
                "type": "ANALYST GENERIC"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts
>|Acknowledgedstatus|Analystdescription|Analysttitle|Subtype|Title|Type|
>|---|---|---|---|---|---|
>| None | We've detected suspicious persistent software, C:\\test.ps1, on the following system: DESKTOP-1 | Suspicious persistent software detected | Analytic | Analyst alert | ANALYST GENERIC |


### cov-secpr-list-sensors
***
Lists Covalence sensors


#### Base Command

`cov-secpr-list-sensors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.Sensors.id | String | Id | 
| Covalence.Sensors.name | String | Name | 
| Covalence.Sensors.isAuthorized | Boolean | Is Authorized | 
| Covalence.Sensors.isNetflowGenerator | Boolean | Is Netflow Generator | 
| Covalence.Sensors.bytesIn | Number | Bytes In | 
| Covalence.Sensors.bytesOut | Number | Bytes Out | 
| Covalence.Sensors.lastActive | String | Last Active | 
| Covalence.Sensors.listeningInterfaces | String | Listening Interfaces | 


#### Command Example
```!cov-secpr-list-sensors```

#### Context Example
```json
{
    "Covalence": {
        "Sensors": [
            {
                "isAuthorized": false,
                "isNetflowGenerator": true,
                "name": "External Sources"
            },
            {
                "isAuthorized": true,
                "isNetflowGenerator": false,
                "name": "1.1.1.1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Sensors
>|Isauthorized|Isnetflowgenerator|Name|
>|---|---|---|
>| false | true | External Sources |
>| true | false | 1.1.1.1 |


### cov-secpr-get-sensor
***
Get sensor details when provided with the sensor id


#### Base Command

`cov-secpr-get-sensor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| sensor_id | Sensor id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.Sensor.id | String | Id | 
| Covalence.Sensor.name | String | Name | 
| Covalence.Sensor.isAuthorized | Boolean | Is Authorized | 
| Covalence.Sensor.listeningInterfaces | String | Listening Interfaces | 
| Covalence.Sensor.isNetflowGenerator | Boolean | Is Netflow Generator | 
| Covalence.Sensor.bytesIn | Number | Bytes In | 
| Covalence.Sensor.bytesOut | Number | Bytes Out | 
| Covalence.Sensor.lastActive | String | Last Active | 


#### Command Example
```!cov-secpr-get-sensor sensor_id=94397407-5577-4d14-8f21-9a65ad5ac7fe```

#### Context Example
```json
{
    "Covalence": {
        "Sensor": {
            "bytesIn": null,
            "bytesOut": null,
            "id": "94397407-5577-4d14-8f21-9a65ad5ac7fe",
            "isAuthorized": true,
            "isNetflowGenerator": false,
            "listeningInterfaces": [
                "eth0",
                "eth1"
            ],
            "name": "1.1.1.1"
        }
    }
}
```

#### Human Readable Output

>### Sensor
>|Id|Isauthorized|Isnetflowgenerator|Listeninginterfaces|Name|
>|---|---|---|---|---|
>| 94397407-5577-4d14-8f21-9a65ad5ac7fe | true | false | eth0,<br/>eth1 | 1.1.1.1 |


### cov-secpr-connections-summary-ip
***
List summarized connections details by IP Address


#### Base Command

`cov-secpr-connections-summary-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| max_count | Maximum number of connection summary by ip to be returned, if none provided will be set to 100. | Optional | 
| initial_index | Initial index where to start listing connection summaries. | Optional | 
| source_ip | source ip filter, if used only connections related to the specified source ip will be returned. | Optional | 
| start_time | Minimal time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| end_time | Maximal time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| clients_only | if "clients_only=true", only connections labeled as client connections will be returned. | Optional | 
| internal_only | if "internal_only=true", only internal connections will be returned. | Optional | 
| advanced_filter | Advanced filter query. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.Connections.averageDuration | Number | Average Duration | 
| Covalence.Connections.bytesIn | Number | Bytes In | 
| Covalence.Connections.bytesOut | Number | Bytes Out | 
| Covalence.Connections.clientServerRelationship | String | Client Server Relationship | 
| Covalence.Connections.continuingConnectionCount | Number | Continuing Connection Count | 
| Covalence.Connections.destinationCity | String | Destination City | 
| Covalence.Connections.destinationCountry | String | Destination Country | 
| Covalence.Connections.destinationId | String | Destination Id | 
| Covalence.Connections.destinationIpAddress | String | Destination Ip Address | 
| Covalence.Connections.destinationMacAddress | String | Destination Mac Address | 
| Covalence.Connections.dstDomainName | String | Dst Domain Name | 
| Covalence.Connections.id | String | Id | 
| Covalence.Connections.packetsIn | Number | Packets In | 
| Covalence.Connections.packetsOut | Number | Packets Out | 
| Covalence.Connections.serverPortCount | Number | Server Port Count | 
| Covalence.Connections.serverPorts | String | Server Ports | 
| Covalence.Connections.sourceCity | String | Source City | 
| Covalence.Connections.sourceCountry | String | Source Country | 
| Covalence.Connections.sourceDomainName | String | Source Domain Name | 
| Covalence.Connections.sourceId | String | Source Id | 
| Covalence.Connections.sourceIpAddress | String | Source Ip Address | 
| Covalence.Connections.sourceMacAddress | String | Source Mac Address | 
| Covalence.Connections.terminatedConnectionCount | Number | Terminated Connection Count | 
| Covalence.Connections.totalDuration | Number | Total Duration | 


#### Command Example
```!cov-secpr-connections-summary-ip source_ip=1.1.1.1 max_count=10```

#### Context Example
```json
{
    "Covalence": {
        "Connections": [
            {
                "averageDuration": 0,
                "bytesIn": 13360769,
                "bytesOut": 8645498,
                "clientServerRelationship": "CLIENT",
                "destinationIpAddress": "8.8.8.8",
                "dstDomainName": "dns.google",
                "serverPorts": "0,53,443",
                "sourceDomainName": null,
                "sourceIpAddress": "1.1.1.1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Connections
>|Averageduration|Bytesin|Bytesout|Clientserverrelationship|Destinationipaddress|Dstdomainname|Serverports|Sourceipaddress|
>|---|---|---|---|---|---|---|---|
>| 0 | 13360769 | 8645498 | CLIENT | 8.8.8.8 | dns.google | 0,53,443 | 1.1.1.1 |


### cov-secpr-connections-summary-port
***
List summarized connections details by Port


#### Base Command

`cov-secpr-connections-summary-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| max_count | Maximum number of connection summary by port to be returned, if none provided will be set to 100. | Optional | 
| initial_index | Initial index where to start listing connection summaries. | Optional | 
| source_ip | source ip filter, only connections related to the specified source ip will be returned. | Required | 
| start_time | Minimal time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| end_time | Maximal time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| clients_only | if "clients_only=true", only connections labeled as client connections will be returned. | Optional | 
| internal_only | if "internal_only=true", only internal connections will be returned. | Optional | 
| advanced_filter | Advanced filter query. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.Connections.averageDuration | Number | Average Duration | 
| Covalence.Connections.bytesIn | Number | Bytes In | 
| Covalence.Connections.bytesOut | Number | Bytes Out | 
| Covalence.Connections.continuingConnectionCount | Number | Continuing Connection Count | 
| Covalence.Connections.destinationCity | String | Destination City | 
| Covalence.Connections.destinationCountry | String | Destination Country | 
| Covalence.Connections.destinationId | String | Destination Id | 
| Covalence.Connections.destinationIpAddress | String | Destination Ip Address | 
| Covalence.Connections.destinationMacAddress | String | Destination Mac Address | 
| Covalence.Connections.dstDomainName | String | Dst Domain Name | 
| Covalence.Connections.endTime | Date | End Time | 
| Covalence.Connections.id | String | Id | 
| Covalence.Connections.packetsIn | Number | Packets In | 
| Covalence.Connections.packetsOut | Number | Packets Out | 
| Covalence.Connections.protocol | String | Protocol | 
| Covalence.Connections.serverPort | Number | Server Port | 
| Covalence.Connections.sourceCity | String | Source City | 
| Covalence.Connections.sourceCountry | String | Source Country | 
| Covalence.Connections.sourceDomainName | String | Source Domain Name | 
| Covalence.Connections.sourceId | String | Source Id | 
| Covalence.Connections.sourceIpAddress | String | Source Ip Address | 
| Covalence.Connections.sourceMacAddress | String | Source Mac Address | 
| Covalence.Connections.startTime | Date | Start Time | 
| Covalence.Connections.terminatedConnectionCount | Number | Terminated Connection Count | 
| Covalence.Connections.totalDuration | Number | Total Duration | 


#### Command Example
```!cov-secpr-connections-summary-port source_ip=1.1.1.1 max_count=10```

#### Context Example
```json
{
    "Covalence": {
        "Connections": [
            {
                "averageDuration": 44,
                "bytesIn": 0,
                "bytesOut": 305837,
                "destinationIpAddress": "8.8.8.8",
                "dstDomainName": "dns.google",
                "serverPort": 0,
                "sourceDomainName": null,
                "sourceIpAddress": "1.1.1.1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Connections
>|Averageduration|Bytesin|Bytesout|Destinationipaddress|Dstdomainname|Serverport|Sourceipaddress|
>|---|---|---|---|---|---|---|
>| 44 | 0 | 305837 | 8.8.8.8 | dns.google | 0 | 1.1.1.1 |


### cov-secpr-list-dns-resolutions
***
List summarized connections details by Port


#### Base Command

`cov-secpr-list-dns-resolutions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| max_count | Maximum number of DNS resolutions to be returned, if none provided will be set to 100. | Optional | 
| initial_index | Initial index where to start listing DNS resolutions. | Optional | 
| request_time_after | Minimal time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| request_time_before | Maximal time in %Y-%m-%dT%H:%M:%S format and UTC time zone. | Optional | 
| domain_name | Domain name filter, if used will only return DNS resolutions from the specified domain name. | Optional | 
| resolved_ip | IP filter, if used will only return DNS resolutions to the specified IP. | Optional | 
| request_origin_ip | Source IP filter, if used will only return DNS resolutions originating from the specified IP. | Optional | 
| nameserver_ip | Nameserver IP filter, if used will only return DNS resolutions involving the specified nameserver IP. | Optional | 
| advanced_filter | Advanced filter query. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.DNSResolutions.id | String | Id | 
| Covalence.DNSResolutions.domainName | String | Domain Name | 
| Covalence.DNSResolutions.resolvedIp | String | Resolved Ip | 
| Covalence.DNSResolutions.requestOriginIp | String | Request Origin Ip | 
| Covalence.DNSResolutions.nameserverIp | String | Nameserver Ip | 
| Covalence.DNSResolutions.nodeLabel | String | Node Label | 
| Covalence.DNSResolutions.requestTime | Number | Request Time | 
| Covalence.DNSResolutions.byteCount | Number | Byte Count | 
| Covalence.DNSResolutions.pktCount | Number | Pkt Count | 


#### Command Example
```!cov-secpr-list-dns-resolutions max_count=10```

#### Context Example
```json
{
    "Covalence": {
        "DNSResolutions": [
            {
                "domainName": "ntp.ubuntu.com",
                "requestOriginIp": "1.1.1.1",
                "requestTime": 1625752183,
                "resolvedIp": "2001:67c:1560:8003::c7"
            }
        ]
    }
}
```

#### Human Readable Output

>### DNS Resolutions
>|Domainname|Requestoriginip|Requesttime|Resolvedip|
>|---|---|---|---|
>| ntp.ubuntu.com | 1.1.1.1 | 1625752183 | 2001:67c:1560:8003::c7 |


### cov-secpr-list-internal-networks
***
List internal networks


#### Base Command

`cov-secpr-list-internal-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.InternalNetworks.cidr | String | Cidr | 
| Covalence.InternalNetworks.notes | String | Notes | 


#### Command Example
```!cov-secpr-list-internal-networks```

#### Context Example
```json
{
    "Covalence": {
        "InternalNetworks": {
            "cidr": "'1.1.1.1/24'",
            "notes": "'update'"
        }
    }
}
```

#### Human Readable Output

>### Internal Networks
>|Cidr|Notes|
>|---|---|
>| '1.1.1.1/24' | 'update' |


### cov-secpr-set-internal-networks
***
Set internal networks


#### Base Command

`cov-secpr-set-internal-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| cidr | The network to be set as internal in CIDR notation. | Required | 
| notes | Comment notes associated with the network, notes must be inside quotes. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.InternalNetworks.cidr | String | Cidr | 
| Covalence.InternalNetworks.notes | String | Notes | 


#### Command Example
```!cov-secpr-set-internal-networks cidr='1.2.1.1/24' notes=update```

#### Context Example
```json
{
    "Covalence": {
        "InternalNetworks": [
            "'1.2.1.1/24'",
            "update"
        ]
    }
}
```

#### Human Readable Output

>Internal network set as '1.2.1.1/24' with notes "update"

### cov-secpr-list-endpoint-agents
***
List endpoint agents


#### Base Command

`cov-secpr-list-endpoint-agents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| advanced_filter | Advanced filter query, if used any other parameters provided to the command will be ignored. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.EndpointAgents.agentUuid | String | Agent Uuid | 
| Covalence.EndpointAgents.agentVersion | String | Agent Version | 
| Covalence.EndpointAgents.firstSeenTime | Date | First Seen Time | 
| Covalence.EndpointAgents.lastSeenTime | Date | Last Seen Time | 
| Covalence.EndpointAgents.lastSessionUser | String | Last Session User | 
| Covalence.EndpointAgents.isMobile | Boolean | Is Mobile | 
| Covalence.EndpointAgents.isConnected | Boolean | Is Connected | 
| Covalence.EndpointAgents.coreVersion | String | Core Version | 
| Covalence.EndpointAgents.coreArchitecture | String | Core Architecture | 
| Covalence.EndpointAgents.coreOs | String | Core Os | 
| Covalence.EndpointAgents.operatingSystem | String | Operating System | 
| Covalence.EndpointAgents.hostName | String | Host Name | 
| Covalence.EndpointAgents.hardwareVendor | String | Hardware Vendor | 
| Covalence.EndpointAgents.hardwareModel | String | Hardware Model | 
| Covalence.EndpointAgents.arch | String | Arch | 
| Covalence.EndpointAgents.osDistro | String | Os Distro | 
| Covalence.EndpointAgents.osVersion | String | Os Version | 
| Covalence.EndpointAgents.kernelVersion | String | Kernel Version | 
| Covalence.EndpointAgents.operatingSystemReleaseId | String | Operating System Release Id | 
| Covalence.EndpointAgents.ipAddress | String | Ip Address | 
| Covalence.EndpointAgents.secondaryIpAddress | String | Secondary Ip Address | 
| Covalence.EndpointAgents.ipAddresses | String | Ip Addresses | 
| Covalence.EndpointAgents.serialNumber | String | Serial Number | 
| Covalence.EndpointAgents.deviceIdentifier | String | Device Identifier | 
| Covalence.EndpointAgents.cpuArchitectureEnum | String | Cpu Architecture Enum | 


#### Command Example
```!cov-secpr-list-endpoint-agents```

#### Context Example
```json
{
    "Covalence": {
        "EndpointAgents": [
            {
                "hardwareVendor": "VMware, Inc.",
                "hostName": "DESKTOP-0EENF9N",
                "ipAddress": "192.168.223.132",
                "isConnected": false,
                "lastSessionUser": "jsmith",
                "operatingSystem": "Windows 10 Home",
                "serialNumber": "VMware-56 4d 6d cd 58 53 49 e4-73 20 4b 2d b2 15 ca 36"
            },
            {
                "hardwareVendor": "VMware, Inc.",
                "hostName": "DESKTOP-N0E5EN6",
                "ipAddress": "192.168.223.130",
                "isConnected": false,
                "lastSessionUser": "jdoe",
                "operatingSystem": "Windows 10 Pro",
                "serialNumber": "VMware-56 4d 77 78 de 75 22 df-6a c9 62 b2 72 e9 6b 91"
            }
        ]
    }
}
```

#### Human Readable Output

>### Endpoint Agents
>|Hardwarevendor|Hostname|Ipaddress|Isconnected|Lastsessionuser|Operatingsystem|Serialnumber|
>|---|---|---|---|---|---|---|
>| VMware, Inc. | DESKTOP-0EENF9N | 192.168.223.132 | false | jsmith | Windows 10 Home | VMware-56 4d 6d cd 58 53 49 e4-73 20 4b 2d b2 15 ca 36 |
>| VMware, Inc. | DESKTOP-N0E5EN6 | 192.168.223.130 | false | jdoe | Windows 10 Pro | VMware-56 4d 77 78 de 75 22 df-6a c9 62 b2 72 e9 6b 91 |


### cov-secpr-find-endpoint-agents-by-user
***
List endpoint agents where the last session user is the one provided as parameter


#### Base Command

`cov-secpr-find-endpoint-agents-by-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| user | User filter. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.EndpointAgents.agentUuid | String | Agent Uuid | 
| Covalence.EndpointAgents.agentVersion | String | Agent Version | 
| Covalence.EndpointAgents.firstSeenTime | Date | First Seen Time | 
| Covalence.EndpointAgents.lastSeenTime | Date | Last Seen Time | 
| Covalence.EndpointAgents.lastSessionUser | String | Last Session User | 
| Covalence.EndpointAgents.isMobile | Boolean | Is Mobile | 
| Covalence.EndpointAgents.isConnected | Boolean | Is Connected | 
| Covalence.EndpointAgents.coreVersion | String | Core Version | 
| Covalence.EndpointAgents.coreArchitecture | String | Core Architecture | 
| Covalence.EndpointAgents.coreOs | String | Core Os | 
| Covalence.EndpointAgents.operatingSystem | String | Operating System | 
| Covalence.EndpointAgents.hostName | String | Host Name | 
| Covalence.EndpointAgents.hardwareVendor | String | Hardware Vendor | 
| Covalence.EndpointAgents.hardwareModel | String | Hardware Model | 
| Covalence.EndpointAgents.arch | String | Arch | 
| Covalence.EndpointAgents.osDistro | String | Os Distro | 
| Covalence.EndpointAgents.osVersion | String | Os Version | 
| Covalence.EndpointAgents.kernelVersion | String | Kernel Version | 
| Covalence.EndpointAgents.operatingSystemReleaseId | String | Operating System Release Id | 
| Covalence.EndpointAgents.ipAddress | String | Ip Address | 
| Covalence.EndpointAgents.secondaryIpAddress | String | Secondary Ip Address | 
| Covalence.EndpointAgents.ipAddresses | String | Ip Addresses | 
| Covalence.EndpointAgents.serialNumber | String | Serial Number | 
| Covalence.EndpointAgents.deviceIdentifier | String | Device Identifier | 
| Covalence.EndpointAgents.cpuArchitectureEnum | String | Cpu Architecture Enum | 


#### Command Example
```!cov-secpr-find-endpoint-agents-by-user user=jdoe```

#### Context Example
```json
{
    "Covalence": {
        "EndpointAgents": {
            "agentUuid": "4dda9c12-b9ec-498b-8e89-1b2bc9078643",
            "agentVersion": "2.0.1.5",
            "arch": "X64",
            "coreArchitecture": "X64",
            "coreOs": "Windows",
            "coreVersion": "2.0.1.5",
            "cpuArchitectureEnum": "X64",
            "deviceIdentifier": "dff207a9-57e0-417d-b72f-667d1c310a65",
            "firstSeenTime": "2021-03-08 13:57:39",
            "hardwareModel": "VMware7,1",
            "hardwareVendor": "VMware, Inc.",
            "hostName": "DESKTOP-N0E5EN6",
            "ipAddress": "192.168.223.130",
            "ipAddresses": "192.168.223.130",
            "isConnected": false,
            "isMobile": false,
            "kernelVersion": "0.0.0.0",
            "lastSeenTime": "2021-07-07 14:14:58",
            "lastSessionUser": "jdoe",
            "operatingSystem": "Windows 10 Pro",
            "operatingSystemReleaseId": "2009",
            "osDistro": "Professional",
            "osVersion": "10.0.0.19042",
            "secondaryIpAddress": "",
            "serialNumber": "VMware-56 4d 77 78 de 75 22 df-6a c9 62 b2 72 e9 6b 91"
        }
    }
}
```

#### Human Readable Output

>### Endpoint Agents
>|Agentuuid|Agentversion|Arch|Corearchitecture|Coreos|Coreversion|Cpuarchitectureenum|Deviceidentifier|Firstseentime|Hardwaremodel|Hardwarevendor|Hostname|Ipaddress|Ipaddresses|Isconnected|Ismobile|Kernelversion|Lastseentime|Lastsessionuser|Operatingsystem|Operatingsystemreleaseid|Osdistro|Osversion|Serialnumber|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4dda9c12-b9ec-498b-8e89-1b2bc9078643 | 2.0.1.5 | X64 | X64 | Windows | 2.0.1.5 | X64 | dff207a9-57e0-417d-b72f-667d1c310a65 | 2021-03-08 13:57:39 | VMware7,1 | VMware, Inc. | DESKTOP-N0E5EN6 | 192.168.223.130 | 192.168.223.130 | false | false | 0.0.0.0 | 2021-07-07 14:14:58 | jdoe | Windows 10 Pro | 2009 | Professional | 10.0.0.19042 | VMware-56 4d 77 78 de 75 22 df-6a c9 62 b2 72 e9 6b 91 |


### cov-secpr-find-endpoint-agents-by-uuid
***
Find the endpoint agent with the UUID provided as parameter


#### Base Command

`cov-secpr-find-endpoint-agents-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| uuid | Endpoint agent UUID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.EndpointAgents.agentUuid | String | Agent Uuid | 
| Covalence.EndpointAgents.agentVersion | String | Agent Version | 
| Covalence.EndpointAgents.firstSeenTime | Date | First Seen Time | 
| Covalence.EndpointAgents.lastSeenTime | Date | Last Seen Time | 
| Covalence.EndpointAgents.lastSessionUser | String | Last Session User | 
| Covalence.EndpointAgents.isMobile | Boolean | Is Mobile | 
| Covalence.EndpointAgents.isConnected | Boolean | Is Connected | 
| Covalence.EndpointAgents.coreVersion | String | Core Version | 
| Covalence.EndpointAgents.coreArchitecture | String | Core Architecture | 
| Covalence.EndpointAgents.coreOs | String | Core Os | 
| Covalence.EndpointAgents.operatingSystem | String | Operating System | 
| Covalence.EndpointAgents.hostName | String | Host Name | 
| Covalence.EndpointAgents.hardwareVendor | String | Hardware Vendor | 
| Covalence.EndpointAgents.hardwareModel | String | Hardware Model | 
| Covalence.EndpointAgents.arch | String | Arch | 
| Covalence.EndpointAgents.osDistro | String | Os Distro | 
| Covalence.EndpointAgents.osVersion | String | Os Version | 
| Covalence.EndpointAgents.kernelVersion | String | Kernel Version | 
| Covalence.EndpointAgents.operatingSystemReleaseId | String | Operating System Release Id | 
| Covalence.EndpointAgents.ipAddress | String | Ip Address | 
| Covalence.EndpointAgents.secondaryIpAddress | String | Secondary Ip Address | 
| Covalence.EndpointAgents.ipAddresses | String | Ip Addresses | 
| Covalence.EndpointAgents.serialNumber | String | Serial Number | 
| Covalence.EndpointAgents.deviceIdentifier | String | Device Identifier | 
| Covalence.EndpointAgents.cpuArchitectureEnum | String | Cpu Architecture Enum | 


#### Command Example
```!cov-secpr-find-endpoint-agents-by-uuid uuid=4dda9c12-b9ec-498b-8e89-1b2bc9078643```

#### Context Example
```json
{
    "Covalence": {
        "EndpointAgents": {
            "agentUuid": "4dda9c12-b9ec-498b-8e89-1b2bc9078643",
            "agentVersion": "2.0.1.5",
            "arch": "X64",
            "coreArchitecture": "X64",
            "coreOs": "Windows",
            "coreVersion": "2.0.1.5",
            "cpuArchitectureEnum": "X64",
            "deviceIdentifier": "dff207a9-57e0-417d-b72f-667d1c310a65",
            "firstSeenTime": "2021-03-08 13:57:39",
            "hardwareModel": "VMware7,1",
            "hardwareVendor": "VMware, Inc.",
            "hostName": "DESKTOP-N0E5EN6",
            "ipAddress": "192.168.223.130",
            "ipAddresses": "192.168.223.130",
            "isConnected": false,
            "isMobile": false,
            "kernelVersion": "0.0.0.0",
            "lastSeenTime": "2021-07-07 14:14:58",
            "lastSessionUser": "jdoe",
            "operatingSystem": "Windows 10 Pro",
            "operatingSystemReleaseId": "2009",
            "osDistro": "Professional",
            "osVersion": "10.0.0.19042",
            "secondaryIpAddress": "",
            "serialNumber": "VMware-56 4d 77 78 de 75 22 df-6a c9 62 b2 72 e9 6b 91"
        }
    }
}
```

#### Human Readable Output

>### Endpoint Agents
>|Agentuuid|Agentversion|Arch|Corearchitecture|Coreos|Coreversion|Cpuarchitectureenum|Deviceidentifier|Firstseentime|Hardwaremodel|Hardwarevendor|Hostname|Ipaddress|Ipaddresses|Isconnected|Ismobile|Kernelversion|Lastseentime|Lastsessionuser|Operatingsystem|Operatingsystemreleaseid|Osdistro|Osversion|Serialnumber|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4dda9c12-b9ec-498b-8e89-1b2bc9078643 | 2.0.1.5 | X64 | X64 | Windows | 2.0.1.5 | X64 | dff207a9-57e0-417d-b72f-667d1c310a65 | 2021-03-08 13:57:39 | VMware7,1 | VMware, Inc. | DESKTOP-N0E5EN6 | 192.168.223.130 | 192.168.223.130 | false | false | 0.0.0.0 | 2021-07-07 14:14:58 | jdoe | Windows 10 Pro | 2009 | Professional | 10.0.0.19042 | VMware-56 4d 77 78 de 75 22 df-6a c9 62 b2 72 e9 6b 91 |


### cov-secpr-search-endpoint-process
***
Search processes by name or advanced filter, at least one parameter is required


#### Base Command

`cov-secpr-search-endpoint-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| name | Process name. | Optional | 
| advanced_filter | Advanced filter query. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.EndpointProcess.id | Number | Id | 
| Covalence.EndpointProcess.agentUuid | String | Agent Uuid | 
| Covalence.EndpointProcess.processName | String | Process Name | 
| Covalence.EndpointProcess.processPath | String | Process Path | 
| Covalence.EndpointProcess.parentProcessName | String | Parent Process Name | 
| Covalence.EndpointProcess.parentProcessPath | String | Parent Process Path | 
| Covalence.EndpointProcess.commandLine | String | Command Line | 
| Covalence.EndpointProcess.username | String | Username | 
| Covalence.EndpointProcess.firstSeenTime | Date | First Seen Time | 
| Covalence.EndpointProcess.lastSeenTime | Date | Last Seen Time | 
| Covalence.EndpointProcess.lastEndTime | Date | Last End Time | 
| Covalence.EndpointProcess.seenCount | Number | Seen Count | 
| Covalence.EndpointProcess.activeCount | Number | Active Count | 


#### Command Example
```!cov-secpr-search-endpoint-process name=explorer.exe```

#### Context Example
```json
{
    "Covalence": {
        "EndpointProcess": [
            {
                "commandLine": "C:\\Windows\\Explorer.EXE",
                "firstSeenTime": "2021-03-08T12:25:54.100Z",
                "lastSeenTime": "2021-04-08T15:23:10.069Z",
                "processPath": "C:\\Windows\\explorer.exe",
                "username": "jdoe"
            },
            {
                "commandLine": "C:\\Windows\\Explorer.EXE",
                "firstSeenTime": "2021-04-23T07:24:25.570Z",
                "lastSeenTime": "2021-07-07T09:52:17.352Z",
                "processPath": "C:\\Windows\\explorer.exe",
                "username": "jsmith"
            }
        ]
    }
}
```

#### Human Readable Output

>### Endpoint Process
>|Commandline|Firstseentime|Lastseentime|Processpath|Username|
>|---|---|---|---|---|
>| C:\Windows\Explorer.EXE | 2021-03-08T12:25:54.100Z | 2021-04-08T15:23:10.069Z | C:\Windows\explorer.exe | jdoe |
>| C:\Windows\Explorer.EXE | 2021-04-23T07:24:25.570Z | 2021-07-07T09:52:17.352Z | C:\Windows\explorer.exe | jsmith |


### cov-secpr-search-endpoint-installed-software
***
Search for endpoint installed software


#### Base Command

`cov-secpr-search-endpoint-installed-software`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_org | Only required in broker mode, used to target a specific organization: target_org="Acme Corporation". | Optional | 
| name | The name of installed software, quotes are required is space character is used. At least one parameter is required. | Required | 
| version | The version of installed software. | Optional | 
| advanced_filter | Advanced filter query. | Optional | 
| details | if details=true, will return the complete response from Covalence API. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.EndpointSoftware.arch | Number | Arch | 
| Covalence.EndpointSoftware.type | Number | Type | 
| Covalence.EndpointSoftware.packageManager | Number | Package Manager | 
| Covalence.EndpointSoftware.installTimestamp | Date | Install Timestamp | 
| Covalence.EndpointSoftware.uninstallTimestamp | Date | Uninstall Timestamp | 
| Covalence.EndpointSoftware.name | String | Name | 
| Covalence.EndpointSoftware.version | String | Version | 
| Covalence.EndpointSoftware.vendor | String | Vendor | 
| Covalence.EndpointSoftware.installPath | String | Install Path | 
| Covalence.EndpointSoftware.appDataPath | String | App Data Path | 
| Covalence.EndpointSoftware.sharedDataPath | String | Shared Data Path | 
| Covalence.EndpointSoftware.installedForUser | String | Installed For User | 
| Covalence.EndpointSoftware.installSource | String | Install Source | 
| Covalence.EndpointSoftware.id | Number | Id | 
| Covalence.EndpointSoftware.agentUuid | String | Agent Uuid | 
| Covalence.EndpointSoftware.softwareNotifyAction | String | Software Notify Action | 


#### Command Example
```!cov-secpr-search-endpoint-installed-software name=firefox```

#### Context Example
```json
{
    "Covalence": {
        "EndpointSoftware": {
            "installTimestamp": "1970-01-01T00:00:00.000Z",
            "name": "Mozilla Firefox 88.0 (x86 fr)",
            "uninstallTimestamp": null,
            "vendor": "Mozilla",
            "version": "88.0"
        }
    }
}
```

#### Human Readable Output

>### Endpoint Software
>|Installtimestamp|Name|Vendor|Version|
>|---|---|---|---|
>| 1970-01-01T00:00:00.000Z | Mozilla Firefox 88.0 (x86 fr) | Mozilla | 88.0 |


### cov-secpr-list-organizations
***
List monitored organizations, only available in broker mode


#### Base Command

`cov-secpr-list-organizations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Covalence.Organization.org_name | String | Org_name | 


#### Command Example
```!cov-secpr-list-organizations```

#### Human Readable Output

>No organizations found