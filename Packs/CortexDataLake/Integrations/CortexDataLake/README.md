## Overview
---

Palo Alto Networks Cortex Data Lake provides cloud-based, centralized log storage and aggregation for your on premise, virtual (private cloud and public cloud) firewalls, for Prisma Access, and for cloud-delivered services such as Cortex XDR
This integration was integrated and tested with version 2 of Cortex Data Lake



---

## Configure Cortex Data Lake on Demisto
---

1. Go to the [HUB](https://apps.paloaltonetworks.com/apps) and select the `Demisto v2` app
2. In the War Room, run the command `!GetLicenseID` to get the `license ID`.
3. Go to __Settings__ > __ABOUT__ > __License__ to get the `Customer Name`.
4. Insert the `license ID` and the `Customer Name` in the required fields and complete the authentication process in order to get the __Authentication Token__  __Registration ID__ __Encryption Key__
5. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
6. Search for Palo Alto Networks Cortex v2.
7. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Authentication Token__: From the authentication process
    * __Registration ID__: From the authentication process
    * __Encryption Key__: From the authentication process
    * __proxy__: Use system proxy settings
    * __insecure__: Trust any certificate (not secure)
    * __Fetch incidents__: Whether to fetch incidents or not
    * __first_fetch_timestamp__: First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year)
    * __Severity of events to fetch (Firewall)__: Select from all,Critical,High,Medium,Low,Informational,Unused
    * __Subtype of events to fetch (Firewall)__: Select from all,attack,url,virus,spyware,vulnerability,file,scan,flood,packet,resource,data,url-content,wildfire,extpcap,wildfire-virus,http-hdr-insert,http-hdr,email-hdr,spyware-dns,spyware-wildfire-dns,spyware-wpc-dns,spyware-custom-dns,spyware-cloud-dns,spyware-raven,spyware-wildfire-raven,spyware-wpc-raven,wpc-virus,sctp
    * __Incidents fetched per query__: How many incidents will be fetched per query. Caution: high number could create overload. Default is 10.
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
Fetches Firewall threat logs as incidents

---
## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cdl-query-logs
2. cdl-get-critical-threat-logs
3. cdl-get-social-applications
4. cdl-search-by-file-hash
5. cdl-query-traffic-logs
6. cdl-query-threat-logs
### 1. cdl-query-logs

Runs a query on the Cortex logging service.

##### Base Command

`cdl-query-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text SQL query. For example, query="SELECT * FROM `firewall.traffic` limit 10". There are multiple tables in Loggings, for example: threat, traffic, and so on. Refer to the Cortex Logging service schema reference for the full list. | Optional |
| limit | The number of logs to return. Default is 10 | Optional | 
 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.App | String | Application associated with the network traffic. | 
| CDL.Logging.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.CharacteristicOfApp | Number | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.LogSourceName | String | Name of the source of the log. | 
| CDL.Logging.IsNat | number | Indicates if the firewall is performing network address translation (NAT) for the logged traffic. | 
| CDL.Logging.NatDestinationPort | Number | Post-NAT destination port. | 
| CDL.Logging.NatDestination | String | If destination NAT performed, the post-NAT destination IP address. | 
| CDL.Logging.NatSource | String | If source NAT was performed, the post-NAT source IP address. | 
| CDL.Logging.SourceIP | String | Original source IP address. | 
| CDL.Logging.AppCategory | String | Identifies the high-level family of the application. | 
| CDL.Logging.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.FileSHA256 | String | The binary hash (SHA256) of the file sent for virus analysis. | 
| CDL.Logging.FileName | String | The name of the infected file. | 
| CDL.Logging.TimeGenerated | Date | Time when the log was generated on the firewall's data plane. | 


##### Command Example
```!cdl-query-logs query="SELECT * FROM `firewall.traffic` limit 1"```

##### Context Example
```
{
  "CDL.Logging": [
    {
      "Action": "allow",
      "App": "smtp",
      "Protocol": "tcp",
      "DestinationIP": "206.116.22.23",
      "RuleMatched": "taplog",
      "CharacteristicOfApp": [
        "3",
        "4",
        "5",
        "6",
        "7",
        "8"
      ],
      "LogSourceName": "gw",
      "NatDestination": "0.0.0.0",
      "NatSource": "0.0.0.0",
      "SourceIP": "10.154.1.20",
      "AppCategory": "collaboration",
      "SourceLocation": "10.0.0.0-10.255.255.255",
      "DestinationLocation": "CA",
      "TimeGenerated": "2020-03-18T19:36:37"
    }
  ]
}
```

##### Human Readable Output
### Logs traffic table
|Action|App|AppCategory|CharacteristicOfApp|DestinationIP|DestinationLocation|LogSourceName|NatDestination|NatSource|Protocol|RuleMatched|SourceIP|SourceLocation|TimeGenerated|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| allow | smtp | collaboration | 3,4,5,6,7,8 | 206.116.22.23 | CA | gw | 0.0.0.0 | 0.0.0.0 | tcp | taplog | 10.154.1.20 | 10.0.0.0-10.255.255.255 | 2020-03-18T19:36:37 |

### 2. cdl-get-critical-threat-logs

---
Runs a query on the Cortex logging service, according to preset queries.

##### Base Command

`cdl-get-critical-threat-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| limit | The number of logs to return. Default is 10 | Optional | 
| time_range | First log time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.Nat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category_of_app. | 
| CDL.Logging.Threat.PcapID | String | Packet capture (pcap) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap_id of 0 (no associated pcap) , or an ID referencing the extended pcap file. | 
| CDL.Logging.Threat.Natdst | String | If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.Flags | String | Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session. | 
| CDL.Logging.Threat.Dport | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Threat.ThreatID | String | Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier | 
| CDL.Logging.Threat.Natsrc | String | If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.CategoryOfApp | String | Identifies the managing application, or parent, of the application associated with this network traffic, if any. | 
| CDL.Logging.Threat.Srcloc | String | Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise. | 
| CDL.Logging.Threat.Dstloc | String | Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise. | 
| CDL.Logging.Threat.To | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Threat.RiskOfApp | String | Indicates how risky the application is from a network security perspective. Values range from 1-5, where 5 is the riskiest. | 
| CDL.Logging.Threat.Natsport | String | Post-NAT source port. | 
| CDL.Logging.Threat.URLDenied | String | Session was denied due to a URL filtering rule. | 
| CDL.Logging.Threat.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Threat.HTTPMethod | String | Only in URL filtering logs. Describes the HTTP Method used in the web request | 
| CDL.Logging.Threat.From | String | The networking zone from which the traffic originated. | 
| CDL.Logging.Threat.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Threat.ReceiveTime | String | Time the log was received at the management plane. | 
| CDL.Logging.Threat.Users | String | Srcuser or dstuser or srcip (one of). | 
| CDL.Logging.Threat.Proto | String | IP protocol associated with the session. | 
| CDL.Logging.Threat.Natdport | String | Post-NAT destination port. | 
| CDL.Logging.Threat.Dst | String | Original destination IP address. The IP address is an IPv4/ IPv6 address in hex format. | 
| CDL.Logging.Threat.Rule | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Threat.CategoryOfThreatID | String | Threat category of the detected threat. | 
| CDL.Logging.Threat.DeviceName | String | The hostname of the firewall that logged the network traffic. | 
| CDL.Logging.Threat.Subtype | String | Subtype of the threat log. | 
| CDL.Logging.Threat.TimeReceived | String | Time the log was received at the management plane. | 
| CDL.Logging.Threat.Direction | String | Indicates the direction of the attack, client-to-server or server-to-client: | 
| CDL.Logging.Threat.Misc | String | The meaning of this field differs according to the log's subtype: Subtype is URL, this field contains the requested URI. Subtype is File, this field contains the file name or file type. Subtype is Virus, this field contains the file name. Subtype is WildFire, this field contains the file name. | 
| CDL.Logging.Threat.Severity | String | Severity associated with the event. | 
| CDL.Logging.Threat.Src | String | Original source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.TimeGenerated | String | Time the log was generated on the data plane. | 
| CDL.Logging.Threat.Serial | String | Serial number of the firewall that generated the log. | 
| CDL.Logging.Threat.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.URLDomain | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.Threat.Category | String | For the URL subtype, this identifies the URL Category. For the WildFire subtype, this identifies the verdict on the file. It is one of ‘malicious’, ‘phishing’, ‘grayware’, or ‘benign’; | 
| CDL.Logging.Threat.Sport | String | Source port utilized by the session. | 
| CDL.Logging.Threat.IsPhishing | Boolean | Detected enterprise credential submission by an end user. | 
| IP.Address | String | IP address. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name (including file extension). | 
| File.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 


##### Command Example
```!cdl-get-critical-threat-logs limit="1" time_range="10 days"```
##### Context Example

```
{
  "CDL.Logging.Threat": [
    {
      "SessionID": 103986,
      "Action": "reset-both",
      "App": "imap",
      "IsNat": false,
      "SubcategoryOfApp": "email",
      "PcapID": 0,
      "NatDestination": "0.0.0.0",
      "Flags": 8192,
      "DestinationPort": 143,
      "ThreatID": 30663,
      "NatSource": "0.0.0.0",
      "IsURLDenied": false,
      "Users": "10.154.10.88",
      "TimeGenerated": "2020-03-18T15:46:10",
      "IsPhishing": false,
      "AppCategory": "collaboration",
      "SourceLocation": "10.0.0.0-10.255.255.255",
      "DestinationLocation": "CH",
      "ToZone": "TapZone",
      "RiskOfApp": 4,
      "NatSourcePort": 0,
      "CharacteristicOfApp": [
        "3",
        "4",
        "5",
        "8"
      ],
      "FromZone": "TapZone",
      "Vsys": "vsys1",
      "Protocol": "tcp",
      "NatDestinationPort": 0,
      "DestinationIP": "84.74.104.27",
      "SourceIP": "10.154.10.88",
      "RuleMatched": "taplog",
      "ThreatCategory": "overflow",
      "LogSourceName": "gw",
      "Subtype": "vulnerability",
      "Direction": "server to client",
      "FileName": "iZJvnxT27.PpT",
      "VendorSeverity": "Critical",
      "LogTime": "2020-03-18T15:46:37",
      "LogSourceID": "007251000070976",
      "VsysID": 1,
      "URLDomain": null,
      "URLCategory": "any",
      "SourcePort": 14484
    }
  ]
}
```
##### Human Readable Output
### Logs threat table
|Action|App|AppCategory|CharacteristicOfApp|DestinationIP|DestinationLocation|DestinationPort|Direction|FileName|Flags|FromZone|IsNat|IsPhishing|IsURLDenied|LogSourceID|LogSourceName|LogTime|NatDestination|NatDestinationPort|NatSource|NatSourcePort|PcapID|Protocol|RiskOfApp|RuleMatched|SessionID|SourceIP|SourceLocation|SourcePort|SubcategoryOfApp|Subtype|ThreatCategory|ThreatID|TimeGenerated|ToZone|URLCategory|URLDomain|Users|VendorSeverity|Vsys|VsysID|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| reset-both | imap | collaboration | 3,4,5,8 | 84.74.104.27 | CH | 143 | server to client | iZJvnxT27.PpT | 8192 | TapZone | false | false | false | 007251000070976 | gw | 2020-03-18T15:46:37 | 0.0.0.0 | 0 | 0.0.0.0 | 0 | 0 | tcp | 4 | taplog | 103986 | 10.154.10.88 | 10.0.0.0-10.255.255.255 | 14484 | email | vulnerability | overflow | 30663 | 2020-03-18T15:46:10 | TapZone | any |  | 10.154.10.88 | Critical | vsys1 | 1 |

### 3. cdl-get-social-applications
___
Runs a query on the Cortex logging service, according to preset queries.

##### Base Command

`cdl-get-social-applications`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | Query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| limit | Amount of logs. Default is 10 | Optional | 
| time_range | First log time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Traffic.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Traffic.RiskOfApp | String | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Traffic.NatSourcePort | String | Post-NAT source port. | 
| CDL.Logging.Traffic.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Traffic.Packets | String | Number of total packets (transmit and receive) seen for the session. | 
| CDL.Logging.Traffic.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Traffic.App | String | Application associated with the network traffic. | 
| CDL.Logging.Traffic.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Traffic.IsNat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Traffic.LogTime | date | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Traffic.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, | 
| CDL.Logging.Traffic.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Traffic.NatDestinationPort | String | Post-NAT destination port. | 
| CDL.Logging.Traffic.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Traffic.NatDestination | String | If destination NAT performed, the post-NAT destination IP address. | 
| CDL.Logging.Traffic.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Traffic.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Traffic.TotalTimeElapsed | String | Total time taken for the network session to complete. | 
| CDL.Logging.Traffic.LogSourceName | String | Device name of the source of the log | 
| CDL.Logging.Traffic.Subtype | String | The log sub type. | 
| CDL.Logging.Traffic.Users | String | Source/Destination user. If neither is available, source_ip is used. | 
| CDL.Logging.Traffic.TunneledApp | String | Is app tunneled. | 
| CDL.Logging.Traffic.IsPhishing | String | Indicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Traffic.SessionEndReason | String | The reason a session terminated. | 
| CDL.Logging.Traffic.NatSource | String | If source NAT was performed, the post-NAT source IP address. | 
| CDL.Logging.Traffic.SourceIP | String | Original source IP address. | 
| CDL.Logging.Traffic.SessionStartIP | date | Time when the session was established. | 
| CDL.Logging.Traffic.TimeGenerated | date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Traffic.AppCategory | String | Identifies the high-level family of the application. | 
| CDL.Logging.Traffic.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Traffic.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Traffic.LogSourceID | String | D that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Traffic.TotalBytes | String | Number of total bytes (transmit and receive). | 
| CDL.Logging.Traffic.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Traffic.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Traffic.URLCategory | String | The URL category. | 
| CDL.Logging.Traffic.SourcePort | String | Source port utilized by the session. | 
| CDL.Logging.Traffic.Tunnel | String | Type of tunnel. |


##### Command Example
```!cdl-get-social-applications limit="2" time_range="10 days"```
##### Context Example
```
{
  "CDL.Logging.Traffic": [
    {
      "Action": "allow",
      "RiskOfApp": 4,
      "SessionID": 108356,
      "Packets": 7,
      "CharacteristicOfApp": [
        "3",
        "4",
        "5",
        "6",
        "8"
      ],
      "App": "facebook-base",
      "Vsys": "vsys1",
      "LogTime": "2020-03-18T15:54:40",
      "SubcategoryOfApp": "social-networking",
      "Protocol": "tcp",
      "DestinationIP": "131.130.159.25",
      "NatDestination": "0.0.0.0",
      "RuleMatched": "taplog",
      "DestinationPort": 80,
      "LogSourceName": "gw",
      "Subtype": "start",
      "Users": "10.154.230.43",
      "TunneledApp": "tunneled-app",
      "SessionEndReason": "n-a",
      "NatSource": "0.0.0.0",
      "SourceIP": "10.154.230.43",
      "SessionStartIP": "2020-03-18T15:54:14",
      "TimeGenerated": "2020-03-18T15:54:16",
      "AppCategory": "collaboration",
      "SourceLocation": "10.0.0.0-10.255.255.255",
      "DestinationLocation": "AT",
      "LogSourceID": "007251000070976",
      "TotalBytes": 946,
      "VsysID": 1,
      "ToZone": "TapZone",
      "URLCategory": "social-networking",
      "SourcePort": 37252,
      "Tunnel": "N/A"
    },
    {
      "Action": "allow",
      "RiskOfApp": 4,
      "SessionID": 276377,
      "Packets": 768,
      "CharacteristicOfApp": [
        "3",
        "4",
        "5",
        "6",
        "8"
      ],
      "App": "facebook-base",
      "Vsys": "vsys1",
      "LogTime": "2020-03-16T15:54:36",
      "SubcategoryOfApp": "social-networking",
      "Protocol": "tcp",
      "DestinationIP": "213.191.250.86",
      "NatDestination": "0.0.0.0",
      "RuleMatched": "taplog",
      "DestinationPort": 80,
      "TotalTimeElapsed": 1,
      "LogSourceName": "gw",
      "Subtype": "end",
      "Users": "10.154.227.21",
      "TunneledApp": "tunneled-app",
      "SessionEndReason": "tcp-fin",
      "NatSource": "0.0.0.0",
      "SourceIP": "10.154.227.21",
      "SessionStartIP": "2020-03-16T15:53:58",
      "TimeGenerated": "2020-03-16T15:54:16",
      "AppCategory": "collaboration",
      "SourceLocation": "10.0.0.0-10.255.255.255",
      "DestinationLocation": "IE",
      "LogSourceID": "007251000070976",
      "TotalBytes": 384468,
      "VsysID": 1,
      "ToZone": "TapZone",
      "URLCategory": "social-networking",
      "SourcePort": 53174,
      "Tunnel": "N/A"
    }
  ]
}
```
##### Human Readable Output
### Logs traffic table
### Logs traffic table
|Action|App|AppCategory|CharacteristicOfApp|DestinationIP|DestinationLocation|DestinationPort|LogSourceID|LogSourceName|LogTime|NatDestination|NatSource|Packets|Protocol|RiskOfApp|RuleMatched|SessionEndReason|SessionID|SessionStartIP|SourceIP|SourceLocation|SourcePort|SubcategoryOfApp|Subtype|TimeGenerated|ToZone|TotalBytes|Tunnel|TunneledApp|URLCategory|Users|Vsys|VsysID|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| allow | facebook-base | collaboration | 3,4,5,6,8 | 131.130.159.25 | AT | 80 | 007251000070976 | gw | 2020-03-18T15:54:40 | 0.0.0.0 | 0.0.0.0 | 7 | tcp | 4 | taplog | n-a | 108356 | 2020-03-18T15:54:14 | 10.154.230.43 | 10.0.0.0-10.255.255.255 | 37252 | social-networking | start | 2020-03-18T15:54:16 | TapZone | 946 | N/A | tunneled-app | social-networking | 10.154.230.43 | vsys1 | 1 |
| allow | facebook-base | collaboration | 3,4,5,6,8 | 213.191.250.86 | IE | 80 | 007251000070976 | gw | 2020-03-16T15:54:36 | 0.0.0.0 | 0.0.0.0 | 768 | tcp | 4 | taplog | tcp-fin | 276377 | 2020-03-16T15:53:58 | 10.154.227.21 | 10.0.0.0-10.255.255.255 | 53174 | social-networking | end | 2020-03-16T15:54:16 | TapZone | 384468 | N/A | tunneled-app | social-networking | 10.154.227.21 | vsys1 | 1 |

### 4. cdl-search-by-file-hash

---
Runs a query on the threat table with the query 'SELECT * FROM `firewall.threat` WHERE file_sha_256 = <file_hash>'

##### Base Command

`cdl-search-by-file-hash`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| limit | The number of logs to return. Default is 10. | Optional | 
| time_range | First log time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| SHA256 | The SHA256 hash of the file for the query. For example, SHA256="503ca1a4fc0d48b18c0336f544ba0f0abf305ae3a3f49b3c2b86b8645d6572dc" would return all logs associated with this file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.Nat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category_of_app. | 
| CDL.Logging.Threat.PcapID | String | Packet capture (pcap) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap_id of 0 (no associated pcap) , or an ID referencing the extended pcap file. | 
| CDL.Logging.Threat.Natdst | String | If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.Flags | String | Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session. | 
| CDL.Logging.Threat.Dport | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Threat.ThreatID | String | Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier | 
| CDL.Logging.Threat.Natsrc | String | If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.CategoryOfApp | String | Identifies the managing application, or parent, of the application associated with this network traffic, if any. | 
| CDL.Logging.Threat.Srcloc | String | Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise. | 
| CDL.Logging.Threat.Dstloc | String | Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise. | 
| CDL.Logging.Threat.To | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Threat.RiskOfApp | String | Indicates how risky the application is from a network security perspective. Values range from 1-5, where 5 is the riskiest. | 
| CDL.Logging.Threat.Natsport | String | Post-NAT source port. | 
| CDL.Logging.Threat.URLDenied | String | Session was denied due to a URL filtering rule. | 
| CDL.Logging.Threat.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Threat.HTTPMethod | String | Only in URL filtering logs. Describes the HTTP Method used in the web request | 
| CDL.Logging.Threat.From | String | The networking zone from which the traffic originated. | 
| CDL.Logging.Threat.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Threat.ReceiveTime | String | Time the log was received at the management plane. | 
| CDL.Logging.Threat.Users | String | Srcuser or dstuser or srcip (one of). | 
| CDL.Logging.Threat.Proto | String | IP protocol associated with the session. | 
| CDL.Logging.Threat.Natdport | String | Post-NAT destination port. | 
| CDL.Logging.Threat.Dst | String | Original destination IP address. The IP address is an IPv4/ IPv6 address in hex format. | 
| CDL.Logging.Threat.Rule | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Threat.CategoryOfThreatID | String | Threat category of the detected threat. | 
| CDL.Logging.Threat.DeviceName | String | The hostname of the firewall that logged the network traffic. | 
| CDL.Logging.Threat.Subtype | String | Subtype of the threat log. | 
| CDL.Logging.Threat.TimeReceived | String | Time the log was received at the management plane. | 
| CDL.Logging.Threat.Direction | String | Indicates the direction of the attack, client-to-server or server-to-client: | 
| CDL.Logging.Threat.Misc | String | The meaning of this field differs according to the log's subtype: Subtype is URL, this field contains the requested URI. Subtype is File, this field contains the file name or file type. Subtype is Virus, this field contains the file name. Subtype is WildFire, this field contains the file name. | 
| CDL.Logging.Threat.Severity | String | Severity associated with the event. | 
| CDL.Logging.Threat.Src | String | Original source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.TimeGenerated | String | Time the log was generated on the data plane. | 
| CDL.Logging.Threat.Serial | String | Serial number of the firewall that generated the log. | 
| CDL.Logging.Threat.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.URLDomain | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.Threat.Category | String | For the URL subtype, this identifies the URL Category. For the WildFire subtype, this identifies the verdict on the file. It is one of ‘malicious’, ‘phishing’, ‘grayware’, or ‘benign’; | 
| CDL.Logging.Threat.Sport | String | Source port utilized by the session. | 
| CDL.Logging.Threat.IsPhishing | Boolean | Detected enterprise credential submission by an end user. | 
| IP.Address | String | IP address. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name (including file extension). | 
| File.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 


##### Command Example
```!cdl-search-by-file-hash SHA256="cbdf1f3cccd949e6e96c425b3d7ccc463b956f002f694472e4d24a12ff2cea4d" limit=1 time_range="10 days"```
##### Context Example
```
{
  "CDL.Logging.Threat": [
    {
      "SessionID": 784600,
      "Action": "block",
      "App": "smtp",
      "IsNat": false,
      "SubcategoryOfApp": "email",
      "PcapID": 0,
      "NatDestination": "0.0.0.0",
      "Flags": 8192,
      "DestinationPort": 25,
      "ThreatID": 52033,
      "NatSource": "0.0.0.0",
      "IsURLDenied": false,
      "Users": "10.154.246.167",
      "TimeGenerated": "2020-03-25T15:42:08",
      "IsPhishing": false,
      "AppCategory": "collaboration",
      "SourceLocation": "10.0.0.0-10.255.255.255",
      "DestinationLocation": "US",
      "ToZone": "TapZone",
      "RiskOfApp": 5,
      "NatSourcePort": 0,
      "CharacteristicOfApp": [
        "3",
        "4",
        "5",
        "6",
        "7",
        "8"
      ],
      "FromZone": "TapZone",
      "Vsys": "vsys1",
      "Protocol": "tcp",
      "NatDestinationPort": 0,
      "DestinationIP": "67.53.137.201",
      "SourceIP": "10.154.246.167",
      "RuleMatched": "taplog",
      "ThreatCategory": "",
      "LogSourceName": "gw",
      "Subtype": "wildfire",
      "Direction": "client to server",
      "FileName": "o93yr.ECr",
      "VendorSeverity": "Informational",
      "LogTime": "2020-03-25T15:42:13",
      "LogSourceID": "007251000070976",
      "VsysID": 1,
      "URLDomain": null,
      "URLCategory": "",
      "SourcePort": 51819,
      "FileSHA256": "cbdf1f3cccd949e6e96c425b3d7ccc463b956f002f694472e4d24a12ff2cea4d"
    }
  ]
}
```
##### Human Readable Output
### Logs threat table
|Action|App|AppCategory|CharacteristicOfApp|DestinationIP|DestinationLocation|DestinationPort|Direction|FileName|FileSHA256|Flags|FromZone|IsNat|IsPhishing|IsURLDenied|LogSourceID|LogSourceName|LogTime|NatDestination|NatDestinationPort|NatSource|NatSourcePort|PcapID|Protocol|RiskOfApp|RuleMatched|SessionID|SourceIP|SourceLocation|SourcePort|SubcategoryOfApp|Subtype|ThreatCategory|ThreatID|TimeGenerated|ToZone|URLCategory|URLDomain|Users|VendorSeverity|Vsys|VsysID|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| block | smtp | collaboration | 3,4,5,6,7,8 | 67.53.137.201 | US | 25 | client to server | o93yr.ECr | cbdf1f3cccd949e6e96c425b3d7ccc463b956f002f694472e4d24a12ff2cea4d | 8192 | TapZone | false | false | false | 007251000070976 | gw | 2020-03-25T15:42:13 | 0.0.0.0 | 0 | 0.0.0.0 | 0 | 0 | tcp | 5 | taplog | 784600 | 10.154.246.167 | 10.0.0.0-10.255.255.255 | 51819 | email | wildfire |  | 52033 | 2020-03-25T15:42:08 | TapZone |  |  | 10.154.246.167 | Informational | vsys1 | 1 |
### 5. cdl-query-traffic-logs

___

Searches the Cortex firewall.traffic table. Traffic logs contain entries for the end of each network session
##### Base Command

`cdl-query-traffic-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_ip | A source IP address or an array of source IPs addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| rule | A rule name or an array of rule names to search. | Optional | 
| from_zone | A source zone  name or an array of source zone names to search. | Optional | 
| to_zone | A destination zone name or an array of zone names to search. | Optional | 
| source_port | Source port utilized by the session. Can be port number or an array of destination port numbers to search. For example '443' or '443,445' | Optional | 
| action | An action name or an array of action names to search. | Optional | 
| query | A free-text query for which to search. This forms the WHERE part of the query, for example, !cdl-query-traffic-logs query="source_ip.value LIKE '192.168.1.*' AND dest_ip.value='8.8.8.8' And dest_port=1234" | Optional | 
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or a comma saparated list of specific fields in the table.  | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00". | Optional | 
| time_range | First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| dest_ip | A destination IP address or an array of destination IPs addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| dest_port | Destination port utilized by the session. Can be port number or an array of destination port numbers to search. For example '443' or '443,445' | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Traffic.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Traffic.RiskOfApp | String | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Traffic.NatSourcePort | String | Post-NAT source port. | 
| CDL.Logging.Traffic.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Traffic.Packets | String | Number of total packets (transmit and receive) seen for the session. | 
| CDL.Logging.Traffic.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Traffic.App | String | Application associated with the network traffic. | 
| CDL.Logging.Traffic.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Traffic.IsNat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Traffic.LogTime | date | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Traffic.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, | 
| CDL.Logging.Traffic.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Traffic.NatDestinationPort | String | Post-NAT destination port. | 
| CDL.Logging.Traffic.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Traffic.NatDestination | String | If destination NAT performed, the post-NAT destination IP address. | 
| CDL.Logging.Traffic.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Traffic.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Traffic.TotalTimeElapsed | String | Total time taken for the network session to complete. | 
| CDL.Logging.Traffic.LogSourceName | String | Device name of the source of the log | 
| CDL.Logging.Traffic.Subtype | String | The log sub type. | 
| CDL.Logging.Traffic.Users | String | Source/Destination user. If neither is available, source_ip is used. | 
| CDL.Logging.Traffic.TunneledApp | String | Is app tunneled. | 
| CDL.Logging.Traffic.IsPhishing | String | Indicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Traffic.SessionEndReason | String | The reason a session terminated. | 
| CDL.Logging.Traffic.NatSource | String | If source NAT was performed, the post-NAT source IP address. | 
| CDL.Logging.Traffic.SourceIP | String | Original source IP address. | 
| CDL.Logging.Traffic.SessionStartIP | date | Time when the session was established. | 
| CDL.Logging.Traffic.TimeGenerated | date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Traffic.AppCategory | String | Identifies the high-level family of the application. | 
| CDL.Logging.Traffic.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Traffic.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Traffic.LogSourceID | String | D that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Traffic.TotalBytes | String | Number of total bytes (transmit and receive). | 
| CDL.Logging.Traffic.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Traffic.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Traffic.URLCategory | String | The URL category. | 
| CDL.Logging.Traffic.SourcePort | String | Source port utilized by the session. | 
| CDL.Logging.Traffic.Tunnel | String | Type of tunnel. | 


##### Command Example
```!cdl-query-traffic-logs action="allow" fields="vendor_name,log_source,rule_matched,dest_location,log_time" time_range="10 days" limit="5"```

##### Context Example
```
{
    "CDL.Logging.Traffic": [
        {
            "RuleMatched": "taplog", 
            "ID": "N2eE+oI3d+esVqaqtVGJv95p4VpTYIihtY50eFi8jgo=", 
            "DestinationLocation": "TH", 
            "LogTime": "2020-03-21T16:50:18Z"
        }, 
        {
            "RuleMatched": "taplog", 
            "ID": "+zZj7TRjBYRXuSdYrbKAYSjoQDyw4vtNwMhvjlbKGrc=", 
            "DestinationLocation": "US", 
            "LogTime": "2020-03-21T16:50:18Z"
        }, 
        {
            "RuleMatched": "taplog", 
            "ID": "PetZR587UGE/wOkxgS2b+zF364WTmJ29VnV2gihfJZM=", 
            "DestinationLocation": "US", 
            "LogTime": "2020-03-21T16:50:33Z"
        }, 
        {
            "RuleMatched": "taplog", 
            "ID": "t6dTRzTObu15RCxw6Nk7SPFXe83uxr06yPMC5Px1p8c=", 
            "DestinationLocation": "RO", 
            "LogTime": "2020-03-21T16:50:18Z"
        }, 
        {
            "RuleMatched": "taplog", 
            "ID": "X4tXn5Ub82q/DDaCyqcZfSboshpWOu+5xvOSf7ydtrY=", 
            "DestinationLocation": "CL", 
            "LogTime": "2020-03-21T16:50:18Z"
        }
    ]
}
```

##### Human Readable Output
|dest_location|log_source|log_time|rule_matched|vendor_name|
|---|---|---|---|---|
| TH |  firewall | 1584809418000000 | taplog | Palo Alto Networks |
| US |  firewall | 1584809418000000 | taplog | Palo Alto Networks |
| US |  firewall | 1584809433000000 | taplog | Palo Alto Networks |
| RO |  firewall | 1584809418000000 | taplog | Palo Alto Networks |
| CL |  firewall | 1584809418000000 | taplog | Palo Alto Networks |


### 6. cdl-query-threat-logs

---
Searches the Cortex panw.threat table, which is the threat logs table for PAN-OS/Panorama.

##### Base Command

`cdl-query-threat-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_ip | Original source IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| dest_ip | Original destination IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| rule_matched | Name of the security policy rule that the network traffic matched. Enter a rule name or array of rule names to search. | Optional | 
| from_zone | The networking zone from which the traffic originated. Enter zone or array of zones to search. | Optional | 
| to_zone | Networking zone to which the traffic was sent. Enter zone or array of zones to search. | Optional | 
| source_port | Source port utilized by the session. Enter a port or array of ports to search. | Optional | 
| dest_port | Network traffic's destination port. Enter a port or array of ports to search. | Optional | 
| action | The action that the firewall took for the network traffic. Enter an action or array of actions to search. | Optional | 
| file_sha_256 | The binary hash (SHA256) of the file. Enter a SHA256 hash or array of SHA256 hashes to search. | Optional | 
| file_name | The name of the file that is blocked. Enter a file name or array of file names to search. | Optional | 
| query | Free input query to search. This is the WHERE part of the query. so an example will be !cdl-query-traffic-logs query="source_ip.value LIKE '192.168.1.*' AND dst = '192.168.1.12'" | Optional | 
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all. | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| time_range | First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.Nat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category_of_app. | 
| CDL.Logging.Threat.PcapID | String | Packet capture (pcap) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap_id of 0 (no associated pcap) , or an ID referencing the extended pcap file. | 
| CDL.Logging.Threat.Natdst | String | If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.Flags | String | Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session. | 
| CDL.Logging.Threat.Dport | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Threat.ThreatID | String | Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier | 
| CDL.Logging.Threat.Natsrc | String | If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.CategoryOfApp | String | Identifies the managing application, or parent, of the application associated with this network traffic, if any. | 
| CDL.Logging.Threat.Srcloc | String | Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise. | 
| CDL.Logging.Threat.Dstloc | String | Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise. | 
| CDL.Logging.Threat.To | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Threat.RiskOfApp | String | Indicates how risky the application is from a network security perspective. Values range from 1-5, where 5 is the riskiest. | 
| CDL.Logging.Threat.Natsport | String | Post-NAT source port. | 
| CDL.Logging.Threat.URLDenied | String | Session was denied due to a URL filtering rule. | 
| CDL.Logging.Threat.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Threat.HTTPMethod | String | Only in URL filtering logs. Describes the HTTP Method used in the web request | 
| CDL.Logging.Threat.From | String | The networking zone from which the traffic originated. | 
| CDL.Logging.Threat.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Threat.ReceiveTime | String | Time the log was received at the management plane. | 
| CDL.Logging.Threat.Users | String | Srcuser or dstuser or srcip (one of). | 
| CDL.Logging.Threat.Proto | String | IP protocol associated with the session. | 
| CDL.Logging.Threat.Natdport | String | Post-NAT destination port. | 
| CDL.Logging.Threat.Dst | String | Original destination IP address. The IP address is an IPv4/ IPv6 address in hex format. | 
| CDL.Logging.Threat.Rule | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Threat.CategoryOfThreatID | String | Threat category of the detected threat. | 
| CDL.Logging.Threat.DeviceName | String | The hostname of the firewall that logged the network traffic. | 
| CDL.Logging.Threat.Subtype | String | Subtype of the threat log. | 
| CDL.Logging.Threat.TimeReceived | String | Time the log was received at the management plane. | 
| CDL.Logging.Threat.Direction | String | Indicates the direction of the attack, client-to-server or server-to-client: | 
| CDL.Logging.Threat.Misc | String | The meaning of this field differs according to the log's subtype: Subtype is URL, this field contains the requested URI. Subtype is File, this field contains the file name or file type. Subtype is Virus, this field contains the file name. Subtype is WildFire, this field contains the file name. | 
| CDL.Logging.Threat.Severity | String | Severity associated with the event. | 
| CDL.Logging.Threat.Src | String | Original source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.TimeGenerated | String | Time the log was generated on the data plane. | 
| CDL.Logging.Threat.Serial | String | Serial number of the firewall that generated the log. | 
| CDL.Logging.Threat.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.URLDomain | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.Threat.Category | String | For the URL subtype, this identifies the URL Category. For the WildFire subtype, this identifies the verdict on the file. It is one of ‘malicious’, ‘phishing’, ‘grayware’, or ‘benign’; | 
| CDL.Logging.Threat.Sport | String | Source port utilized by the session. | 
| CDL.Logging.Threat.IsPhishing | Boolean | Detected enterprise credential submission by an end user. | 
| IP.Address | String | IP address. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name (including file extension). | 
| File.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 


##### Command Example
```!cdl-query-threat-logs action="allow" fields="vendor_name,log_source,rule_matched,dest_location,log_time" time_range="10 days" limit="1"```

##### Context Example
```
{
    "CDL.Logging.Threat": [
        {
            "NatDestinationPort": null, 
            "VsysID": null, 
            "RuleMatched": "taplog", 
            "FromZone": null, 
            "URLDomain": null, 
            "DestinationLocation": "AE", 
            "IsPhishing": null, 
            "URLCategory": "", 
            "NatSource": "", 
            "NatSourcePort": null, 
            "IsURLDenied": null, 
            "PcapID": null, 
            "Direction": "", 
            "Users": null, 
            "ThreatID": null, 
            "SessionID": null, 
            "CharacteristicOfApp": null, 
            "VendorSeverity": "", 
            "LogTime": "2020-02-22T16:50:23Z", 
            "IsNat": null, 
            "SubcategoryOfApp": null, 
            "SourceIP": "", 
            "RiskOfApp": null, 
            "DestinationIP": "", 
            "Vsys": null, 
            "TimeGenerated": null, 
            "Subtype": "", 
            "Flags": null, 
            "ToZone": null, 
            "Action": "", 
            "AppCategory": null, 
            "ThreatCategory": null, 
            "Protocol": "", 
            "LogSourceName": null, 
            "App": null, 
            "Misc": null, 
            "DestinationPort": null, 
            "SourcePort": null, 
            "NatDestination": "", 
            "SourceLocation": null, 
            "LogSourceID": null
        }
    ]
}
```

##### Human Readable Output
### Logs threat table
|dest_location|log_source|log_time|rule_matched|vendor_name|
|---|---|---|---|---|
| AE | firewall | 1582390223000000 | taplog | Palo Alto Networks |

## Additional Information

---
* In the documented CDL v2, You must now specify the customer's instance ID when you identify the log type that you want to query
against. That is, log types must be fully qualified and the instance ID is a part of the fully qualified name:
`<instanceID>.firewall.traffic`
However in this integration the instance ID is added automatically to the query so the name `firewall.traffic` is a valid table name
* The SQL syntex supported for queries is `csql`
