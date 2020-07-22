Palo Alto Networks Cortex Data Lake provides cloud-based, centralized log storage and aggregation for your on premise, virtual (private cloud and public cloud) firewalls, for Prisma Access, and for cloud-delivered services such as Cortex XDR
This integration was integrated and tested with version xx of Cortex Data Lake
## Configure Cortex Data Lake on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex Data Lake.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| refresh_token | Token | True |
| reg_id | ID | True |
| auth_key | Key | True |
| isFetch | Fetch incidents | False |
| first_fetch_timestamp | First fetch time \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| firewall_severity | Severity of events to fetch \(Firewall\) | False |
| firewall_subtype | Subtype of events to fetch \(Firewall\) | False |
| incidentType | Incident type | False |
| limit | Incidents fetched per query | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cdl-query-logs
***
Runs a query on the Cortex logging service.


#### Base Command

`cdl-query-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text SQL query. For example, query="SELECT * FROM `firewall.traffic` limit 10". There are multiple tables in Loggings, for example: threat, traffic, and so on. Refer to the Cortex Logging service schema reference for the full list. | Optional | 
| limit | The number of logs to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.App | String | Application associated with the network traffic. | 
| CDL.Logging.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.CharacteristicOfApp | Number | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.LogSourceName | String | Name of the source of the log. | 
| CDL.Logging.IsNat | number | Indicates if the firewall is performing network address translation \(NAT\) for the logged traffic. | 
| CDL.Logging.NatDestinationPort | Number | Post\-NAT destination port. | 
| CDL.Logging.NatDestination | String | If destination NAT performed, the post\-NAT destination IP address. | 
| CDL.Logging.NatSource | String | If source NAT was performed, the post\-NAT source IP address. | 
| CDL.Logging.SourceIP | String | Original source IP address. | 
| CDL.Logging.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.FileSHA256 | String | The binary hash \(SHA256\) of the file sent for virus analysis. | 
| CDL.Logging.FileName | String | The name of the infected file. | 
| CDL.Logging.TimeGenerated | Date | Time when the log was generated on the firewall's data plane. | 


#### Command Example
```!cdl-query-logs query="SELECT * FROM `firewall.traffic` limit 1"```

#### Context Example
```
{
    "CDL": {
        "Logging": [
            {
                "Action": "deny",
                "App": "not-applicable",
                "AppCategory": "unknown",
                "CharacteristicOfApp": [],
                "DestinationIP": "172.16.7.7",
                "DestinationLocation": "172.16.0.0-172.31.255.255",
                "FileName": null,
                "FileSHA256": null,
                "IsNat": null,
                "LogSourceName": "Aristotle",
                "NatDestination": "0.0.0.0",
                "NatDestinationPort": 0,
                "NatSource": "0.0.0.0",
                "Protocol": "udp",
                "RuleMatched": "DENY",
                "SourceIP": "172.16.0.1",
                "SourceLocation": "172.16.0.0-172.31.255.255",
                "TimeGenerated": "2020-05-18T18:15:07"
            }
        ]
    }
}
```

#### Human Readable Output

>### Logs firewall.traffic table
>|Action|App|AppCategory|DestinationIP|DestinationLocation|LogSourceName|NatDestination|NatDestinationPort|NatSource|Protocol|RuleMatched|SourceIP|SourceLocation|TimeGenerated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| deny | not-applicable | unknown | 172.16.0.255 | 172.16.0.0-172.31.255.255 | Aristotle | 0.0.0.0 | 0 | 0.0.0.0 | udp | DENY | 172.16.0.1 | 172.16.0.0-172.31.255.255 | 2020-05-18T18:15:07 |


### cdl-get-critical-threat-logs
***
Runs a query on the Cortex logging service, according to preset queries.


#### Base Command

`cdl-get-critical-threat-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| limit | The number of logs to return. | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.IsNat | String | Indicates whether the firewall is performing network address translation \(NAT\) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category\_of\_app. | 
| CDL.Logging.Threat.PcapID | String | Packet capture \(pcap\) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap\_id of 0 \(no associated pcap\) , or an ID referencing the extended pcap file. | 
| CDL.Logging.Threat.NatDestination | String | If destination NAT performed, the post\-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.Flags | String | Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session. | 
| CDL.Logging.Threat.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Threat.ThreatID | String | Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier | 
| CDL.Logging.Threat.NatSource | String | If source NAT was performed, the post\-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.IsURLDenied | Boolean | Indicates whether the session was denied due to a URL filtering rule. | 
| CDL.Logging.Threat.Users | String | Source/Destination user. If neither is available, source\_ip is used. | 
| CDL.Logging.Threat.TimeGenerated | Date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Threat.IsPhishing | Boolean | ndicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Threat.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.Threat.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Threat.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Threat.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Threat.RiskOfApp | Number | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Threat.NatSourcePort | Number | Post\-NAT source port. | 
| CDL.Logging.Threat.CharacteristicOfApp | Unknown | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Threat.FromZone | String | The networking zone from which the traffic originated. | 
| CDL.Logging.Threat.Vsys | String | String representation of the unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Threat.NatDestinationPort | Number | Post\-NAT destination port. | 
| CDL.Logging.Threat.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Threat.SourceIP | String | Original source IP address. | 
| CDL.Logging.Threat.RuleMatched | String | Unique identifier for the security policy rule that the network traffic matched. | 
| CDL.Logging.Threat.ThreatCategory | String | Threat category of the detected threat. | 
| CDL.Logging.Threat.LogSourceName | String | Name of the source of the log. | 
| CDL.Logging.Threat.Subtype | String | Identifies the log subtype. | 
| CDL.Logging.Threat.Direction | String | Indicates the direction of the attack. | 
| CDL.Logging.Threat.FileName | String | The name of the file that is blocked. | 
| CDL.Logging.Threat.VendorSeverity | String | Severity associated with the event. | 
| CDL.Logging.Threat.LogTime | String | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Threat.LogSourceID | String | ID that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Threat.VsysID | Number | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.URLDomain | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.Threat.URLCategory | String | The URL category. | 
| CDL.Logging.Threat.SourcePort | Number | Source port utilized by the session. | 


#### Command Example
```!cdl-get-critical-threat-logs limit="1" time_range="10 days"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "Threat": [
                {
                    "Action": "reset-both",
                    "App": "imap",
                    "AppCategory": "collaboration",
                    "CharacteristicOfApp": [
                        "3",
                        "4",
                        "5",
                        "8"
                    ],
                    "DestinationIP": "3.3.3.3",
                    "DestinationLocation": "GB",
                    "DestinationPort": 143,
                    "Direction": "server to client",
                    "FileName": "GTPu3.Xls",
                    "FileSHA256": null,
                    "Flags": 8192,
                    "FromZone": "TapZone",
                    "IsNat": false,
                    "IsPhishing": false,
                    "IsURLDenied": false,
                    "LogSourceID": "007251000070976",
                    "LogSourceName": "gw",
                    "LogTime": "2020-03-16T11:52:54",
                    "NatDestination": "0.0.0.0",
                    "NatDestinationPort": 0,
                    "NatSource": "0.0.0.0",
                    "NatSourcePort": 0,
                    "PcapID": 0,
                    "Protocol": "tcp",
                    "RiskOfApp": 4,
                    "RuleMatched": "taplog",
                    "SessionID": 75787,
                    "SourceIP": "10.1.1.1",
                    "SourceLocation": "10.0.0.0-10.255.255.255",
                    "SourcePort": 11094,
                    "SubcategoryOfApp": "email",
                    "Subtype": "vulnerability",
                    "ThreatCategory": "overflow",
                    "ThreatID": 33411,
                    "TimeGenerated": "2020-03-16T11:52:39",
                    "ToZone": "TapZone",
                    "URLCategory": "any",
                    "URLDomain": null,
                    "Users": "10.1.1.1",
                    "VendorSeverity": "Critical",
                    "Vsys": "vsys1",
                    "VsysID": 1
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logs threat table
>|Action|App|AppCategory|CharacteristicOfApp|DestinationIP|DestinationLocation|DestinationPort|Direction|FileName|Flags|FromZone|IsNat|IsPhishing|IsURLDenied|LogSourceID|LogSourceName|LogTime|NatDestination|NatDestinationPort|NatSource|NatSourcePort|PcapID|Protocol|RiskOfApp|RuleMatched|SessionID|SourceIP|SourceLocation|SourcePort|SubcategoryOfApp|Subtype|ThreatCategory|ThreatID|TimeGenerated|ToZone|URLCategory|Users|VendorSeverity|Vsys|VsysID|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| reset-both | imap | collaboration | 3,<br/>4,<br/>5,<br/>8 | 10.1.1.1 | GB | 143 | server to client | GTPu3.Xls | 8192 | TapZone | false | false | false | 007251000070976 | gw | 2020-03-16T11:52:54 | 0.0.0.0 | 0 | 0.0.0.0 | 0 | 0 | tcp | 4 | taplog | 75787 | 10.1.1.1 | 10.0.0.0-10.255.255.255 | 11094 | email | vulnerability | overflow | 33411 | 2020-03-16T11:52:39 | TapZone | any | 10.1.1.1 | Critical | vsys1 | 1 |


### cdl-get-social-applications
***
Runs a query on the Cortex logging service, according to preset queries.


#### Base Command

`cdl-get-social-applications`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | Query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| limit | Amount of logs. | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Traffic.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Traffic.RiskOfApp | String | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Traffic.NatSourcePort | String | Post\-NAT source port. | 
| CDL.Logging.Traffic.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Traffic.Packets | String | Number of total packets \(transmit and receive\) seen for the session. | 
| CDL.Logging.Traffic.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Traffic.App | String | Application associated with the network traffic. | 
| CDL.Logging.Traffic.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Traffic.IsNat | String | Indicates whether the firewall is performing network address translation \(NAT\) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Traffic.LogTime | date | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Traffic.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, | 
| CDL.Logging.Traffic.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Traffic.NatDestinationPort | String | Post\-NAT destination port. | 
| CDL.Logging.Traffic.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Traffic.NatDestination | String | If destination NAT performed, the post\-NAT destination IP address. | 
| CDL.Logging.Traffic.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Traffic.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Traffic.TotalTimeElapsed | String | Total time taken for the network session to complete. | 
| CDL.Logging.Traffic.LogSourceName | String | Device name of the source of the log | 
| CDL.Logging.Traffic.Subtype | String | The log sub type. | 
| CDL.Logging.Traffic.Users | String | Source/Destination user. If neither is available, source\_ip is used. | 
| CDL.Logging.Traffic.TunneledApp | String | Is app tunneled. | 
| CDL.Logging.Traffic.IsPhishing | String | Indicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Traffic.SessionEndReason | String | The reason a session terminated. | 
| CDL.Logging.Traffic.NatSource | String | If source NAT was performed, the post\-NAT source IP address. | 
| CDL.Logging.Traffic.SourceIP | String | Original source IP address. | 
| CDL.Logging.Traffic.SessionStartIP | date | Time when the session was established. | 
| CDL.Logging.Traffic.TimeGenerated | date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Traffic.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.Traffic.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Traffic.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Traffic.LogSourceID | String | D that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Traffic.TotalBytes | String | Number of total bytes \(transmit and receive\). | 
| CDL.Logging.Traffic.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Traffic.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Traffic.URLCategory | String | The URL category. | 
| CDL.Logging.Traffic.SourcePort | String | Source port utilized by the session. | 
| CDL.Logging.Traffic.Tunnel | String | Type of tunnel. | 


#### Command Example
```!cdl-get-social-applications limit="2" time_range="10 days"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "Traffic": [
                {
                    "Action": "allow",
                    "App": "facebook-base",
                    "AppCategory": "collaboration",
                    "CharacteristicOfApp": [
                        "3",
                        "4",
                        "5",
                        "6",
                        "8"
                    ],
                    "DestinationIP": "1.1.1.1",
                    "DestinationLocation": "ES",
                    "DestinationPort": 80,
                    "IsNat": null,
                    "IsPhishing": null,
                    "LogSourceID": "007251000070976",
                    "LogSourceName": "gw",
                    "LogTime": "2020-02-24T11:53:04",
                    "NatDestination": "0.0.0.0",
                    "NatDestinationPort": 0,
                    "NatSource": "0.0.0.0",
                    "NatSourcePort": 0,
                    "Packets": 7,
                    "Protocol": "tcp",
                    "RiskOfApp": 4,
                    "RuleMatched": "taplog",
                    "SessionEndReason": "n-a",
                    "SessionID": 425765,
                    "SessionStartIP": "2020-02-24T11:52:45",
                    "SourceIP": "10.5.5.5",
                    "SourceLocation": "10.0.0.0-10.255.255.255",
                    "SourcePort": 1627,
                    "SubcategoryOfApp": "social-networking",
                    "Subtype": "start",
                    "TimeGenerated": "2020-02-24T11:52:45",
                    "ToZone": "TapZone",
                    "TotalBytes": 946,
                    "TotalTimeElapsed": 0,
                    "Tunnel": "N/A",
                    "TunneledApp": "tunneled-app",
                    "URLCategory": "social-networking",
                    "Users": "10.5.5.5",
                    "Vsys": "vsys1",
                    "VsysID": 1
                },
                {
                    "Action": "allow",
                    "App": "facebook-base",
                    "AppCategory": "collaboration",
                    "CharacteristicOfApp": [
                        "3",
                        "4",
                        "5",
                        "6",
                        "8"
                    ],
                    "DestinationIP": "4.4.4.4",
                    "DestinationLocation": "FR",
                    "DestinationPort": 80,
                    "IsNat": null,
                    "IsPhishing": null,
                    "LogSourceID": "007251000070976",
                    "LogSourceName": "gw",
                    "LogTime": "2019-11-16T11:52:49",
                    "NatDestination": "0.0.0.0",
                    "NatDestinationPort": 0,
                    "NatSource": "0.0.0.0",
                    "NatSourcePort": 0,
                    "Packets": 7,
                    "Protocol": "tcp",
                    "RiskOfApp": 4,
                    "RuleMatched": "taplog",
                    "SessionEndReason": "n-a",
                    "SessionID": 564870,
                    "SessionStartIP": "2019-11-16T11:52:45",
                    "SourceIP": "10.6.6.6",
                    "SourceLocation": "10.0.0.0-10.255.255.255",
                    "SourcePort": 9369,
                    "SubcategoryOfApp": "social-networking",
                    "Subtype": "start",
                    "TimeGenerated": "2019-11-16T11:52:45",
                    "ToZone": "TapZone",
                    "TotalBytes": 946,
                    "TotalTimeElapsed": 0,
                    "Tunnel": "N/A",
                    "TunneledApp": "tunneled-app",
                    "URLCategory": "social-networking",
                    "Users": "10.6.6.6",
                    "Vsys": "vsys1",
                    "VsysID": 1
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logs traffic table
>|Action|App|AppCategory|CharacteristicOfApp|DestinationIP|DestinationLocation|DestinationPort|LogSourceID|LogSourceName|LogTime|NatDestination|NatDestinationPort|NatSource|NatSourcePort|Packets|Protocol|RiskOfApp|RuleMatched|SessionEndReason|SessionID|SessionStartIP|SourceIP|SourceLocation|SourcePort|SubcategoryOfApp|Subtype|TimeGenerated|ToZone|TotalBytes|TotalTimeElapsed|Tunnel|TunneledApp|URLCategory|Users|Vsys|VsysID|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| allow | facebook-base | collaboration | 3,<br/>4,<br/>5,<br/>6,<br/>8 | 1.1.1.1 | ES | 80 | 007251000070976 | gw | 2020-02-24T11:53:04 | 0.0.0.0 | 0 | 0.0.0.0 | 0 | 7 | tcp | 4 | taplog | n-a | 425765 | 2020-02-24T11:52:45 | 105 | 10.0.0.0-10.255.255.255 | 1627 | social-networking | start | 2020-02-24T11:52:45 | TapZone | 946 | 0 | N/A | tunneled-app | social-networking | 10.5.5.5 | vsys1 | 1 |
>| allow | facebook-base | collaboration | 3,<br/>4,<br/>5,<br/>6,<br/>8 | 4.4.4.4 | FR | 80 | 007251000070976 | gw | 2019-11-16T11:52:49 | 0.0.0.0 | 0 | 0.0.0.0 | 0 | 7 | tcp | 4 | taplog | n-a | 564870 | 2019-11-16T11:52:45 | 10.6.6.6 | 10.0.0.0-10.255.255.255 | 9369 | social-networking | start | 2019-11-16T11:52:45 | TapZone | 946 | 0 | N/A | tunneled-app | social-networking | 10.6.6.6 | vsys1 | 1 |


### cdl-search-by-file-hash
***
Runs a query on the threat table with the query 'SELECT * FROM `firewall.threat` WHERE file_sha_256 = <file_hash>'


#### Base Command

`cdl-search-by-file-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| limit | The number of logs to return. | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| SHA256 | The SHA256 hash of the file for the query. For example, SHA256="503ca1a4fc0d48b18c0336f544ba0f0abf305ae3a3f49b3c2b86b8645d6572dc" would return all logs associated with this file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.IsNat | String | Indicates whether the firewall is performing network address translation \(NAT\) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category\_of\_app. | 
| CDL.Logging.Threat.PcapID | String | Packet capture \(pcap\) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap\_id of 0 \(no associated pcap\) , or an ID referencing the extended pcap file. | 
| CDL.Logging.Threat.NatDestination | String | If destination NAT performed, the post\-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.Flags | String | Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session. | 
| CDL.Logging.Threat.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Threat.ThreatID | String | Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier | 
| CDL.Logging.Threat.NatSource | String | If source NAT was performed, the post\-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.IsURLDenied | Boolean | Indicates whether the session was denied due to a URL filtering rule. | 
| CDL.Logging.Threat.Users | String | Source/Destination user. If neither is available, source\_ip is used. | 
| CDL.Logging.Threat.TimeGenerated | Date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Threat.IsPhishing | Boolean | ndicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Threat.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.Threat.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Threat.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Threat.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Threat.RiskOfApp | Number | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Threat.NatSourcePort | Number | Post\-NAT source port. | 
| CDL.Logging.Threat.CharacteristicOfApp | Unknown | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Threat.FromZone | String | The networking zone from which the traffic originated. | 
| CDL.Logging.Threat.Vsys | String | String representation of the unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Threat.NatDestinationPort | Number | Post\-NAT destination port. | 
| CDL.Logging.Threat.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Threat.SourceIP | String | Original source IP address. | 
| CDL.Logging.Threat.RuleMatched | String | Unique identifier for the security policy rule that the network traffic matched. | 
| CDL.Logging.Threat.ThreatCategory | String | Threat category of the detected threat. | 
| CDL.Logging.Threat.LogSourceName | String | Name of the source of the log. | 
| CDL.Logging.Threat.Subtype | String | Identifies the log subtype. | 
| CDL.Logging.Threat.Direction | String | Indicates the direction of the attack. | 
| CDL.Logging.Threat.FileName | String | The name of the file that is blocked. | 
| CDL.Logging.Threat.VendorSeverity | String | Severity associated with the event. | 
| CDL.Logging.Threat.LogTime | String | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Threat.LogSourceID | String | ID that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Threat.VsysID | Number | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.URLDomain | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.Threat.URLCategory | String | The URL category. | 
| CDL.Logging.Threat.SourcePort | Number | Source port utilized by the session. | 


#### Command Example
```!cdl-search-by-file-hash SHA256="cbdf1f3cccd949e6e96c425b3d7ccc463b956f002f694472e4d24a12ff2cea4d" limit=1 time_range="10 days"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "Threat": null
        }
    }
}
```

#### Human Readable Output

>### Logs threat table
>**No entries.**


### cdl-query-traffic-logs
***
Searches the Cortex firewall.traffic table. Traffic logs contain entries for the end of each network session


#### Base Command

`cdl-query-traffic-logs`
#### Input

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
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| dest_ip | A destination IP address or an array of destination IPs addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| dest_port | Destination port utilized by the session. Can be port number or an array of destination port numbers to search. For example '443' or '443,445' | Optional | 
| ip | IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| port | Port utilized by the session. Enter a port or array of ports to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Traffic.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Traffic.RiskOfApp | String | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Traffic.NatSourcePort | String | Post\-NAT source port. | 
| CDL.Logging.Traffic.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Traffic.Packets | String | Number of total packets \(transmit and receive\) seen for the session. | 
| CDL.Logging.Traffic.CharacteristicOfApp | String | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Traffic.App | String | Application associated with the network traffic. | 
| CDL.Logging.Traffic.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Traffic.IsNat | String | Indicates whether the firewall is performing network address translation \(NAT\) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Traffic.LogTime | date | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Traffic.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, | 
| CDL.Logging.Traffic.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Traffic.NatDestinationPort | String | Post\-NAT destination port. | 
| CDL.Logging.Traffic.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Traffic.NatDestination | String | If destination NAT performed, the post\-NAT destination IP address. | 
| CDL.Logging.Traffic.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.Traffic.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Traffic.TotalTimeElapsed | String | Total time taken for the network session to complete. | 
| CDL.Logging.Traffic.LogSourceName | String | Device name of the source of the log | 
| CDL.Logging.Traffic.Subtype | String | The log sub type. | 
| CDL.Logging.Traffic.Users | String | Source/Destination user. If neither is available, source\_ip is used. | 
| CDL.Logging.Traffic.TunneledApp | String | Is app tunneled. | 
| CDL.Logging.Traffic.IsPhishing | String | Indicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Traffic.SessionEndReason | String | The reason a session terminated. | 
| CDL.Logging.Traffic.NatSource | String | If source NAT was performed, the post\-NAT source IP address. | 
| CDL.Logging.Traffic.SourceIP | String | Original source IP address. | 
| CDL.Logging.Traffic.SessionStartIP | date | Time when the session was established. | 
| CDL.Logging.Traffic.TimeGenerated | date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Traffic.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.Traffic.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Traffic.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Traffic.LogSourceID | String | D that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Traffic.TotalBytes | String | Number of total bytes \(transmit and receive\). | 
| CDL.Logging.Traffic.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Traffic.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Traffic.URLCategory | String | The URL category. | 
| CDL.Logging.Traffic.SourcePort | String | Source port utilized by the session. | 
| CDL.Logging.Traffic.Tunnel | String | Type of tunnel. | 


#### Command Example
```!cdl-query-traffic-logs action="allow" fields="vendor_name,log_source,rule_matched,dest_location,log_time" time_range="10 days" limit="5"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "Traffic": [
                {
                    "Action": null,
                    "App": null,
                    "AppCategory": null,
                    "CharacteristicOfApp": null,
                    "DestinationIP": null,
                    "DestinationLocation": "US",
                    "DestinationPort": null,
                    "IsNat": null,
                    "IsPhishing": null,
                    "LogSourceID": null,
                    "LogSourceName": null,
                    "LogTime": "2020-04-04T11:53:11",
                    "NatDestination": null,
                    "NatDestinationPort": null,
                    "NatSource": null,
                    "NatSourcePort": null,
                    "Packets": null,
                    "Protocol": null,
                    "RiskOfApp": null,
                    "RuleMatched": "taplog",
                    "SessionEndReason": null,
                    "SessionID": null,
                    "SessionStartIP": null,
                    "SourceIP": null,
                    "SourceLocation": null,
                    "SourcePort": null,
                    "SubcategoryOfApp": null,
                    "Subtype": null,
                    "TimeGenerated": null,
                    "ToZone": null,
                    "TotalBytes": null,
                    "TotalTimeElapsed": null,
                    "Tunnel": null,
                    "TunneledApp": null,
                    "URLCategory": null,
                    "Users": null,
                    "Vsys": null,
                    "VsysID": null
                },
                {
                    "Action": null,
                    "App": null,
                    "AppCategory": null,
                    "CharacteristicOfApp": null,
                    "DestinationIP": null,
                    "DestinationLocation": "RU",
                    "DestinationPort": null,
                    "IsNat": null,
                    "IsPhishing": null,
                    "LogSourceID": null,
                    "LogSourceName": null,
                    "LogTime": "2020-04-04T11:53:11",
                    "NatDestination": null,
                    "NatDestinationPort": null,
                    "NatSource": null,
                    "NatSourcePort": null,
                    "Packets": null,
                    "Protocol": null,
                    "RiskOfApp": null,
                    "RuleMatched": "taplog",
                    "SessionEndReason": null,
                    "SessionID": null,
                    "SessionStartIP": null,
                    "SourceIP": null,
                    "SourceLocation": null,
                    "SourcePort": null,
                    "SubcategoryOfApp": null,
                    "Subtype": null,
                    "TimeGenerated": null,
                    "ToZone": null,
                    "TotalBytes": null,
                    "TotalTimeElapsed": null,
                    "Tunnel": null,
                    "TunneledApp": null,
                    "URLCategory": null,
                    "Users": null,
                    "Vsys": null,
                    "VsysID": null
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logs traffic table
>|dest_location|log_source|log_time|rule_matched|vendor_name|
>|---|---|---|---|---|
>| US | firewall | 1586001191000000 | taplog | Palo Alto Networks |
>| US | firewall | 1586001191000000 | taplog | Palo Alto Networks |
>| US | firewall | 1586001191000000 | taplog | Palo Alto Networks |
>| US | firewall | 1586001191000000 | taplog | Palo Alto Networks |
>| RU | firewall | 1586001191000000 | taplog | Palo Alto Networks |


### cdl-query-threat-logs
***
Searches the Cortex panw.threat table, which is the threat logs table for PAN-OS/Panorama.


#### Base Command

`cdl-query-threat-logs`
#### Input

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
| query | Free input query to search. This is the WHERE part of the query. so an example will be !cdl-query-traffic-logs query="source_ip.value LIKE '192.168.1.*' AND dest_ip.value = '192.168.1.12'" | Optional | 
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all. | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| ip | IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| port | Port utilized by the session. Enter a port or array of ports to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.IsNat | String | Indicates whether the firewall is performing network address translation \(NAT\) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category\_of\_app. | 
| CDL.Logging.Threat.PcapID | String | Packet capture \(pcap\) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap\_id of 0 \(no associated pcap\) , or an ID referencing the extended pcap file. | 
| CDL.Logging.Threat.NatDestination | String | If destination NAT performed, the post\-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.Flags | String | Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session. | 
| CDL.Logging.Threat.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.Threat.ThreatID | String | Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier | 
| CDL.Logging.Threat.NatSource | String | If source NAT was performed, the post\-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format. | 
| CDL.Logging.Threat.IsURLDenied | Boolean | Indicates whether the session was denied due to a URL filtering rule. | 
| CDL.Logging.Threat.Users | String | Source/Destination user. If neither is available, source\_ip is used. | 
| CDL.Logging.Threat.TimeGenerated | Date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.Threat.IsPhishing | Boolean | ndicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.Threat.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.Threat.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.Threat.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.Threat.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Threat.RiskOfApp | Number | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Threat.NatSourcePort | Number | Post\-NAT source port. | 
| CDL.Logging.Threat.CharacteristicOfApp | Unknown | Identifies the behaviorial characteristic of the application associated with the network traffic. | 
| CDL.Logging.Threat.FromZone | String | The networking zone from which the traffic originated. | 
| CDL.Logging.Threat.Vsys | String | String representation of the unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.Threat.NatDestinationPort | Number | Post\-NAT destination port. | 
| CDL.Logging.Threat.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.Threat.SourceIP | String | Original source IP address. | 
| CDL.Logging.Threat.RuleMatched | String | Unique identifier for the security policy rule that the network traffic matched. | 
| CDL.Logging.Threat.ThreatCategory | String | Threat category of the detected threat. | 
| CDL.Logging.Threat.LogSourceName | String | Name of the source of the log. | 
| CDL.Logging.Threat.Subtype | String | Identifies the log subtype. | 
| CDL.Logging.Threat.Direction | String | Indicates the direction of the attack. | 
| CDL.Logging.Threat.FileName | String | The name of the file that is blocked. | 
| CDL.Logging.Threat.VendorSeverity | String | Severity associated with the event. | 
| CDL.Logging.Threat.LogTime | String | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.Threat.LogSourceID | String | ID that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Threat.VsysID | Number | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Threat.URLDomain | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.Threat.URLCategory | String | The URL category. | 
| CDL.Logging.Threat.SourcePort | Number | Source port utilized by the session. | 


#### Command Example
```!cdl-query-threat-logs action="allow" fields="vendor_name,log_source,rule_matched,dest_location,log_time" time_range="10 days" limit="1"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "Threat": [
                {
                    "Action": null,
                    "App": null,
                    "AppCategory": null,
                    "CharacteristicOfApp": null,
                    "DestinationIP": null,
                    "DestinationLocation": "YE",
                    "DestinationPort": null,
                    "Direction": null,
                    "FileName": null,
                    "FileSHA256": null,
                    "Flags": null,
                    "FromZone": null,
                    "IsNat": null,
                    "IsPhishing": null,
                    "IsURLDenied": null,
                    "LogSourceID": null,
                    "LogSourceName": null,
                    "LogTime": "2020-02-12T11:53:13",
                    "NatDestination": null,
                    "NatDestinationPort": null,
                    "NatSource": null,
                    "NatSourcePort": null,
                    "PcapID": null,
                    "Protocol": null,
                    "RiskOfApp": null,
                    "RuleMatched": "taplog",
                    "SessionID": null,
                    "SourceIP": null,
                    "SourceLocation": null,
                    "SourcePort": null,
                    "SubcategoryOfApp": null,
                    "Subtype": null,
                    "ThreatCategory": null,
                    "ThreatID": null,
                    "TimeGenerated": null,
                    "ToZone": null,
                    "URLCategory": null,
                    "URLDomain": null,
                    "Users": null,
                    "VendorSeverity": null,
                    "Vsys": null,
                    "VsysID": null
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logs threat table
>|dest_location|log_source|log_time|rule_matched|vendor_name|
>|---|---|---|---|---|
>| YE | firewall | 1581508393000000 | taplog | Palo Alto Networks |


### cdl-query-url-logs
***
Searches the URL table


#### Base Command

`cdl-query-url-logs`
#### Input

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
| query | Free input query to search. This is the WHERE part of the query. so an example will be !cdl-query-url-logs query="source_ip.value LIKE '192.168.1.*' AND dest_ip.value = '192.168.1.12'" | Optional | 
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all. | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| ip | IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| port | Port utilized by the session. Enter a port or array of ports to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.URL.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.URL.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.URL.App | String | Application associated with the network traffic. | 
| CDL.Logging.URL.PcapID | String | Packet capture \(pcap\) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap\_id of 0 \(no associated pcap\) , or an ID referencing the extended pcap file. | 
| CDL.Logging.URL.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.URL.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.URL.AppSubCategory | String | Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category\_of\_app. | 
| CDL.Logging.URL.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.URL.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.URL.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.URL.FromZone | String | The networking zone from which the traffic originated. | 
| CDL.Logging.URL.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.URL.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.URL.SourceIP | String | Original source IP address. | 
| CDL.Logging.URL.RuleMatched | String | Unique identifier for the security policy rule that the network traffic matched. | 
| CDL.Logging.URL.ThreatCategory | String | Threat category of the detected threat. | 
| CDL.Logging.URL.ThreatName | String | Threat name of the detected threat. | 
| CDL.Logging.URL.Subtype | String | Identifies the log subtype. | 
| CDL.Logging.URL.LogTime | String | Time the log was received in Cortex Data Lake. | 
| CDL.Logging.URL.LogSourceName | String | Name that uniquely identifies the source of the log. | 
| CDL.Logging.URL.Denied | Boolean | Indicates whether the session was denied due to a URL filtering rule. | 
| CDL.Logging.URL.Category | String | The URL category. | 
| CDL.Logging.URL.SourcePort | Number | Source port utilized by the session. | 
| CDL.Logging.URL.Url | String | The name of the internet domain that was visited in this session. | 
| CDL.Logging.URL.Uri | String | The URI address | 
| CDL.Logging.URL.ContentType | String | Content type of the HTTP response data. | 
| CDL.Logging.URL.HTTPMethod | String | The HTTP Method used
in the web request | 
| CDL.Logging.URL.Severity | String | Severity associated with the event. | 
| CDL.Logging.URL.UserAgent | String | The web browser that the user
used to access the URL. | 
| CDL.Logging.URL.RefererProtocol | Number | The protocol used in the HTTP REFERER header field. | 
| CDL.Logging.URL.RefererPort | Number | The port used in the HTTP REFERER header field. | 
| CDL.Logging.URL.RefererFQDN | String | The full domain name used in the HTTP REFERER
header field. | 
| CDL.Logging.URL.RefererURL | String | The url used in the HTTP REFERER header field. | 
| CDL.Logging.URL.SrcUser | String | The username that initiated the network traffic. | 
| CDL.Logging.URL.SrcUserInfo | String | The initiated user info. | 
| CDL.Logging.URL.DstUser | String | The username to which the network traffic was destined. | 
| CDL.Logging.URL.DstUserInfo | String | The destination user info. | 
| CDL.Logging.URL.TechnologyOfApp | String | The networking technology used by the identified application. | 


#### Command Example
```!cdl-query-url-logs action="alert" ip="1.1.1.1" limit="1"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "URL": [
                {
                    "Action": "alert",
                    "App": "web-browsing",
                    "AppCategory": "general",
                    "AppSubcategory": "",
                    "Category": "unknown",
                    "ContentType": null,
                    "Denied": false,
                    "DestinationIP": "1.1.1.1",
                    "DestinationLocation": "TH",
                    "DestinationPort": 200,
                    "DstUser": null,
                    "DstUserInfo": null,
                    "FromZone": "TapZone",
                    "HTTPMethod": "get",
                    "LogSourceName": "gw",
                    "LogTime": "2019-12-04T02:00:19",
                    "PcapID": 0,
                    "Protocol": "tcp",
                    "RefererFQDN": null,
                    "RefererPort": null,
                    "RefererProtocol": null,
                    "RefererURL": null,
                    "RuleMatched": "taplog",
                    "SessionID": 123456,
                    "Severity": "Informational",
                    "SourceIP": "2.2.2.2",
                    "SourceLocation": "",
                    "SourcePort": 100,
                    "SrcUser": null,
                    "SrcUserInfo": null,
                    "Subtype": "url",
                    "TechnologyOfApp": "browser-based",
                    "ThreatCategory": null,
                    "ThreatName": null,
                    "ToZone": "TapZone",
                    "URI": "abcdkcaxusaqu8wmjfs47qeyiyff8f7ob0ukbz5rsr8swlxtrv9a0hdpxgxu/",
                    "URL": "abcxahqpvjjhylnwmscezdw1npk96rkjru",
                    "UserAgent": null
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logs url table
>|Action|Application|Destination Address|RuleMatched|Source Address|TimeGenerated|
>|---|---|---|---|---|---|
>| alert | web-browsing | 1.1.1.1 | taplog | 2.2.2.2 | 2019-12-04T02:00:04 |

