## Overview
---

Palo Alto Networks Strata Logging Service XSOAR Connector provides cloud-based, centralized log storage and aggregation for your on premise, virtual (private cloud and public cloud) firewalls, for Prisma Access, and for cloud-delivered services such as Cortex XDR.
This integration was integrated and tested with version 2 of Strata Logging Service XSOAR Connector.

---

## Configure Strata Logging Service XSOAR Connector on Cortex XSOAR
---

1. Go to the Palo Alto Networks [HUB](https://apps.paloaltonetworks.com/apps) and select and add the **Cortex XSOAR** app as described [here](https://docs.paloaltonetworks.com/hub/hub-getting-started/get-started/accessing-applications.html).
The following screen will appear:

   ![image](https://github.com/demisto/content-docs/blob/master/docs/doc_imgs/integrations/cdl-authorization.png?raw=true)

2. In the Palo Alto Networks Cortex XSOAR Playground or War Room, run the ***!GetLicenseID*** command to get the License ID.
The License ID will be used in Step 4.
3. (Cortex XOAR 6.x) Go to __Settings__ > __ABOUT__ > __License__ and get the value in the license field Customer name. 
   
   (Cortex xSOAR 8, Administrators only ) Go to __Profile__ > __ABOUT__ and get the value in the license field Customer name.

   The Customer name will be used in Step 4.
   
5. In the Palo Alto Networks HUB, enter the License ID and the Customer name in the screen obtained in Step 1. The License ID and Customer name were obtained in Steps 2 and 3. Click **Start Authorization Process** to get the Authentication Token, Registration ID, and Encryption Key - these three fields will be used in the Palo Alto Networks Cortex v2 integration instance in Step 7 below.
6. In Palo Alto Networks Cortex XSOAR, navigate to __Settings__ > __Integrations__ > __Servers & Services__.
7. Search for Strata Logging Service XSOAR Connector.
8. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Authentication Token__: Retrieved in the authentication process in Step 4.
    * __Registration ID__: Retrieved in the authentication process in Step 4.
    * __Encryption Key__: Retrieved in the authentication process in Step 4.
    * __Fetch incidents__: Whether to fetch incidents or not.
    * __first_fetch_timestamp__: First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year).
    * __Fetch Table__: Choose the table from which incidents will be fetched.
    * __Severity of events to fetch (Firewall)__: Select from all, Critical, High, Medium,Low, Informational, Unused.
    * __Subtype of events to fetch (Firewall)__: Select from all, attack, url, virus, spyware, vulnerability, file, scan, flood, packet, resource, data, url-content, wildfire, extpcap, wildfire-virus, http-hdr-insert, http-hdr, email-hdr, spyware-dns, spyware-wildfire-dns, spyware-wpc-dns, spyware-custom-dns, spyware-cloud-dns, spyware-raven, spyware-wildfire-raven, spyware-wpc-raven, wpc-virus,sctp
    * __Fetch Fields__: Comma-separated fields that will be fetched with every incident, e.g., "pcap,session_id". Enter "*" for all possible fields.
    * __Fetch Filter__: Specify the filter that should be used to fetch incidents. Can not be used in combination with the Subtype and Severity parameters.
    * __Incidents fetched per query__: How many incidents will be fetched per query. Caution: high number could create overload. Default is 10.
    * __proxy__: Use system proxy settings.
    * __insecure__: Trust any certificate (not secure).
4. Click __Test__ to validate the URLs, token, and connection.

In order for the integration to work, the following URLs need to be accessible:

 - For authentication: 
   - `oproxy.demisto.ninja`
   - `api.paloaltonetworks.com `
 - For API requests, one of the following:
   - US: `api.us.cdl.paloaltonetworks.com`
   - EU: `api.nl.cdl.paloaltonetworks.com`

## Fetched Incidents Data
The integration can fetch incidents from the following tables:
- firewall.auth
- firewall.decryption
- firewall.extpcap
- firewall.file_data
- firewall.globalprotect
- firewall.hipmatch
- firewall.iptag
- firewall.threat
- firewall.traffic
- firewall.url
- firewall.userid
- log.system
- log.config


## CDL Server - API Calls Caching Mechanism
The integration implements a caching mechanism for repetitive error when requesting access token from CDL server.
When the integration reaches the limit of allowed calls, the following error will be shown:

```We have found out that your recent attempts to authenticate against the CDL server have failed. Therefore we have limited the number of calls that the CDL integration performs.```

The integration will re-attempt authentication if the command was called under the following cases:

1. First hour - once every minute.
2. First 48 hours - once in 10 minutes.
3. After that every 60 minutes.

If you wish to try authenticating again, run the 'cdl-reset-authentication-timeout' command and retry.


---
## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cdl-query-logs
2. cdl-get-critical-threat-logs
3. cdl-get-social-applications
4. cdl-search-by-file-hash
5. cdl-query-traffic-logs
6. cdl-query-threat-logs
7. cdl-query-url-logs
8. cdl-query-file-data

### 1. cdl-query-logs

Runs a query on the Cortex logging service.

##### Base Command

`cdl-query-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A free-text SQL query. For example, query="SELECT * FROM \`firewall.traffic\` limit 10". There are multiple tables in Loggings, for example: threat, traffic, and so on. Refer to the Cortex Logging service schema reference for the full list. | Optional |
| limit | The number of logs to return. Default is 10 | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| transform_results | If set to false, query results are not mapped into the standard command context. Default is "true". | Optional | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.App | String | Application associated with the network traffic. | 
| CDL.Logging.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.CharacteristicOfApp | Number | Identifies the behavioral characteristic of the application associated with the network traffic. | 
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
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| time_range | First log time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.Nat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, which is identified in category_of_app. | 
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
| CDL.Logging.Threat.CharacteristicOfApp | String | Identifies the behavioral characteristic of the application associated with the network traffic. | 
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
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| time_range | First log time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Traffic.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Traffic.RiskOfApp | String | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Traffic.NatSourcePort | String | Post-NAT source port. | 
| CDL.Logging.Traffic.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Traffic.Packets | String | Number of total packets (transmit and receive) seen for the session. | 
| CDL.Logging.Traffic.CharacteristicOfApp | String | Identifies the behavioral characteristic of the application associated with the network traffic. | 
| CDL.Logging.Traffic.App | String | Application associated with the network traffic. | 
| CDL.Logging.Traffic.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Traffic.IsNat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Traffic.LogTime | date | Time the log was received in Strata Logging Service XSOAR Connector. | 
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
| CDL.Logging.Traffic.LogSourceID | String | ID that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
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
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| time_range | First log time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| SHA256 | The SHA256 hash of the file for the query. For example, SHA256="503ca1a4fc0d48b18c0336f544ba0f0abf305ae3a3f49b3c2b86b8645d6572dc" would return all logs associated with this file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.Nat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, which is identified in category_of_app. | 
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
| CDL.Logging.Threat.CharacteristicOfApp | String | Identifies the behavioral characteristic of the application associated with the network traffic. | 
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
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or a comma separated list of specific fields in the table.  | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00". | Optional | 
| time_range | First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| dest_ip | A destination IP address or an array of destination IPs addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| dest_port | Destination port utilized by the session. Can be port number or an array of destination port numbers to search. For example '443' or '443,445' | Optional | 
| ip | IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| port | Port utilized by the session. Enter a port or array of ports to search. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Traffic.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Traffic.RiskOfApp | String | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.Traffic.NatSourcePort | String | Post-NAT source port. | 
| CDL.Logging.Traffic.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Traffic.Packets | String | Number of total packets (transmit and receive) seen for the session. | 
| CDL.Logging.Traffic.CharacteristicOfApp | String | Identifies the behavioral characteristic of the application associated with the network traffic. | 
| CDL.Logging.Traffic.App | String | Application associated with the network traffic. | 
| CDL.Logging.Traffic.Vsys | String | Virtual system associated with the network traffic. | 
| CDL.Logging.Traffic.IsNat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Traffic.LogTime | date | Time the log was received in Strata Logging Service XSOAR Connector. | 
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
| CDL.Logging.Traffic.LogSourceID | String | ID that uniquely identifies the source of the log. If the source is a firewall, this is its serial number. | 
| CDL.Logging.Traffic.TotalBytes | String | Number of total bytes (transmit and receive). | 
| CDL.Logging.Traffic.VsysID | String | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.Traffic.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.Traffic.URLCategory | String | The URL category. | 
| CDL.Logging.Traffic.SourcePort | String | Source port utilized by the session. | 
| CDL.Logging.Traffic.Tunnel | String | Type of tunnel. | 
| CDL.Logging.Traffic.SourceDeviceHost | String | Hostname of the device from which the session originated. |
| CDL.Logging.Traffic.DestDeviceHost | String | Hostname of the device session destination.


##### Command Example
```!cdl-query-traffic-logs action="allow" fields="vendor_name,log_source,rule_matched,dest_location,log_time" time_range="10 days" limit="5"```

```!cdl-query-traffic-logs query="log_source_id = '{firewall_target}'" fields=all limit=5 start_time="2018-07-13 00:00:00"```
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
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputted fields with all. | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| time_range | First fetch time (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| ip | IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| port | Port utilized by the session. Enter a port or array of ports to search. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.Threat.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.Threat.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.Threat.App | String | Application associated with the network traffic. | 
| CDL.Logging.Threat.Nat | String | Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1. | 
| CDL.Logging.Threat.SubcategoryOfApp | String | Identifies the application's subcategory. The subcategory is related to the application's category, which is identified in category_of_app. | 
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
| CDL.Logging.Threat.CharacteristicOfApp | String | Identifies the behavioral characteristic of the application associated with the network traffic. | 
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
| CDL.Logging.Threat.SourceDeviceHost | String | Hostname of the device from which the session originated. |
| CDL.Logging.Threat.DestDeviceHost | String | Hostname of the device session destination. |
| IP.Address | String | IP address. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name (including file extension). | 
| File.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 


##### Command Examples
```!cdl-query-threat-logs query="is_packet_capture = true AND severity = \"Critical\"" fields=pcap limit=10```
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

### 7. cdl-query-url-logs

---
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
| fields | The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputted fields with all. | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00" | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00" | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | Optional | 
| limit | The number of logs to return. Default is 5. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 
| ip | IP address. Enter an IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2. | Optional | 
| port | Port utilized by the session. Enter a port or array of ports to search. | Optional | 
| url | This argument allows to perform a LIKE search of the specified values on the Url and Uri fields An example value will be paloaltonetworks.com,demisto which will provide results like https://apps.paloaltonetworks.com and https://demisto.com | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.URL.SessionID | String | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.URL.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.URL.App | String | Application associated with the network traffic. | 
| CDL.Logging.URL.PcapID | String | Packet capture \(pcap\) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap\_id of 0 \(no associated pcap\) , or an ID referencing the extended pcap file. | 
| CDL.Logging.URL.DestinationPort | String | Network traffic's destination port. If this value is 0, then the app is using its standard port. | 
| CDL.Logging.URL.AppCategory | String | Identifies the high\-level family of the application. | 
| CDL.Logging.URL.AppSubCategory | String | Identifies the application's subcategory. The subcategory is related to the application's category, which is identified in category\_of\_app. | 
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
| CDL.Logging.URL.LogTime | String | Time the log was received in Strata Logging Service XSOAR Connector. | 
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
| CDL.Logging.URL.SourceDeviceHost | String | Hostname of the device from which the session originated. |
| CDL.Logging.URL.DestDeviceHost | String | Hostname of the device session destination. |


#### Command Example
```!cdl-query-url-logs action="alert" ip=1.1.1.1 limit="1"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "URL": [
                {
                    "Action": "alert",
                    "App": "web-browsing",
                    "AppCategory": "general-internet",
                    "AppSubcategory": "internet-utility",
                    "Category": "unknown",
                    "ContentType": null,
                    "Denied": false,
                    "DestinationIP": "1.1.1.1",
                    "DestinationLocation": "TH",
                    "DestinationPort": 80,
                    "DstUser": null,
                    "DstUserInfo": null,
                    "FromZone": "TapZone",
                    "HTTPMethod": "get",
                    "LogSourceName": "gw",
                    "LogTime": "2019-11-04T02:00:19",
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
                    "SourceLocation": "2.0.0.0-10.255.255.255",
                    "SourcePort": 123,
                    "SrcUser": null,
                    "SrcUserInfo": null,
                    "Subtype": "url",
                    "TechnologyOfApp": "browser-based",
                    "ThreatCategory": null,
                    "ThreatName": null,
                    "ToZone": "TapZone",
                    "URI": "eujea0rudykqgbvianr5lqfgrykbufbamkeyizdw1npk96zax5c4h8sbxs1kgqx31nwp5jsfsgif8iorqvjocpnyff8f7ob0ukbz5rsr8swlxtrv9a0hdppm8rkjrh8hopy3dhb0lxlah9myxx70qxwtipjeufremdmg8m3vyxgxu/",
                    "URL": "kcaxusaqu8wmjfs47qnnxw7wikiwteujea0rudykqgbvianr5lqfgrykbufbamkeyizdw1npk96zax5c4h8sbxs1kgqx31nwp5jsfsgif8iorqvjocpnyff8f7ob0ukbz5rsr8swlxtrv9a0hdppm8rkjrh8hopy3dhb0lxlah9myxx70qxwtipjeufremdmg8m3vyxgxu",
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
>| alert | web-browsing | 1.1.1.1 | taplog | 2.2.2.2 | 2019-11-04T02:00:04 |


### cdl-query-file-data

***
Searches the Cortex firewall.file_data table.

#### Base Command

`cdl-query-file-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Identifies the action that the firewall took for the network traffic. Possible values are: unknown, n-a, aged-out, decoder, tcp-reuse, resources-unavailable, tcp-fin, tcp-rst-from-server, tcp-rst-from-client, policy-deny, threat, decrypt-error, decrypt-unsupport-param, decrypt-cert-validation, request-timeout, shutdown-from-endpoint, abort-from-endpoint, split-tunnel. | Optional | 
| app | Application associated with the network traffic. | Optional | 
| app_category | Identifies the high-level family of the application. | Optional | 
| dest_device_host | Hostname of the device to which the session was directed. | Optional | 
| dest_ip | Original destination IP address. | Optional | 
| dest_edl | The name of the external dynamic list that contains the destination IP address of the traffic. | Optional | 
| dest_dynamic_address_group | The dynamic address group that Device-ID identifies as the destination for the traffic. | Optional | 
| dest_location | Destination country or internal region for private addresses. | Optional | 
| dest_port | Network traffic's destination port. If this value is 0, then the app is using<br/>its standard port. | Optional | 
| dest_user | The username to which the network traffic was destined. | Optional | 
| file_name | The name of the file that is blocked. | Optional | 
| file_sha_256 | The binary hash (SHA256) of the file. | Optional | 
| file_type | Palo Alto Networks textual identifier for the threat. | Optional | 
| from_zone | The networking zone from which the traffic originated. | Optional | 
| is_server_to_client | Indicates if direction of traffic is from server to client. | Optional | 
| is_url_denied | Indicates whether the session was denied due to a URL filtering rule. | Optional | 
| log_type | Identifies the log type. | Optional | 
| nat_dest | If destination NAT performed, the post-NAT destination IP address. | Optional | 
| nat_dest_port | Post-NAT destination port. | Optional | 
| nat_source | If source NAT was performed, the post-NAT source IP address. | Optional | 
| nat_source_port | Post-NAT source port. | Optional | 
| rule_matched | Name of the security policy rule that the network traffic matched. | Optional | 
| rule_matched_uuid | Unique identifier for the security policy rule that the network traffic matched. | Optional | 
| severity | Severity as defined by the platform. | Optional | 
| source_device_host | Hostname of the device from which the session originated. | Optional | 
| source_ip | Original source IP address. | Optional | 
| source_edl | The name of the external dynamic list that contains the source IP address of the traffic. | Optional | 
| source_dynamic_address_group | The dynamic address group that Device-ID identifies as the source of the traffic. | Optional | 
| source_location | Source country or internal region for private addresses. | Optional | 
| source_port | Source port utilized by the session. | Optional | 
| source_user | The username that initiated the network traffic. | Optional | 
| sub_type | Identifies the log subtype. | Optional | 
| url_category | The URL category. | Optional | 
| url_domain | The name of the internet domain that was visited in this session. | Optional | 
| start_time | The query start time. For example, start_time="2018-04-26 00:00:00". | Optional | 
| end_time | The query end time. For example, end_time="2018-04-26 00:00:00". | Optional | 
| time_range | First log time (&lt;number&gt; &lt;time unit&gt;. For example, 12 minutes, 7 days, 3 weeks). | Optional | 
| limit | Limit the results to return. The default is 5. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 50 (in case only page was provided). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CDL.Logging.File.App | String | Application associated with the network traffic. | 
| CDL.Logging.File.TimeGenerated | Date | Time when the log was generated on the firewall's data plane. | 
| CDL.Logging.File.SourceIP | String | Original source IP address. | 
| CDL.Logging.File.DestinationLocation | String | Destination country or internal region for private addresses. | 
| CDL.Logging.File.FileSHA256 | String | The binary hash \(SHA256\) of the file. | 
| CDL.Logging.File.FileName | String | The name of the file that is blocked. | 
| CDL.Logging.File.RuleMatched | String | Name of the security policy rule that the network traffic matched. | 
| CDL.Logging.File.LogSourceName | String | Name of the source of the log - hostname of the firewall that logged the network traffic. | 
| CDL.Logging.File.NatDestination | String | If destination NAT performed, the post-NAT destination IP address. | 
| CDL.Logging.File.NatDestinationPort | Number | Post-NAT destination port. | 
| CDL.Logging.File.CharacteristicOfApp | String | Identifies the behavioral characteristic of the application associated with the network traffic. | 
| CDL.Logging.File.SourceLocation | String | Source country or internal region for private addresses. | 
| CDL.Logging.File.DestinationIP | String | Original destination IP address. | 
| CDL.Logging.File.Action | String | Identifies the action that the firewall took for the network traffic. | 
| CDL.Logging.File.IsNat | Boolean | Indicates if the firewall is performing network address translation \(NAT\) for the logged traffic. | 
| CDL.Logging.File.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.File.NatSource | String | If source NAT was performed, the post-NAT source IP address. | 
| CDL.Logging.File.AppCategory | String | Identifies the high-level family of the application. | 
| CDL.Logging.File.IsUrlDenied | Boolean | Indicates whether the session was denied due to a URL filtering rule. | 
| CDL.Logging.File.IsTunnelInspected | Boolean | Indicates whether the payload for the outer tunnel was inspected. | 
| CDL.Logging.File.SequenceNo | Number | The log entry identifier, which is incremented sequentially. | 
| CDL.Logging.File.IsDecryptMirror | Boolean | Indicates whether decrypted traffic was sent out in clear text through a mirror port. | 
| CDL.Logging.File.IsNonStdDestPort | Boolean | Indicates if the destination port is non-standard. | 
| CDL.Logging.File.RuleMatchedUuid | String | Unique identifier for the security policy rule that the network traffic matched. | 
| CDL.Logging.File.IsProxy | Boolean | Indicates whether the SSL session is decrypted \(SSL Proxy\). | 
| CDL.Logging.File.VendorSeverity | String | Severity associated with the event. | 
| CDL.Logging.File.IsPhishing | Boolean | Indicates whether enterprise credentials were submitted by an end user. | 
| CDL.Logging.File.ToZone | String | Networking zone to which the traffic was sent. | 
| CDL.Logging.File.Flags | Number | Bit field which provides details on the session, such as whether the session use IPv6. | 
| CDL.Logging.File.Tunnel | String | Type of tunnel. | 
| CDL.Logging.File.CloudHostname | String | The hostname in which the VM-series firewall is running. | 
| CDL.Logging.File.Http2Connection | Number | Parent session ID for an HTTP/2 connection. If the traffic is not using HTTP/2, this field is set to 0. | 
| CDL.Logging.File.IsPrismaBranch | Boolean | Internal-use field. If set to 1, the log was generated on a cloud-based firewall. If 0, the firewall was running on-premise. | 
| CDL.Logging.File.OutboundIf | String | Interface to which the network traffic was destined. | 
| CDL.Logging.File.IsSymReturn | Boolean | Indicates whether symmetric return was used to forward traffic for this session. | 
| CDL.Logging.File.URLCategory | String | The URL category. | 
| CDL.Logging.File.IsReconExcluded | Boolean | Indicates whether source for the flow is on the firewall allow list and not subject to recon protection. | 
| CDL.Logging.File.SanctionedStateOfApp | Boolean | Indicates whether the application has been flagged as sanctioned by the firewall administrator. | 
| CDL.Logging.File.ReportID | Number | Identifies the analysis requested from the sandbox \(cloud or appliance\). | 
| CDL.Logging.File.DestinationPort | Number | Network traffic's destination port. If this value is 0, then the app is using
its standard port. | 
| CDL.Logging.File.IsDupLog | Boolean | Indicates whether this log data is available in multiple locations, such as from Strata Logging Service XSOAR Connector as well as from an on-premise log collector. | 
| CDL.Logging.File.LogTime | Date | Time the log was received in Strata Logging Service XSOAR Connector. | 
| CDL.Logging.File.SessionID | Number | Identifies the firewall's internal identifier for a specific network session. | 
| CDL.Logging.File.RecordSize | Number | Record size. | 
| CDL.Logging.File.IngestionTime | Date | Ingestion time of the log. | 
| CDL.Logging.File.CountOfRepeats | Number | Number of sessions with same Source IP, Destination IP, Application, and Content/Threat Type seen for the summary interval. | 
| CDL.Logging.File.VsysID | Number | A unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.File.VendorName | String | Identifies the vendor that produced the data. | 
| CDL.Logging.File.IsMptcpOn | Boolean | Indicates whether the option is enabled on the next-generation firewall that allows a client to use multiple paths to connect to a destination host. | 
| CDL.Logging.File.IsClientToServer | Boolean | Indicates if direction of traffic is from client to server. | 
| CDL.Logging.File.IsServerToClient | Boolean | Indicates if direction of traffic is from server to client. | 
| CDL.Logging.File.IsPacketCapture | Boolean | Indicates whether the session has a packet capture \(PCAP\). | 
| CDL.Logging.File.IsTransaction | Boolean | Indicates whether the log corresponds to a transaction within an HTTP proxy session \(Proxy Transaction\). | 
| CDL.Logging.File.InboundIf | String | Interface from which the network traffic was sourced. | 
| CDL.Logging.File.FromZone | String | The networking zone from which the traffic originated. | 
| CDL.Logging.File.FileType | String | Palo Alto Networks textual identifier for the threat. | 
| CDL.Logging.File.IsPrismaMobile | Boolean | Internal use field. If set to 1, the log record was generated using a cloud-based GlobalProtect instance. If 0, GlobalProtect was hosted on-premise. | 
| CDL.Logging.File.IsContainer | Boolean | Indicates if the session is a container page access \(Container Page\). | 
| CDL.Logging.File.IsSaasApp | Boolean | Internal use field. Indicates whether the application associated with this network traffic is a SAAS application. | 
| CDL.Logging.File.Vsys | String | Unique identifier for a virtual system on a Palo Alto Networks firewall. | 
| CDL.Logging.File.IsNat | Boolean | Indicates if the firewall is performing network address translation \(NAT\) for the logged traffic. | 
| CDL.Logging.File.FileID | Number | Numerical identifier for the threat type. | 
| CDL.Logging.File.IsCaptivePortal | Boolean | Indicates if user information for the session was captured through Captive Portal. | 
| CDL.Logging.File.Protocol | String | IP protocol associated with the session. | 
| CDL.Logging.File.CustomerID | Number | The ID that uniquely identifies the Strata Logging Service XSOAR Connector instance which received this log record. | 
| CDL.Logging.File.Subtype | String | Identifies the log subtype. | 
| CDL.Logging.File.TunneledApp | String | Tunneled app \(For internal use only\). | 
| CDL.Logging.File.LogSourceID | String | ID that uniquely identifies the source of the log - serial number of the firewall that generated the log. | 
| CDL.Logging.File.IsForwarded | Boolean | Internal-use field that indicates if the log is being forwarded. | 
| CDL.Logging.File.RiskOfApp | Number | Indicates how risky the application is from a network security perspective. | 
| CDL.Logging.File.PcapID | Number | Packet capture ID. | 
| CDL.Logging.File.AppSubcategory | String | Identifies the application's subcategory. | 
| CDL.Logging.File.IsExported | Boolean | Indicates if this log was exported from the firewall using the firewall's log export function. | 
| CDL.Logging.File.Severity | String | Severity as defined by the platform. | 
| CDL.Logging.File.NatSourcePort | Number | Post-NAT source port. | 
| CDL.Logging.File.LogType | String | Identifies the log type. | 
| CDL.Logging.File.LogSet | String | Log forwarding profile name that was applied to the session. This name was defined by the firewall's administrator. | 
| CDL.Logging.File.TechnologyOfApp | String | The networking technology used by the identified application. | 
| CDL.Logging.File.DirectionOfAttack | String | Indicates the direction of the attack. | 
| CDL.Logging.File.LogSource | String | Identifies the origin of the data - the system that produced the data. | 


#### Command Example
```!cdl-query-file-data source_ip="10.10.10.101" time_range="6 months" limit="1"```

#### Context Example
```
{
    "CDL": {
        "Logging": {
            "File": [
                {
                    "Action": "alert",
                    "App": "web-browsing",
                    "AppCategory": "general-internet",
                    "AppSubcategory": "internet-utility",
                    "CharacteristicOfApp": [
                        "3",
                        "4",
                        "5",
                        "6",
                        "8"
                    ],
                    "CloudHostname": "CloudHostName",
                    "CountOfRepeats": 1,
                    "CustomerID": "117270019",
                    "DestinationIP": "2.2.2.2",
                    "DestinationLocation": "US",
                    "DestinationPort": 80,
                    "DirectionOfAttack": "server to client",
                    "FileID": 52270,
                    "FileName": "TestFileName",
                    "FileSHA256": null,
                    "FileType": "Google Chrome Extension File",
                    "Flags": 4202496,
                    "FromZone": "LAN",
                    "Http2Connection": 0,
                    "InboundIf": "ethernet",
                    "IngestionTime": 2020-04-21T18:47:31,
                    "IsCaptivePortal": false,
                    "IsClientToServer": false,
                    "IsContainer": false,
                    "IsDecryptMirror": false,
                    "IsDupLog": false,
                    "IsExported": false,
                    "IsForwarded": true,
                    "IsMptcpOn": false,
                    "IsNat": true,
                    "IsNonStdDestPort": false,
                    "IsPacketCapture": false,
                    "IsParismaMobile": null,
                    "IsPhishing": false,
                    "IsPrismaBranch": false,
                    "IsProxy": false,
                    "IsReconExcluded": false,
                    "IsSaasApp": false,
                    "IsServerToClient": false,
                    "IsSymReturn": false,
                    "IsTransaction": false,
                    "IsTunnelInspected": false,
                    "IsUrlDenied": false,
                    "LogSet": "DEFAULT",
                    "LogSource": "firewall",
                    "LogSourceID": "015351000045229",
                    "LogSourceName": "Aristotle",
                    "LogTime": "2020-04-21T18:47:31",
                    "LogType": "threat",
                    "NatDestination": "2.2.2.2",
                    "NatDestinationPort": 80,
                    "NatSource": "3.3.3.3",
                    "NatSourcePort": 12345,
                    "OutboundIf": "ethernet",
                    "PcapID": 0,
                    "Protocol": "tcp",
                    "RecordSize": 3477,
                    "ReportID": 0,
                    "RiskOfApp": 4,
                    "RuleMatched": "INTERNET",
                    "RuleMatchedUuid": "123d644f-7691-437a-8f9b-4567c511bac2",
                    "SanctionedStateOfApp": false,
                    "SequenceNo": 327,
                    "SessionID": 16753,
                    "Severity": "Low",
                    "SourceIP": "10.10.10.101",
                    "Subtype": "file",
                    "TechnologyOfApp": "browser-based",
                    "TimeGenerated": "2020-04-21T18:47:12",
                    "ToZone": "ISP",
                    "Tunnel": "N/A",
                    "TunneledApp": "tunneled-app",
                    "URLCategory": "computer-and-internet-info",
                    "VendorName": "Palo Alto Networks",
                    "VendorSeverity": "Low",
                    "Vsys": "vsys1",
                    "VsysID": 1
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Logs file_data table
>|Action|Application|Destination Address|FileID|FileName|FileType|RuleMatched|Source Address|TimeGenerated|
>|---|---|---|---|---|---|---|---|---|
>| alert | web-browsing | 2.2.2.2 | 52270 | ANindV94kHC673w9zWXj8TY | Google Chrome Extension File | INTERNET | 10.10.10.101 | 2020-04-21T18:47:12 |


### cdl-reset-authentication-timeout
***
Use this command in case your authentication calls fail due to internal call-limit, the command will reset the limit cache.


#### Base Command

`cdl-reset-authentication-timeout`

#### Command Example
```!cdl-reset-authentication-timeout```

#### Human Readable Output
```Caching mechanism failure time counters have been successfully reset.```

## Additional Information

---
* In the documented CDL v2, You must now specify the customer's instance ID when you identify the log type that you want to query
against. That is, log types must be fully qualified and the instance ID is a part of the fully qualified name:
`<instanceID>.firewall.traffic`
However in this integration the instance ID is added automatically to the query so the name `firewall.traffic` is a valid table name
* The SQL syntax supported for queries is `csql`
* The provided authentication items ([configuration step 4](#configure-cortex-data-lake-on-cortex-xsoar)) can only be used once for each Strata Logging Service XSOAR Connector tenant (but can be shared for different Cortex XSOAR instances). Trying to re-generate those items will revoke any previously generated set of authentication items.
