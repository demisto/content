A polling wrapper script; This script searches Palo Alto Networks firewall logs across eight different log types (threat, traffic, wildfire, URL, data, correlation, system, and decryption). It provides flexible filtering capabilities including IP addresses, time ranges, network zones, rules, ports, URLs, file hashes, and custom query strings, with configurable result limits up to 5,000 logs. This enables security teams to efficiently investigate network activity, analyze traffic patterns, and perform forensic analysis across their Panorama and Firewall infrastructure through automated log retrieval. This script depends on the Panorama integration and can be executed against either a Firewall device or a Panorama device, depending on the configured integration instance.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| log-type | The log type. Options: threat, traffic, wildfire, url, data, corr, system, decryption. |
| url_category | Use a value from the URL Category list such as Malware, Phishing, AI Conversational Assistant, etc. to query URL logs. This argument cannot be used in combination with the following arguments: time-generated, time-generated-after, addr-src, addr-dst, zone-src, zone-dst, action, port-dst, rule, url, filedigest. |
| time-generated | The time the log was generated from the timestamp and prior to it. For example "2019/08/11 01:10:44, will get logs before the specified date.". |
| time-generated-after | The time the log was generated from the timestamp and prior to it. For example "2019/08/11 01:10:44", will get logs after the specified date. |
| addr-src | The source address. |
| addr-dst | The destination address. |
| ip | The source or destination IP address. |
| zone-src | The source zone. |
| zone-dst | The destination source. |
| action | The rule action. |
| port-dst | The destination port. |
| rule | The rule name, for example "Allow all outbound". |
| url | The URL, for example "safebrowsing.googleapis.com". |
| filedigest | The file hash (for WildFire logs only). |
| number_of_logs | The maximum number of logs to retrieve. If empty, the default is 100. The maximum is 5,000. Default: 100. |
| show-detail | Whether to show only `after-change-preview`, and `before-change-preview`, or get full data for it. The full data are under the fields `after-change-detail`, and `before-change-detail`. Default: no. |

## Outputs

---

| **Context Path** | **Type** | **Description** |
| --- | --- | --- |
| Panorama.Monitor.JobID | String | The job ID of the logs query. |
| Panorama.Monitor.Status | String | The status of the logs query. |
| Panorama.Monitor.Message | String | The message of the logs query. |
| Panorama.Monitor.Logs.Action | String | The action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". |
| Panorama.Monitor.Logs.Application | String | The application associated with the session. |
| Panorama.Monitor.Logs.Category | String | The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware", or "benign". For other subtypes, the value is "any". |
| Panorama.Monitor.Logs.DeviceName | String | The hostname of the firewall on which the session was logged. |
| Panorama.Monitor.Logs.DestinationAddress | String | The original session destination IP address. |
| Panorama.Monitor.Logs.DestinationUser | String | The username of the user to which the session was destined. |
| Panorama.Monitor.Logs.DestinationCountry | String | The destination country or internal region for private addresses. Maximum length is 32 bytes. |
| Panorama.Monitor.Logs.DestinationPort | String | The destination port utilized by the session. |
| Panorama.Monitor.Logs.FileDigest | String | Only for the WildFire subtype, all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service. |
| Panorama.Monitor.Logs.FileName | String | File name or file type when the subtype is file. File name when the subtype is virus. File name when the subtype is wildfire-virus. File name when the subtype is wildfire. |
| Panorama.Monitor.Logs.FileType | String | Only for the WildFire subtype, all other types do not use this field. Specifies the type of file that the firewall forwarded for WildFire analysis. |
| Panorama.Monitor.Logs.FromZone | String | The zone from which the session was sourced. |
| Panorama.Monitor.Logs.URLOrFilename | String | The actual URL when the subtype is url. The file name or file type when the subtype is file. The file name when the subtype is virus. The file name when the subtype is wildfire-virus. The file name when the subtype is wildfire. The URL or file name when the subtype is vulnerability (if applicable). |
| Panorama.Monitor.Logs.NATDestinationIP | String | The post-NAT destination IP address if destination NAT was performed. |
| Panorama.Monitor.Logs.NATDestinationPort | String | The post-NAT destination port. |
| Panorama.Monitor.Logs.NATSourceIP | String | The post-NAT source IP address if source NAT was performed. |
| Panorama.Monitor.Logs.NATSourcePort | String | The post-NAT source port. |
| Panorama.Monitor.Logs.PCAPid | String | The packet capture (pcap) ID is a 64 bit unsigned integral denoting an ID to correlate threat pcap files with extended pcaps taken as a part of that flow. All threat logs will contain either a pcap_id of 0 (no associated pcap), or an ID
