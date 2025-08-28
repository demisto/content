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
| log_type | The log type. Options: threat, traffic, wildfire, url, data, corr, system, decryption. |
| url_category | Filters logs by a specific URL category. Optional values are: Malware, Phishing, Command and Control, Dynamic DNS, Encrypted DNS, Parked, Unknown, Newly Registered Domains, Grayware, Hacking, Proxy Avoidance And Anonymizers, Ransomware, Scanning Activity, Artificial Intelligence, High Risk, Compromised Website. This argument cannot be used in combination with the following arguments: time-generated, time-generated-after, addr-src, addr-dst, zone-src, zone-dst, action, port-dst, rule, url, filedigest. It can only be used with log_type set to "url". For all other log_type values, this argument is ignored. |
| time_generated | The time the log was generated from the timestamp and prior to it.<br/>For example "2019/08/11 01:10:44, will get logs before the specified date.". |
| time_generated_after | The time the log was generated from the timestamp and prior to it.<br/>For example "2019/08/11 01:10:44", will get logs after the specified date. |
| addr_src | The source address. |
| addr_dst | The destination address. |
| ip | The source or destination IP address. |
| zone_src | The source zone. |
| zone_dst | The destination source. |
| action | The rule action. |
| port_dst | The destination port. |
| rule | The rule name, for example "Allow all outbound". |
| url | The URL, for example "safebrowsing.googleapis.com". |
| filedigest | The file hash \(for WildFire logs only\). |
| number_of_logs | The maximum number of logs to retrieve. If empty, the default is 100. The maximum is 5,000. |
| show_detail | Whether to show only \`after-change-preview\`, and \`before-change-preview\`, or get full data for it.  The full data are under the fields \`after-change-detail\`, and \`before-change-detail\`. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.Monitor.JobID | The job ID of the logs query. | String |
| Panorama.Monitor.Status | The status of the logs query. | String |
| Panorama.Monitor.Message | The message of the logs query. | String |
| Panorama.Monitor.Logs.Action | The action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". | String |
| Panorama.Monitor.Logs.Application | The application associated with the session. | String |
| Panorama.Monitor.Logs.Category | The URL category of the URL subtype. For WildFire subtype, it is the verdict on the file, and can be either "malicious", "phishing", "grayware", or "benign". For other subtypes, the value is "any". | String |
| Panorama.Monitor.Logs.DeviceName | The hostname of the firewall on which the session was logged. | String |
| Panorama.Monitor.Logs.DestinationAddress | The original session destination IP address. | String |
| Panorama.Monitor.Logs.DestinationUser | The username of the user to which the session was destined. | String |
| Panorama.Monitor.Logs.DestinationCountry | The destination country or internal region for private addresses. Maximum length is 32 bytes. | String |
| Panorama.Monitor.Logs.DestinationPort | The destination port utilized by the session. | String |
| Panorama.Monitor.Logs.FileDigest | Only for the WildFire subtype, all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service. | String |
| Panorama.Monitor.Logs.FileName | File name or file type when the subtype is file.<br/>File name when the subtype is virus.<br/>File name when the subtype is wildfire-virus.<br/>File name when the subtype is wildfire. | String |
| Panorama.Monitor.Logs.FileType | Only for the WildFire subtype, all other types do not use this field.<br/>Specifies the type of file that the firewall forwarded for WildFire analysis. | String |
| Panorama.Monitor.Logs.FromZone | The zone from which the session was sourced. | String |
| Panorama.Monitor.Logs.URLOrFilename | The actual URL when the subtype is url.<br/>The file name or file type when the subtype is file.<br/>The file name when the subtype is virus.<br/>The file name when the subtype is wildfire-virus.<br/>The file name when the subtype is wildfire.<br/>The URL or file name when the subtype is vulnerability \(if applicable\). | String |
| Panorama.Monitor.Logs.NATDestinationIP | The post-NAT destination IP address if destination NAT was performed. | String |
| Panorama.Monitor.Logs.NATDestinationPort | The post-NAT destination port. | String |
| Panorama.Monitor.Logs.NATSourceIP | The post-NAT source IP address if source NAT was performed. | String |
| Panorama.Monitor.Logs.NATSourcePort | The post-NAT source port. | String |
| Panorama.Monitor.Logs.PCAPid | The packet capture \(pcap\) ID is a 64 bit unsigned integral denoting<br/>an ID to correlate threat pcap files with extended pcaps taken as a part of<br/>that flow. All threat logs will contain either a pcap_id of 0 \(no associated<br/>pcap\), or an ID referencing the extended pcap file. | String |
| Panorama.Monitor.Logs.IPProtocol | The IP protocol associated with the session. | String |
| Panorama.Monitor.Logs.Recipient | Only for the WildFire subtype, all other types do not use this field.<br/>Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | String |
| Panorama.Monitor.Logs.Rule | The name of the rule that the session matched. | String |
| Panorama.Monitor.Logs.RuleID | The ID of the rule that the session matched. | String |
| Panorama.Monitor.Logs.ReceiveTime | The time the log was received at the management plane. | String |
| Panorama.Monitor.Logs.Sender | Only for the WildFire subtype; all other types do not use this field.<br/>Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | String |
| Panorama.Monitor.Logs.SessionID | An internal numerical identifier applied to each session. | String |
| Panorama.Monitor.Logs.DeviceSN | The serial number of the firewall on which the session was logged. | String |
| Panorama.Monitor.Logs.Severity | The severity associated with the threat. Can be "informational", "low",<br/>"medium", "high", or "critical". | String |
| Panorama.Monitor.Logs.SourceAddress | The original session source IP address. | String |
| Panorama.Monitor.Logs.SourceCountry | The source country or internal region for private addresses. Maximum<br/>length is 32 bytes. | String |
| Panorama.Monitor.Logs.SourceUser | The username of the user who initiated the session. | String |
| Panorama.Monitor.Logs.SourcePort | The source port utilized by the session. | String |
| Panorama.Monitor.Logs.ThreatCategory | The threat categories used to classify different types of<br/>threat signatures. | String |
| Panorama.Monitor.Logs.Name | The Palo Alto Networks identifier for the threat. A description<br/>string followed by a 64-bit numerical identifier. | String |
| Panorama.Monitor.Logs.ID | The Palo Alto Networks ID for the threat. | String |
| Panorama.Monitor.Logs.ToZone | The zone to which the session was destined. | String |
| Panorama.Monitor.Logs.TimeGenerated | The time the log was generated on the data plane. | String |
| Panorama.Monitor.Logs.URLCategoryList | A list of the URL filtering categories the firewall used to<br/>enforce the policy. | String |
| Panorama.Monitor.Logs.Bytes | The total log bytes. | String |
| Panorama.Monitor.Logs.BytesReceived | The log bytes received. | String |
| Panorama.Monitor.Logs.BytesSent | The log bytes sent. | String |
| Panorama.Monitor.Logs.Vsys | The VSYS on the firewall that generated the log. | String |
