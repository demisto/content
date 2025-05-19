Queries the following PAN-OS log types: traffic, threat, URL, data-filtering and wildfire. The playbook accepts inputs such as IP addresses, hash, and URL.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* pan-os-query-logs

## Playbook Inputs
---

| **Name** | **Description** | **Required** |
| --- | --- | --- | 
| url | The URL. For example, "safebrowsing.googleapis.com". | Optional |
| filedigest | The file hash (for WildFire logs only). |Optional |
| ip | The source or destination address.| Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.Monitor | The monitor logs object. | string |
| Panorama.Monitor.Logs.Action | The action taken for the session. Can be "alert", "allow", "deny", "drop", "drop-all-packets", "reset-client", "reset-server", "reset-both", or "block-url". | string |
| Panorama.Monitor.Logs.Application | The application associated with the session. | string |
| Panorama.Monitor.Logs.Category | For URL subtype, it is the URL category; For WildFire subtype, it is the verdict on the file and is either ‘malicious’, ‘phishing’, ‘grayware’, or ‘benign’; For other subtypes, the value is ‘any’. | string |
| Panorama.Monitor.Logs.DeviceName | The hostname of the firewall on which the session was logged. | string |
| Panorama.Monitor.Logs.DestinationAddress | The original session destination IP address. | string |
| Panorama.Monitor.Logs.DestinationUser | The username of the user to which the session was destined. | string |
| Panorama.Monitor.Logs.DestinationCountry | The destination country or internal region for private addresses. The Maximum length is 32 bytes. | string |
| Panorama.Monitor.Logs.DestinationPort | The destination port utilized by the session. | string |
| Panorama.Monitor.Logs.FileDigest | Only for WildFire subtype; all other types do not use this field. The filedigest string shows the binary hash of the file sent to be analyzed by the WildFire service. | string |
| Panorama.Monitor.Logs.FileName | The file name or file type when the subtype is file. The file name when the subtype is virus. The file name when the subtype is wildfire-virus. The file name when the subtype is wildfire. | string |
| Panorama.Monitor.Logs.FileType | Only for the WildFire subtype; all other types do not use this field. Specifies the type of file that the firewall forwarded for WildFire analysis. | string |
| Panorama.Monitor.Logs.FromZone | The zone the session was sourced from. | string |
| Panorama.Monitor.Logs.URLOrFilename | The actual URI when the subtype is URL. The file name or file type when the subtype is file. The file name when the subtype is virus. The file name when the subtype is wildfire-virus. The file name when the subtype is wildfire. The URL or file name when the subtype is vulnerability if applicable. | string |
| Panorama.Monitor.Logs.NATDestinationIP | Whether the destination NAT performed, the post-NAT destination IP address. | string |
| Panorama.Monitor.Logs.NATDestinationPort | The post-NAT destination port. | string |
| Panorama.Monitor.Logs.NATSourceIP | Whether the source NAT performed, the post-NAT source IP address. | string |
| Panorama.Monitor.Logs.NATSourcePort | The Post-NAT source port. | string |
| Panorama.Monitor.Logs.PCAPid | The packet capture (pcap) ID is a 64 bit unsigned integral denoting an ID to correlate threat pcap files with extended pcaps taken as a part of that flow. All threat logs will contain either a pcap_id of 0 (no associated pcap), or an ID referencing the extended pcap file. | string |
| Panorama.Monitor.Logs.IPProtocol | The IP address protocol associated with the session. | string |
| Panorama.Monitor.Logs.Recipient | Only for the WildFire subtype; all other types do not use this field. Specifies the name of the receiver of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | string |
| Panorama.Monitor.Logs.Rule | The name of the rule that the session matched. | string |
| Panorama.Monitor.Logs.RuleID | The ID of the rule that the session matched. | string |
| Panorama.Monitor.Logs.ReceiveTime | The time the log was received at the management plane. | string |
| Panorama.Monitor.Logs.Sender | Only for the WildFire subtype; all other types do not use this field. Specifies the name of the sender of an email that WildFire determined to be malicious when analyzing an email link forwarded by the firewall. | string |
| Panorama.Monitor.Logs.SessionID | The internal numerical identifier applied to each session. | string |
| Panorama.Monitor.Logs.DeviceSN | The serial number of the firewall on which the session was logged. | string |
| Panorama.Monitor.Logs.Severity | The severity associated with the threat. Can be "informational", "low", "medium", "high", or "critical". | string |
| Panorama.Monitor.Logs.SourceAddress | The original session source IP address. | string |
| Panorama.Monitor.Logs.SourceCountry | The source country or internal region for private addresses. The Maximum length is 32 bytes. | string |
| Panorama.Monitor.Logs.SourceUser | The username of the user who initiated the session. | string |
| Panorama.Monitor.Logs.SourcePort | The source port utilized by the session. | string |
| Panorama.Monitor.Logs.Name | The Palo Alto Networks identifier for the threat. It is a description string followed by a 64-bit numerical identifier. | string |
| Panorama.Monitor.Logs.ID | The Palo Alto Networks ID for the threat. | string |
| Panorama.Monitor.Logs.ToZone | The zone to which the session was destined. | string |
| Panorama.Monitor.Logs.TimeGenerated | The time that the log was generated on the dataplane. | string |
| Panorama.Monitor.Logs.URLCategoryList | The list of the URL filtering categories that the firewall used to enforce policy. | string |
| Panorama.Monitor.JobID | The job ID of the logs query. | unknown |
| Panorama.Monitor.Status | The status of the logs query. | string |
| Panorama.Monitor.Message | The message  of the logs query. | string |

## Playbook Image
---
![PAN-OS_Query_Logs_For_Indicators](../doc_files/PAN-OS_Query_Logs_For_Indicators.png)
