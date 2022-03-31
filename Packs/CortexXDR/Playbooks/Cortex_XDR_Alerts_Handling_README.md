This playbook is used to loop over every alert in a Cortex XDR incident. 
Supported alert categories:
- Malware
- Port Scan

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Port Scan - Adjusted
* Cortex XDR - Malware Investigation

### Integrations
* Cortex XDR - IR

### Scripts
This playbook does not use any scripts.

### Commands
* xdr-get-incident-extra-data

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_id | Incident ID. | PaloAltoNetworksXDR.Incident.incident_id | Optional |
| alert_id | Alert ID. | PaloAltoNetworksXDR.Incident.alerts.alert_id | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | Unique ID assigned to each returned incident. | unknown |
| PaloAltoNetworksXDR.Incident.description | Dynamic calculated description of the incident. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.alert_id | Unique ID for each alert. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.severity | Severity of the alert.,"low","medium","high""" | unknown |
| PaloAltoNetworksXDR.Incident.alerts.name | Calculated name of the alert. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.category | Category of the alert, for example, Spyware Detected via Anti-Spyware profile. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.host_ip | Host IP involved in the alert. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.host_name | Host name involved in the alert. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.user_name | User name involved with the alert. | unknown |
| PaloAltoNetworksXDR.Incident.alerts.event_type | Event type "Process Execution","Network Event","File Event","Registry Event","Injection Event","Load Image Event","Windows Event Log" | unknown |
| PaloAltoNetworksXDR.Incident.alerts.action | The action that triggered the alert. "REPORTED", "BLOCKED", "POST_DETECTED", "SCANNED", "DOWNLOAD", "PROMPT_ALLOW", "PROMPT_BLOCK", "DETECTED", "BLOCKED_1", "BLOCKED_2", "BLOCKED_3", "BLOCKED_5", "BLOCKED_6", "BLOCKED_7", "BLOCKED_8", "BLOCKED_9", "BLOCKED_10", "BLOCKED_11", "BLOCKED_13", "BLOCKED_14", "BLOCKED_15", "BLOCKED_16", "BLOCKED_17", "BLOCKED_24", "BLOCKED_25", "DETECTED_0", "DETECTED_4", "DETECTED_18", "DETECTED_19", "DETECTED_20", "DETECTED_21", "DETECTED_22", "DETECTED_23" | unknown |
| PaloAltoNetworksXDR.Incident.alerts.action_pretty | The action that triggered the alert "Detected \(Reported\)" "Prevented \(Blocked\)" "Detected \(Post Detected\)" "Detected \(Scanned\)" "Detected \(Download\)" "Detected \(Prompt Allow\)" "Prevented \(Prompt Block\)" "Detected" "Prevented \(Denied The Session\)" "Prevented \(Dropped The Session\)" "Prevented \(Dropped The Session And Sent a TCP Reset\)" "Prevented \(Blocked The URL\)" "Prevented \(Blocked The IP\)" "Prevented \(Dropped The Packet\)" "Prevented \(Dropped All Packets\)" "Prevented \(Terminated The Session And Sent a TCP Reset To Both Sides Of The Connection\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Client\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Server\)" "Prevented \(Continue\)" "Prevented \(Block-Override\)" "Prevented \(Override-Lockout\)" "Prevented \(Override\)" "Prevented \(Random-Drop\)" "Prevented \(Silently Dropped The Session With An ICMP Unreachable Message To The Host Or Application\)" "Prevented \(Block\)" "Detected \(Allowed The Session\)" "Detected \(Raised An Alert\)" "Detected \(Syncookie Sent\)" "Detected \(Forward\)" "Detected \(Wildfire Upload Success\)" "Detected \(Wildfire Upload Failure\)" "Detected \(Wildfire Upload Skip\)" "Detected \(Sinkhole\)" | unknown |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_image_name | Image name | unknown |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_command_line | Command line | unknown |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_status | Signature status "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | unknown |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_vendor | Singature vendor name | unknown |
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_sha256 | Image SHA256 | unknown |
| PaloAltoNetworksXDR.Incident.alerts.is_whitelisted | Is on allow list "Yes" "No" | unknown |
| PaloAltoNetworksXDR.Incident.network_artifacts.type | Network artifact type "IP" | unknown |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_domain | The domain related to the artifact. | unknown |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_country | The country related to the artifact | unknown |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_ip | The remote IP related to the artifact. | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_status | Digital signature status of the file. "SIGNATURE_UNAVAILABLE" "SIGNATURE_SIGNED" "SIGNATURE_INVALID" "SIGNATURE_UNSIGNED" "SIGNATURE_WEAK_HASH" | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.is_process | Whether the file artifact is related to a process execution. | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_name | Name of the file. | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_wildfire_verdict | The file verdict, calculated by Wildfire. "BENIGN" "MALWARE" "GRAYWARE" "PHISING" "UNKNOWN" | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.is_malicious | Whether the artifact is malicious, decided by the Wildfire verdic | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.type | The artifact type "META" "GID" "CID" "HASH" "IP" "DOMAIN" "REGISTRY" "HOSTNAME" | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256 | SHA-256 hash of the file | unknown |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_vendor_name | File signature vendor name | unknown |
| PortScan.BlockPorts | Indicates whether there's a need to block the ports used for exploitation on the scanned host. | unknown |
| PortScan.AttackerIPs | Attacker IPs from the port scan alert. | unknown |
| PortScan.AttackerHostnames | Attacker hostnames from the port scan alert. | unknown |
| PortScan.AttackerUsername | Attacker username from the port scan alert. | unknown |
| PortScan.FileArtifacts | File artifacts from the port scan alert. | unknown |
| PortScan.LateralMovementFirstDatetime | Lateral Movement First Date time from the port scan alert. | unknown |
| PortScan.PortScanFirstDatetime | Port Scan First Date time | unknown |

## Playbook Image
---
![Cortex XDR Alerts Handling](https://github.com/demisto/content/raw/3fadebe9e16eb7c9fc28ce3bb600319ec875e3b5/Packs/CortexXDR/doc_files/Cortex_XDR_Alerts_Handling.png)