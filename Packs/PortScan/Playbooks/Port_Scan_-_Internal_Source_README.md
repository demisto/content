Remediates port scans originating within the network.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block IP - Generic v2
* PANW - Hunting and threat detection by indicator type V2
* Isolate Endpoint - Generic
* Account Enrichment - Generic v2.1
* Calculate Severity - Generic v2
* Active Directory - Get User Manager Details
* Block File - Generic v2
* Splunk Indicator Hunting
* QRadar Indicator Hunting V2

### Integrations
* Builtin

### Scripts
* SetAndHandleEmpty

### Commands
* xdr-get-endpoints
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| BlockAttackerIP | Whether attacking IPs should be automatically blocked using firewalls. | False |  | Required |
| WhitelistedHostnames | A list of hostnames that should not be isolated even if used in an attack. |  |  | Optional |
| IsolateEndpointIfCriticalIncident | Whether to automatically isolate endpoints if the severity is critical and the endpoint is not on the WhitelistedHostnames input, or opt for manual user approval. True means isolation will be done automatically if the conditions are met. | False |  | Required |
| RoleForEscalation | The name of the Cortex XSOAR role of the users that the incident can be escalated to, in case of developments like lateral movement. |  |  | Optional |
| BlockMaliciousFiles | Whether to automatically block malicious files involved with the incident across all endpoints in the organization. | False |  | Required |
| InternalSourceIPs | The internal IP address\(es\) that performed the port scan. In order to properly respond to internal scans, either this or the SourceHostnames input has to be filled with data. |  |  | Optional |
| SourceHostnames | The source hostname\(s\) that performed the port scan. In order to properly respond to internal scans, either this or the InternalSourceIPs input has to be filled with data. |  |  | Optional |
| SourceUsernames | The Active Directory username\(s\) that were used in the port scan attack. |  |  | Optional |
| InvolvedFileMD5 | MD5 hashes of files that were involved in the port scan incident. |  |  | Optional |
| InvolvedFileSHA1 | SHA1 hashes of files that were involved in the port scan incident. |  |  | Optional |
| InvolvedFileSHA256 | SHA256 hashes of files that were involved in the port scan incident. |  |  | Optional |
| DBotScore | All the DBotScores that were calculated either automatically by auto\-reputation, or using specific tasks, when the incident was ingested. This is used to calculate the incident severity at a later stage. | None | DBotScore | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](https://github.com/demisto/content/raw/5e428e8319dc849cefd284e8a25ccd7b527604a1/Packs/PortScan/doc_files/Port_Scan_-_Internal_Source.png)