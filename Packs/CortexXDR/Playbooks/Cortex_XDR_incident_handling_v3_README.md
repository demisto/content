This playbook is triggered by fetching a Palo Alto Networks Cortex XDR incident.
The playbook syncs and updates new XDR alerts that construct the incident and triggers a sub-playbook to handle each alert by type.
Then, the playbook performs enrichment on the incident’s indicators and hunts for related IOCs.
Based on the severity, it lets the analyst decide whether to continue to the remediation stage or close the investigation as a false positive.
After the remediation, if there are no new alerts, the playbook stops the alert sync and closes the XDR incident and investigation. For performing the bidirectional sync, the playbook uses the incoming and outgoing mirroring feature added in XSOAR version 6.0.0. After the Calculate Severity - Generic v2 sub-playbook’s run, Cortex XSOAR will be treated as the single source of truth for the severity field, and it will sync only from Cortex XSOAR to XDR, so manual changes for the severity field in XDR will not update in the XSOAR incident.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Calculate Severity - Generic v2
* Block Indicators - Generic v2
* Entity Enrichment - Generic v3
* Cortex XDR device control violations
* Cortex XDR Alerts Handling
* Palo Alto Networks - Hunting And Threat Detection

### Integrations
* CortexXDRIR
* Cortex XDR - IR

### Scripts
* Set
* DBotFindSimilarIncidents
* SetGridField

### Commands
* xdr-update-incident
* linkIncidents
* xdr-get-incident-extra-data
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_id | Incident ID. | incident.xdrincidentid | Optional |
| similarIncidentFields | A comma-separated list of similar incident field keys. | xdrdescription | Optional |
| LinkSimilarIncidents | This input indicates whether the playbook will link similar incidents. To link similar incidents, Specify Yes/No. | Yes | Optional |
| Hunting | This input indicates whether the playbook will hunt for related IOCs. Specify Yes/No. | Yes | Optional |
| InternalRange | A comma-separated list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation. An example of a list <br/>"172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). <br/>If a list is not provided, will use the default list provided in the IsIPInRanges, |  | Optional |
| CriticalUsernames | A comma-separated list of names of critical users in the organization.<br/>This will affect the calculated severity of the incident. | admin,administrator | Optional |
| CriticalHostnames | A comma-separated list of names of critical endpoints in the organization. This will affect the calculated severity of the incident. |  | Optional |
| CriticalADGroups | CSV of DN names of critical Active Directory groups. This will affect the severity calculated for this incident. |  | Optional |
| InternalHostRegex | This is provided for the script IsInternalHostName that checks if the detected host names are internal or external if the hosts match the organization's naming convention. For example, the host testpc1 will have the following regex \\w\{6\}\\d\{1\}. |  | Optional |
| InternalDomainName | The organizations internal domain name. This is provided for the script IsInternalHostName that checks if the detected host names are internal or external if the hosts contain the internal domains suffix. For example, paloaltonetworks.com. If there is more than one domain, use the \| character to separate values such as \(paloaltonetworks.com\|test.com\). |  | Optional |
| TimeStamp | Timestamp in relative date format for query device control events from Cortex XDR. | 10 days | Optional |
| AutoRemediation | Whether remediation will be run automatically or manually. If set to "True" - remediation will be automatic. | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR incident handling v3](https://raw.githubusercontent.com/demisto/content/813a815564305b3a82a324dc3c08024fe1470f9b/Packs/CortexXDR/doc_files/Cortex_XDR_incident_handling_v3.png)