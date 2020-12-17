This playbook is triggered by fetching a Palo Alto Networks Cortex XDR incident.
The playbook syncs and updates new XDR alerts that construct the incident and triggers a sub-playbook to handle each alert by type.
Then, the playbook performs enrichment on the incident's indicators and hunting for related IOCs.
Based on the severity, it lets the analyst decide whether to continue to the remediation stage or close the investigation as a false positive. 
After the remediation, if there are no new alerts, the playbook stops the alert sync and closes the XDR incident and investigation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Calculate Severity - Generic v2
* Block Indicators - Generic v2
* Entity Enrichment - Generic v3
* Palo Alto Networks - Hunting And Threat Detection
* Cortex XDR Alerts Handling

### Integrations
* Cortex XDR - IR
* PaloAltoNetworks_XDR

### Scripts
* StopScheduledTask
* FindSimilarIncidents
* Set
* XDRSyncScript
* DemistoLinkIncidents

### Commands
* closeInvestigation
* xdr-update-incident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_id | Incident ID. |  | Optional |
| similarIncidentFields | A comma-separated list of similar incident fields keys. | xdrdescription | Optional |
| LinkSimilarIncidents | This input indicates whether the playbook will link similar incidents. Specify Yes/No. | Yes | Optional |
| Hunting | Yes/No | Yes | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| CriticalUsernames | A comma-separated list of names of critical users in the organization. This will affect the calculated severity of the incident. | admin,administrator | Optional |
| CriticalHostnames | A comma-separated list of names of critical endpoints in the organization. This will affect the calculated severity of the incident. |  | Optional |
| CriticalADGroups | A comma-separated list of DN names of critical Active Directory groups. This will affect the severity calculated for this incident. |  | Optional |
| InternalDomainName | The organization's internal domain name. This is provided for the ***IsInternalHostName*** script that checks if the detected host names are internal or external if the hosts contain the internal domains suffix. For example, demisto.com. If there is more than one domain, use the \| character to separate values such as \(demisto.com\|test.com\) |  | Optional |
| InternalHostRegex | This is provided for the ***IsInternalHostName*** script that checks if the detected host names are internal or external if the hosts match the organization's naming convention. For example, the host testpc1 will have the following regex \\w\{6\}\\d\{1\} |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR incident handling v2](https://raw.githubusercontent.com/demisto/content/d0bde5eac9154adc18d49814a73a6e44a69313b2/Packs/CortexXDR/doc_files/Cortex_XDR_incident_handling_v2.png)
