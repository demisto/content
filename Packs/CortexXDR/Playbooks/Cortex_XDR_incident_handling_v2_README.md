This playbook is triggered by fetching a Palo Alto Networks Cortex XDR incident.
The playbook syncs and updates new XDR alerts that construct the incident and triggers a sub-playbook to handle each alert by type.
Then, the playbook performs enrichment on the incident's indicators and hunting for related IOCs.
Based on the severity, it lets the analyst decide whether to continue to the remediation stage or close the investigation as a false positive. 
After the remediation, if there are no new alerts, the playbook stops the alert sync and closes the XDR incident and investigation.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PANW - Hunting and threat detection by indicator type V2
* Calculate Severity - Generic v2
* Cortex XDR Alerts Handling
* Entity Enrichment - Generic v3
* Block Indicators - Generic v2

### Integrations
* PaloAltoNetworks_XDR
* Cortex XDR - IR

### Scripts
* DemistoLinkIncidents
* StopScheduledTask
* XDRSyncScript
* FindSimilarIncidents
* Set

### Commands
* xdr-update-incident
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_id | Incident ID. |  | Optional |
| similarIncidentFields | A comma\-separated list of similar incident fields keys. |  | Optional |
| LinkSimilarIncidents | This input indicates whether the playbook will link similar incidents. Specify Yes/No. | Yes | Optional |
| Hunting | Yes/No | Yes | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| CriticalUsernames | A list of comma\-separated names of critical users in the organization. This will affect the calculated severity of the incident. | admin,administrator | Optional |
| CriticalHostnames | A list of comma\-separated names of critical endpoints in the organization. This will affect the calculated severity of the incident. |  | Optional |
| CriticalADGroups | CSV of DN names of critical Active Directory groups. This will affect the severity calculated for this incident. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR incident handling v2](https://github.com/demisto/content/raw/3fadebe9e16eb7c9fc28ce3bb600319ec875e3b5/Packs/CortexXDR/doc_files/Cortex_XDR_incident_handling_v2.png)