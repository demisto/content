This playbook is triggered by fetching a Palo Alto Networks Cortex XDR incident.
The playbook syncs and updates new XDR alerts that construct the incident and triggers a sub-playbook to handle each alert by type.
Then, the playbook performs enrichment on the incident's indicators and hunting for related IOCs.
Based on the severity, it lets the analyst decide whether to continue to the remediation stage or close the investigation as a false positive. 
After the remediation, if there are no new alerts, the playbook stops the alert sync and closes the XDR incident and investigation. For performing the bidirectional sync, the playbook uses the incoming and outgoing mirroring feature added in XSOAR version 6.0.0. After the `Calculate Severity - Generic v2` sub-playbook’s run Cortex XSOAR will be treated as the single source of truth for the severity field, and it will sync only from Cortex XSOAR to XDR, so manual changes for the severity field in XDR will not update in the XSOAR incident.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Entity Enrichment - Generic v3
* PANW - Hunting and threat detection by indicator type V2
* Block Indicators - Generic v2
* Cortex XDR Alerts Handling
* Calculate Severity - Generic v2
* Cortex XDR device control violations

### Integrations
* Cortex XDR - IR
* CortexXDRIR

### Scripts
* Set
* FindSimilarIncidents
* DemistoLinkIncidents

### Commands
* xdr-get-incident-extra-data
* xdr-update-incident
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_id | Incident ID. | incident.xdrincidentid | Optional |
| similarIncidentFields | A comma-separated list of similar incident fields keys. | xdrdescription | Optional |
| LinkSimilarIncidents | This input indicates whether the playbook will link similar incidents. Specify Yes/No. | Yes | Optional |
| Hunting | Yes/No | Yes | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation, separated by commas. An example of a list of ranges would be: "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16" \(without quotes\). If a list is not provided, will use default list provided in the IsIPInRanges script \(the known IPv4 private address ranges\). |  | Optional |
| CriticalUsernames | A list of comma-separated names of critical users in the organization. This will affect the calculated severity of the incident. | admin,administrator | Optional |
| CriticalHostnames | A list of comma-separated names of critical endpoints in the organization. This will affect the calculated severity of the incident. |  | Optional |
| CriticalADGroups | CSV of DN names of critical Active Directory groups. This will affect the severity calculated for this incident. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR incident handling v3](https://raw.githubusercontent.com/demisto/content/d0bde5eac9154adc18d49814a73a6e44a69313b2/Packs/CortexXDR/doc_files/Cortex_XDR_incident_handling_v3.png)