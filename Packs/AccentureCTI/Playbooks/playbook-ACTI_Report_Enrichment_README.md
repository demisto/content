- This playbook enriches Intelligence Alerts, Intelligence Reports, Malware Families, Threat Actors, Threat Groups & Threat Campaigns

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* ACTI Indicator Query

### Scripts
This playbook does not use any scripts.

### Commands
* acti-get-fundamentals-by-uuid
* acti-getThreatIntelReport

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ia_uuid | Intelligence Alert unique ID. | ${intelligence_alerts}.None | Optional |
| ir_uuid | Intelligence Report unique ID. | ${intelligence_reports}.None | Optional |
| Domain | The extracted domain. | ${Domain} | Optional |
| IP | The extracted IP. | ${IP} | Optional |
| URL | The extracted URL. | ${URL} | Optional |
| MalwareFamily_uuid | Malware Family unique ID. | ${acti_malware_family_uuid}.None | Optional |
| ThreatGroup_uuid | Threat Group unique ID. | ${acti_threat_groups_uuid}.None | Optional |
| ThreatCampaign_uuid | Threat Campaign unique ID. | ${acti_threat_campaigns_uuid}.None | Optional |
| ThreatActor_uuid | Threat Actor unique ID. | ${acti_threat_actors_uuid}.None | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IAIR |  | unknown |
| DBotScore |  | unknown |
| Domain |  | unknown |
| IP |  | unknown |
| URL |  | unknown |

## Playbook Image
---
![ACTI Report Enrichment](Insert the link to your image here)