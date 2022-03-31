This playbook enriches Intelligence Alerts & Intelligence Reports.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* ACTI Indicator Query

### Scripts
This playbook does not use any scripts.

### Commands
* acti-getThreatIntelReport

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ia_uuid | The Intelligence Alert uuid. | ${intelligence_alerts}.None | Optional |
| ir_uuid | The Intelligence Report uuid. | ${intelligence_reports}.None | Optional |
| Domain | The extarcted Domain. | ${Domain} | Optional |
| IP | The extracted IP. | ${IP} | Optional |
| URL | The extracted URL. | ${URL} | Optional |

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
![ACTI IA/IR Enrichment](Insert the link to your image here)