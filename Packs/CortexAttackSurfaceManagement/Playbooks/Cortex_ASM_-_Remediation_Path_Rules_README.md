This playbook returns "RemediationAction" options based return from Remediation Path Rules API, or defaults to data collection task options from "Cortex ADM - Decision" subplaybook.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
Cortex ASM - Decision

### Integrations
CortexAttackSurfaceManagement

### Scripts
* Set
* GetTime
* RemediationPathRuleEvaluation

### Commands
asm-list-remediation-rule

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExternallyDetectedProviders | Providers of the external service. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RemediationAction | Remediation action to be taken. | string |
| RPR_Timestamp | Timestamp of when the remediation path rule action was determined. | string |

## Playbook Image
---
![Cortex ASM - Remediation Path Rules](../doc_files/Cortex_ASM_-_Remediation_Path_Rules.png)