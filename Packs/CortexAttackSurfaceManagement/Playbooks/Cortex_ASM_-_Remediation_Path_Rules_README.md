This playbook returns "RemediationAction" options based on the return from the Remediation Path Rules API, or defaults to the data collection task.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

Cortex ASM - Remediation Objectives

### Integrations

* CortexAttackSurfaceManagement

### Scripts

* Set
* GetTime
* RemediationPathRuleEvaluation
* GridFieldSetup
* RemediationPathRuleEvaluation
* Set
* GridFieldSetup
* GetTime

### Commands

* asm-list-remediation-rule

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ExternallyDetectedProviders | Providers of external service. |  | Optional |
| BypassDevCheck | Determine whether to bypass the Dev Check in automated remediation criteria: https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/Cortex-Xpanse-Expander-User-Guide/Automated-Remediation-Capabilities-Matrix<br/><br/>Set to "True" if you want to bypass.  " | False | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RemediationAction | Remediation action to be taken. | string |
| RPR_Timestamp | Timestamp of when the remediation path rule action was determined. | string |
| Select a remediation option.Answers.0 | A selection is necessary in order for the playbook to progress further. | singleSelect |

## Playbook Image

---

![Cortex ASM - Remediation Path Rules](../doc_files/Cortex_ASM_-_Remediation_Path_Rules.png)
