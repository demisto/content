Playbook that checks to see if an existing ASM service ID is available. If it is available, it will begin a Cortex Xpanse Remediation Confirmation Scan.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex ASM - Remediation Confirmation Scan

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | Remote IP address in the alert. | alert.remoteip | Optional |
| RemotePort | Remote port number in the alert. | alert.remoteport | Optional |
| ASMRuleID | Attack Surface Management Rule ID. | alert.asmattacksurfaceruleid | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex ASM - Detect Service](../doc_files/Cortex_ASM_-_Detect_Service.png)
