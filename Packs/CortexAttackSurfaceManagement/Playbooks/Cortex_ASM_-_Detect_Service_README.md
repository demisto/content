Playbook that looks at what ASM sub-type the alert is and directs it to different pre/post mitigation scans (such as NMAP, SNMP).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* NMAP - Single Port Scan
* NMAP - Banner Check
* Cortex ASM - SNMP Check

### Integrations
This playbook does not use any integrations.

### Scripts
* GridFieldSetup

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RemoteIP | Remote IP address in the alert. | alert.remoteip | Optional |
| RemotePort | Remote port number in the alert. | alert.remoteport | Optional |
| ASMRuleID | Attack Surface Management Rule ID. | alert.asmattacksurfaceruleid | Required |
| ScanNumber | Scan number in case there are multiple IDs in the parent playbook. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex ASM - Detect Service](../doc_files/Cortex_ASM_-_Detect_Service.png)