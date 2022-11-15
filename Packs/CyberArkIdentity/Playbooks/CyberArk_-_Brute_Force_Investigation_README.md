This playbook investigates a “Brute Force” incident by gathering user and IP information  and performs remediation based on the information gathered and received from the user.

Used Sub-playbooks:
* Enrichment for Verdict
* Block IP - Generic v3
* Block Account - Generic v2



## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Enrichment for Verdict
* Block Account - Generic v2
* Block IP - Generic v3

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* setAlert

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InternalRange | List of Internal IP ranges |  | Optional |
| inputs.AutoBlockIP | Set to True if should block the IP without confirmation | False | Optional |
| inputs.AutoBlockAccount | Set to True if should block the user account without confirmation | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CyberArk - Brute Force_Investigation](../doc_files/CyberArk_-_Brute_Force_Investigation.png)