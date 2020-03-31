Sets up and maintains log forwarding for the Panorama rulebase.
It can be run when setting up a new instance, or as a periodic job to enforce log forwarding policy.
You can either update all rules and override previous profiles, or update only rules that do not have a log forwarding profile configured.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* AreValuesEqual

### Commands
* panorama-edit-rule
* panorama-list-rules

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| log-forwarding-name | The name of the log-forwarding object that will be attached to all of the rules. | log_forwarding_101 | Required |
| auto_commit | Whether the rule should be committed automatically or manually. | yes | Optional |
| pre-post-rulebase | Either the pre-rulebase or post-rulebase, depending on the rule structure. | pre-rulebase | Required |
| device-group | The device group to work on. | - |Optional |
| override-existing-profiles | Whether the log-forwarding profiles that were already defined should be overrode. | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

![PAN-OS_Log_Forwarding_Setup_And_Maintenance](https://github.com/demisto/content/blob/77dfca704d8ac34940713c1737f89b07a5fc2b9d/images/playbooks/PAN-OS_Log_Forwarding_Setup_And_Maintenance.png)
