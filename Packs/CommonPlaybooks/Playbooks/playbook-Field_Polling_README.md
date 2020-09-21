This playbook will poll a field for whether a value exists and whether it contains a specific value.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Generic Polling

### Integrations
This playbook does not use any integrations.

### Scripts
* PollingField 

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| field | The field to poll for a value. Ensure that you use the lower case version of the field. For example; the Details field should be details |  | Required |
| value | The regex to check the field for. By default this is .\+ which matches anything other than None. | .+ | Required |
| frequency | How often to check \(in minutes\) | 1 | Required |
| timeout | When to timeout \(in minutes\) | 10 | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Field Polling Generic](https://github.com/demisto/content/raw/978fcd6bff93c2c821cd5f2104bd3f20ee33bf87/Packs/CommonPlaybooks/doc_files/playbook-Field_Polling.png)