This playbook polls a context key to check if a specific value exists.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Generic Polling

### Integrations
This playbook does not use any integrations.

### Scripts
* CheckContextValue 

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| key | The context key to poll for a value. Can contain ''.'', for example: "ContextKey1.ContextKey2.ContextKey3"' |  | Required |
| value | The regex to check the field for. By default the regex contains .+, which matches anything other than None. | .+ | Required |
| frequency | How often to check \(in minutes\). | 1 | Required |
| timeout | When to timeout \(in minutes\). | 10 | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Setup Account](./../doc_files/playbook-Context_Polling_-_Generic.png)