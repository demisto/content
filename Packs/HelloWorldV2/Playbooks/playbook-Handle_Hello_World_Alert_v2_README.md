This is a playbook which will handle the alerts coming from the Hello World v2 service

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* HelloWorldV2

### Scripts
This playbook does not use any scripts.

### Commands
* helloworld-get-alert-new

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AlertID | Alert ID to retrieve details for. By default retrieves from the HelloWorld ID custom field in the HelloWorld incident type | ${incident.helloworldid} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Handle Hello World Alert v2](Insert the link to your image here)
