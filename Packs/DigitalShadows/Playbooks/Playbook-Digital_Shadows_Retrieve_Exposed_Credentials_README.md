

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Digital Shadows

### Scripts
This playbook does not use any scripts.

### Commands
* ds-get-breach-records

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
|  |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DigitalShadows.BreachRecords.Username | A best effort to identify a username within the content of the breach record | unknown |
| DigitalShadows.BreachRecords.Password | The password found in the breach record, if any could be found | unknown |

## Playbook Image
---
![Digital Shadows Retrieve Exposed Credentials](Insert the link to your image here)