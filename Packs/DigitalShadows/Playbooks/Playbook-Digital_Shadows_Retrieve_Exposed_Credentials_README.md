Retrieve the exposed email address and password relating to a Digital Shadows Exposed Credential Alert.

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
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DigitalShadows.BreachRecords.Username | A best effort to identify a username within the content of the breach record | unknown |
| DigitalShadows.BreachRecords.Password | The password found in the breach record, if any could be found | unknown |
