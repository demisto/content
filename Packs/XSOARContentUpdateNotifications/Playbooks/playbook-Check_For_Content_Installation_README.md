This playbook checks for content updates.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* DeleteContext
* Set

### Commands
* demisto-api-get

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PacksUpdated | This will return true if all the content packs were updated. If a user specified "All" in the content pack filters then all packs must be updated. Otherwise, only those that are specified in the filter need to be updated for this to return as True. | boolean |
