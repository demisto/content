Playbook that takes action id and checks the action status. 
Please enter action id you want to know it’s status.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* Cortex XDR - IR

### Scripts
* PrintErrorEntry

### Commands
* xdr-action-status-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| action_id | Action ID of the specific request. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Check Action Status](https://raw.githubusercontent.com/demisto/content/cortex-xdr-enhancement/Packs/CortexXDR/doc_files/Cortex%20XDR%20-%20Check%20Action%20Status.png)