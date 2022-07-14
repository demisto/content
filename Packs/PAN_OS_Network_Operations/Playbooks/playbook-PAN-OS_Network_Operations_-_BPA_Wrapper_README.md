Wraps the BPA use case to make it simple to run using a button.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* linkIncidents
* createNewIncident
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_name | The name of the new BPA incident to create. | Panorama - Best Practices Assessment | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CreatedIncidentID | commands.local.cmd.create.inc.outputs.createdId | unknown |

## Playbook Image
---
![PAN-OS Network Operations - BPA Wrapper](../doc_files/PAN-OS_Network_Operations_-_BPA_Wrapper.png)