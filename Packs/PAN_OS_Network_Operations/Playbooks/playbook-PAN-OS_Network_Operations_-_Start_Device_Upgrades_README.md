This playbook is used by the Domain Upgrade playbook to start (either manually or automatically) groups of Device Upgrade incidents.

It works by first retrieving the administrative domains/device-groups that have upgrades pending, then marking the pause tasks within them complete in batches.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* taskComplete

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Automatically Upgrade | If set to true, will automatically start all device ugprades. | ${incident.panosnetworkoperationsautomaticupgradeswitch} | Optional |
| incident_ids | List of incident IDs corresponding to device upgrade incidents to start. | ${CreatedIncidentID} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Start Device Upgrades](../doc_files/PAN-OS_Network_Operations_-_Start_Device_Upgrades.png)