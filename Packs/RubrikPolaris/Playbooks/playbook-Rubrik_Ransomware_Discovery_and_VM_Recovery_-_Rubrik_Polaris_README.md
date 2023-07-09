Use this playbook to recover a virtual machine using the "RubrikPolaris" integration by either exporting or live-mounting a backup snapshot. This playbook also creates tickets on ServiceNow using "ServiceNow v2" integration.
Supported integrations:
- RubrikPolaris
- ServiceNow v2

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Rubrik Poll Async Result - Rubrik Polaris
* Rubrik IOC Scan - Rubrik Polaris

### Integrations
* RubrikPolaris
* ServiceNow v2

### Scripts
* http
* Set
* PrintErrorEntry
* SetAndHandleEmpty
* Print

### Commands
* servicenow-create-ticket
* rubrik-gps-vm-livemount
* rubrik-gps-vm-export
* rubrik-gps-vm-datastore-list
* servicenow-update-ticket
* rubrik-gps-vm-host-list
* rubrik-gps-vm-snapshot-create
* rubrik-polaris-vm-object-metadata-get
* servicenow-add-comment

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ObjectId | Object ID of the incident. | incident.rubrikpolarisfid | Required |
| ClusterId | Cluster ID of the incident. | incident.rubrikpolariscdmclusterid | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Rubrik Ransomware Discovery and VM Recovery - Rubrik Polaris](../doc_files/Rubrik_Ransomware_Discovery_and_VM_Recovery_-_Rubrik_Polaris.png)