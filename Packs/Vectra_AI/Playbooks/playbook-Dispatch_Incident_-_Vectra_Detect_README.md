This playbook is called from the Process Incident - Vectra Detect playbook. It will fetch all active detections for the entity under investigation. It will then assign the entity to a user; if an assignment already exists, it will update that assignment and add a note in Vectra.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext

### Commands

* vectra-assignment-assign
* vectra-account-note-add
* vectra-search-assignments
* vectra-search-detections
* vectra-host-note-add

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| user_id | User ID for entity assignment. |  | Optional |
| entity_type | Type of the entity. | incident.vectraentitytype | Optional |
| entity_id | ID of the entity. | incident.accountid | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Dispatch Incident - Vectra Detect](../doc_files/Dispatch_Incident_-_Vectra_Detect.png)
