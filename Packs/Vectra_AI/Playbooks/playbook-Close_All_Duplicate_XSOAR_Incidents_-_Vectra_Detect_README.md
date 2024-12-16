This playbook will clean up all incidents in XSOAR by closing duplicate incidents from Vectra Detect.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Close Duplicate XSOAR Incidents - Vectra Detect

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| page_size | Specify the number of incidents to close during a single execution. | 50 | Optional |
| note | The note to add to the closed incidents. | Duplicate. Closed. | Optional |
| close_in_vectra | If set to true, the playbook will close the entity's assignment in Vectra platform. This option is supported only when instance of Vectra Detect integration is enabled. | True | Optional |
| incident_types | Specify the incident type(s) to close duplicate incidents. Supports comma-separated values. | Vectra Account, Vectra Host | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Close All Duplicate XSOAR Incidents - Vectra Detect](../doc_files/Close_All_Duplicate_XSOAR_Incidents_-_Vectra_Detect.png)
