This playbook executes when no other playbook is associated with an incident. It enriches indicators in an incident using one or more integrations.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Entity Enrichment - Generic v3
* Calculate Severity - Generic v2

### Integrations

This playbook does not use any integrations.

### Scripts

* AssignAnalystToIncident

### Commands

* closeInvestigation
* extractIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Enrich | Determines whether to enrich all indicators in the incident. | True | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | False | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Default](../doc_files/Default.png)
