

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Detonate File - Generic
* Calculate Severity - Standard
* Case Management - Generic - Set SLAs based on Severity
* Entity Enrichment - Generic v4
* Threat Hunting - Generic
* Detonate URL - Generic

### Integrations

This playbook does not use any integrations.

### Scripts

* 4d65d2f8-4d52-4097-887b-11aefcaab76c

### Commands

* findIndicators
* extractIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| enrichIndicators | Set to true if you want to extract indicators | true | Optional |
| DetonateURL | Set to true if you want to detonate URL in a sandbox | False | Optional |
| DetonateFile | Set to true if you want to detonate File in a sandbox | False | Optional |
| HuntForIndicators | Hunt for indicators from other sources | False | Optional |
| RefineExclusionList | Set to true to add exclusion list tuning step to the workflow | True | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Quick Start Investigation](../doc_files/Quick_Start_Investigation.png)