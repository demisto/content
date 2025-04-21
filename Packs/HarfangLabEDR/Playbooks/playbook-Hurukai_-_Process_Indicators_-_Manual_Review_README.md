This playbook tags indicators ingested by feeds that require manual approval. The playbook is triggered due to a job. The indicators are tagged as requiring a manual review. The playbook concludes with creating a new incident that includes all of the indicators that the analyst must review.
To enable the playbook, the indicator query needs to be configured. An example query is a list of the feeds whose ingested indicators should be manually reviewed. For example, sourceBrands:"Feed A" or sourceBrands:"Feed B".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* HarfangLab EDR - Hunt IOCs

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* createNewIncident
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | type:File | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Hurukai - Process Indicators - Manual Review](../doc_files/Hurukai_-_Process_Indicators_-_Manual_Review.png)
