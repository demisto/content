This playbook tags indicators ingested by feeds that require manual approval. The playbook is triggered due to a job. The indicators are tagged as requiring a manual review. The playbook optionally concludes with creating a new incident that includes all of the indicators that the analyst must review.
To enable the playbook, the indicator query needs to be configured. An example query is a list of the feeds whose ingested indicators should be manually reviewed. For example, sourceBrands:"Feed A" or sourceBrands:"Feed B".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* TIM - Indicator Auto Processing

### Integrations
* Builtin

### Scripts
This playbook does not use any scripts.

### Commands
* createNewIncident
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
|  |  |  |  | Optional |
| OpenIncidentToReviewIndicatorsManually | This input determines if processed indicators that have the manual review tag are reviewed in a new incident. To create an incident, enter any value other than &\#x27;No&\#x27;. | No |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

![TIM - Process Indicators - Manual Review](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/TIM_-_Process_Indicators_-_Manual_Review.png)