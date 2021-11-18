This playbook helps analysts manage the manual process of adding indicators from cloud providers, apps, services etc. to an allow list. The playbook indicator query is set to search for indicators that have the 'whitelist_review' tag. The playbooks layout displays all of the related indicators in the summary page. While reviewing the indicators, the analyst can go to the summary page and tag the indicators accordingly with tags such as, 'approved_black', 'approved_white', etc. Once the analyst completes the review, the playbook can optionally send an email with a list of changes done by the analyst which haven't been approved. Once complete, the playbook removes the 'whitelist review' tag from the indicators.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* associateIndicatorToIncident
* removeIndicatorField
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | tags:whitelist_review and -tags:being_reviewed | Optional |
| ApproversEmailAddress | This input specifies the email address to which to send the approval form if approval is required. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/0ce0007e6dcec27648d6dd4d30a432de945681f1/Packs/TIM_Processing/doc_files/TIM_-_Review_Indicators_Manually_For_Whitelisting.png)