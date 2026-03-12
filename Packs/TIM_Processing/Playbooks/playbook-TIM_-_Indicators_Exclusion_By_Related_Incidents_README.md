This playbooks allows you to exclude indicators according to the number of incidents the indicator is related to. The indicator query is "investigationsCount:>=X" where X is the number of related incidents to the indicator that you set. Excluded indicators are located in the Cortex XSOAR exclusion list and are removed from all of their related incidents and future ones. The purpose of excluding these indicators is to reduce the amount internal and common indicators appearing in many incidents and showing only relevant indicators. Creating exclusions can also accelerate performance. 
The excludeIndicators command provides all the options that are on the exclusion list addition - except for using regex.
## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* createNewIncident
* excludeIndicators
* appendIndicatorField

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | The indicator query is "investigationsCount:>=X" where X is the number of related incidents to the indicator that you set. |  | Optional |
| ActionToPerform | This input specifies which action the playbook performs on the provided indicators. Possible input values can be:    AutoExclude, TagIndicators |  | Optional |
| TagValueForIndicators | This input specifies the tag value to apply to the indicators. An example value can be allowlist_review. This input should be used only if The ActionToPerform input value is TagIndicators. |  | Optional |
| OpenIncidentToReviewIndicatorsManually | This input determines if processed indicators that have the allowlist review tag are reviewed in a new incident. To create an incident, enter any value other than 'No'. | No | Optional |
| AutoExcludeReason | Provide the reason that will appear in the XSOAR exclusion |  | Optional |
| indicatorsValues | A comma-separated list of indicator values. Supports values of more than one indicator type. For example the value of an IP address, a domain, and a file hash. | | Optional |
| indicatorsTypes | A comma-separated list of indicator types. Supports multiple types. For example IP, Host and Email. | | Optional |
| reason | The reason the indicators were excluded. | | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Playbook Image](https://raw.githubusercontent.com/demisto/content/75e7294b81733c91e2be73477d5544b186bcb692/Packs/TIM_Processing/doc_files/TIM_-_Process_Indicators_Exclusion_By_Related_Incidents.png)
