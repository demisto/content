This playbooks allows you to filter indicators according to the number of incidents the indicator is related to. The indicator query is "investigationsCount:>=X" where X is the number of related incidents to the indicator that you set.

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
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |
| ActionToPerform | This input specifies which action the playbook performs on the provided indicators. Possible input values can be
    AutoExclude
    TagIndicators |  | Optional |
| TagValueForIndicators | This input specifies the tag value to apply to the indicators. |  | Optional |
| OpenIncidentToReviewIndicatorsManually | This input determines if processed indicators that have the whitelist review tag are reviewed in a new incident. To create an incident, enter any value other than 'No'. | No | Optional |
| AutoExcludeReason | Provide the reason that will appear in the XSOAR exclusion |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->