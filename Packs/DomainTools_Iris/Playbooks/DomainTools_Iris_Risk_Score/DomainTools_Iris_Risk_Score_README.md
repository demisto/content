## DomainTools Iris Risk Score Playbook

This playbook retrieves the Domain Risk Score of the given domain and check if the risk score is over the threshold and throws an Alert for the Analyst to manually review the domain indicator.

## Dependencies
This playbook uses the following sub-playbooks, integrations, lists and scripts.

### Sub-playbooks
This playbook does not use a sub playbooks.


### Integrations
* DomainTools Iris

### Scripts
Please install this scripts by DomainTools first before running the playbook.
- `SetIndicatorTableData`


### Commands
* domaintoolsiris-investigate

### Lists
This playbook does not use any custom lists.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| domains | The domain(s) to query. Can lookup multiple domains using a comma-separated values.  | None | None | Required |
| dt_min_riskscore_threshold | The minimum risk score threshold.| 70 | None | Required |
| should_wait_for_analyst_review | Flags if users should wait for an analyst to review. Default is false. Value can be either true/false only. | false | None | Required |

## Playbook Outputs
---
This playbook outputs a new domain indicator based on the iris investigate result.
