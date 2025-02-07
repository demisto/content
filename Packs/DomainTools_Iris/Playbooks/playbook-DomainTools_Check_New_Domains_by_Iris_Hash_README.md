## DomainTools Check New Domains by Iris Search Hash Playbook

This playbook retrieves domain from a given `search hash` with built-in “first_seen” param. Outputs all new domains in the current incident indicators.

## Dependencies

This playbook uses the following sub-playbooks, integrations, lists and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* DomainTools Iris

### Scripts

Please install this scripts by DomainTools first before running the playbook.

* `SetIndicatorTableData`


### Commands

* domaintoolsiris-pivot

### Lists

This playbook does not use any custom lists.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| iris_search_hash | The Iris Investigate search hash to pivot. | None | Iris Investigate Searh Hash | Required |
| should_wait_for_analyst_review | Flags if users should wait for an analyst to review. Default is false. Value can be either true/false only. | false | None | Required |

## Playbook Outputs

---
This playbook outputs a new domain indicator based on the iris search hash result.
