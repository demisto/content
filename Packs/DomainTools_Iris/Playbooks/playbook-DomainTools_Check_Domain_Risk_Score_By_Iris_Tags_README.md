## DomainTools Check Domain Risk Score By Tags Playbook

This playbook call iris ivestigate api with a given "tag". Check active domains with high risk score then alerts user and outputs all high risk domains in the current incident indicators.

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

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| dt_min_riskscore_threshold | The minimum risk score threshold value to check. | None | None | Required |
| dt_monitored_iris_tags | The Iris tags to lookup. Values should be a comma separated value. e.g. (tag1,tag2) | None | None | Required |
| should_wait_for_analyst_review | Flags if users should wait for an analyst to review. Default is false. Value can be either true/false only. | false | None | Required |

## Playbook Outputs

---
This playbook outputs a high risk score domain as an indicator.