Detailed alert example for Recorded Future.

This playbook is intended as guidance for how the command `recordedfuture-single-alert` can be used in playbooks.

The single alert takes an alert id which can be retrieved from recordedfuture-alerts. If a specific alert rule is desired you can first fetch alert rules and input the alert rule id into `reccordedfuture-alerts`.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts. Depends on the recorded futures indicator field; risk rules.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Recorded Future v2

### Scripts
This playbook does not use any scripts.

### Commands
* recordedfuture-alerts
* recordedfuture-single-alert

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| freetext | Freetext to search for specific alert  | Domain.Name | required |

## Playbook Outputs
There are no outputs for this playbook.
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested | string |
| DBotScore.Type | Indicator type | string |
| DBotScore.Vendor | Vendor used to calculate the score | string |
| DBotScore.Score | The actual score | number |


## Playbook Image
---
![Recorded Future Domain Intelligence](https://github.com/demisto/content/raw/master/Packs/RecordedFuture/doc_files/detailed-alert-playbook.png)
