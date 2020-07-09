This playbook receives an Insight and it's indicators before validation. Updated indicators fetched to perform the validation. Indicators are classified as Remediated or Not Remediated based on their validated status and the appropriate field (SafeBreach Remediation Status) is updated.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeBreach_v2

### Scripts
This playbook does not use any scripts.

### Commands
* setIndicator
* safebreach-get-remediation-data

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IndicatorsBefore | Indicators extracted before remediation |  | Required |
| Insight | Insight to verify remediation for |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RemediatedIndicators | List of indicators that were remediated | unknown |
| NotRemediatedIndicators | List of indicators that were not remediated | unknown |

## Playbook Image
---
![SafeBreach - Compare and Validate Insight Indicators (draft)](Insert the link to your image here)