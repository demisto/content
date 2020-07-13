This playbook compares Insight indicators before and after being processed. It receives an Insight and it's indicators before validation, fetches updated indicators after rerunning the Insight, and then compares the results to validate mitigation. Indicators are classified as Remediated or Not Remediated based on their validated status and the appropriate field (SafeBreach Remediation Status) is updated.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeBreach_v2

### Scripts
* SetAndHandleEmpty
* ChangeContext
* Set

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
![SafeBreach - Compare and Validate Insight Indicators](Insert the link to your image here)