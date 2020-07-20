This playbook compares SafeBreach Insight indicators before and after the processing. It receives an insight and it's indicators before validation, fetches updated indicators after rerunning the insight, and then compares the results to validate mitigation. Indicators are classified as Remediated or Not Remediated based on their validated status and the appropriate field (SafeBreach Remediation Status) is updated.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeBreach_v2

### Scripts
* ChangeContext
* SetAndHandleEmpty
* Set

### Commands
* setIndicator
* safebreach-get-remediation-data

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IndicatorsBefore | Indicator values extracted from a SafeBreach Insight before remediation. |  | Required |
| Insight | SafeBreach insight object to verify the remediation for. |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RemediatedIndicators | List of indicators that were remediated | Array |
| NotRemediatedIndicators | List of indicators that were not remediated | Array |

## Playbook Image
---
![SafeBreach - Compare and Validate Insight Indicators](Insert the link to your image here)