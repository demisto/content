Deprecated. No available replacement.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* SafeBreach_v2

### Scripts

* Set
* SetAndHandleEmpty
* ChangeContext

### Commands

* safebreach-get-remediation-data
* setIndicator

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
