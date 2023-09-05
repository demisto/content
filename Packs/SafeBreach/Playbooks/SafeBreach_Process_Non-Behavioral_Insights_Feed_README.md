Deprecated. No available replacement.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* SafeBreach - Compare and Validate Insight Indicators
* SafeBreach - Rerun Insights
* SafeBreach - Create Incidents per Insight and Associate Indicators
* Block Indicators - Generic v2

### Integrations

* SafeBreach_v2

### Scripts

* Set
* Sleep

### Commands

* safebreach-get-remediation-data
* safebreach-get-insights

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | sourceBrands:["SafeBreach*"] and -safebreachisbehavioral:T | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
