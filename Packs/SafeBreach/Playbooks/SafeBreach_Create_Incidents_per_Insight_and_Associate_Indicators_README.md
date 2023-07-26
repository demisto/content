Deprecated. No available replacement.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* SafeBreach_v2

### Scripts

* Set
* Sleep
* SearchIncidentsV2

### Commands

* associateIndicatorToIncident
* createNewIncident
* safebreach-get-insights

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input | safebreachisbehavioral:T | Optional |
| insightIds | List of Insight ids to create incidents for. |  | Required |
| indicators | List of indicators that to be assigned to created incidents |  | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| incident | Incidents created from SafeBreach Insights | Array |
