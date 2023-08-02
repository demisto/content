Deprecated. No available replacement.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* SafeBreach v2

### Scripts

* Sleep
* Print

### Commands

* safebreach-rerun-insight

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InsightIds | SafeBreach Insight Ids | SafeBreach.Insight.Id | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SafeBreach.Insight.Id | Insight unique ID. | Number |
| SafeBreach.Insight.Rerun.Name | Insight rerun test name. | String |
| SafeBreach.Insight.Rerun.Id | ID of the rerun insight test. | String |
| SafeBreach.Insight.Rerun.AttacksCount | Count of the attacks executed in the insight rerun test. | Number |
| SafeBreach.Test.Id | ID of the test. | String |
| SafeBreach.Test.Name | Name of the test. | String |
| SafeBreach.Test.AttacksCount | The number of attacks executed in the insight rerun test. | Number |
| SafeBreach.Test.Status | Test run status. For insight rerun, starts from PENDING. | String |
| SafeBreach.Test.ScheduledTime | Time when the test was triggered. | String |
