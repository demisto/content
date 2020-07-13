This is an auxiliary sub-playbook that reruns a single insight using a specified Insight Id as an input. It is used to loop over insights as part of the main rerun playbook - "SafeBreach Rerun Insights".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeBreach v2

### Scripts
This playbook does not use any scripts.

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
| SafeBreach.Insight.Id | Insight unique ID. | unknown |
| SafeBreach.Insight.Rerun.Name | Insight rerun test name. | unknown |
| SafeBreach.Insight.Rerun.Id | ID of the rerun insight test. | unknown |
| SafeBreach.Insight.Rerun.AttacksCount | Count of the attacks executed in the insight rerun test. | unknown |
| SafeBreach.Test.Id | ID of the test. | unknown |
| SafeBreach.Test.Name | Name of the test. | unknown |
| SafeBreach.Test.AttacksCount | The number of attacks executed in the insight rerun test. | unknown |
| SafeBreach.Test.Status | Test run status. For insight rerun, starts from PENDING. | unknown |
| SafeBreach.Test.ScheduledTime | Time when the test was triggered. | unknown |

## Playbook Image
---
![SafeBreach Rerun Single Insight](Insert the link to your image here)