This is a sub-playbook that reruns a single insight using a specified Insight Id as input. It is used to run insights one by one iteratively as part of the main rerun playbook - "SafeBreach Rerun Insights".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SafeBreach v2

### Scripts
* Print
* Sleep

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

## Playbook Image
---
![SafeBreach - Rerun Single Insight](https://github.com/demisto/content/raw/6af01e00312a5558e9e2fecdb22534e98414bc9c/Packs/SafeBreach/doc_imgs/SafeBreach_Rerun_Single_Insight.png)