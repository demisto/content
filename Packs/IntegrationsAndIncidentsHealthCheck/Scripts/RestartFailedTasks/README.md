Run in the same incident that `GetFailedTasks` to be able to restart all (or a some) of the failed tasks

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Dependencies
---
This script uses the following commands and scripts.
* demisto-api-post

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| PlaybookExclusion | Comma Separated list of failed tasks to exclude from restart based on playbook string match |
| SleepTime | Sleep between restarting batch task \(seconds\) |
| IncidentLimit | Limit of number of incidents to restart tasks on |
| GroupSize | Integer of how many tasks you want to be restarted at a time \(grouping\) before a sleep period \(as to not overwhelm the system\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| None |  | Unknown |
