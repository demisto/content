Analyzes the health of an incident's or issue's workplan (structure, large inputs/outputs, common scripts and subplaybooks, loops, slow tasks, and skewed conditional tasks) and produces a Markdown health report. The workplan is retrieved using the Core REST API (core-api-get) command.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | HealthCheck |

## Dependencies

---
This script uses the following commands and scripts.

* core-api-get

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| workplan_id | The Workplan ID to analyze. Enter the Incident ID \(Cortex XSOAR\) or the Issue ID \(Cortex XSIAM\) whose workplan should be analyzed. If not provided, the current incident/issue is used. |
| large_io_threshold_kb | Task input/output size threshold in KB. Tasks with inputs or outputs larger than this value are reported. |
| slow_task_threshold_seconds | Slow task threshold in seconds. Tasks that ran longer than this value are reported. |
| top_n | Number of items to display in the "Top N" tables. |
| attach_report | Whether to attach the report to the War Room as a Markdown \(.md\) file. |

## Outputs

---
There are no outputs for this script.
