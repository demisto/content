Generates an investigation summary report in an automated way. This can be used in post-processing flow as well.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | post-processing |
| Cortex XSOAR Version | 3.5.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name | The report name to generate (should correspond with report type). |
| type | The report type to generate (should correspond with report name). |
| incidentId | The incident ID to generate the report for. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Report.Name | The report's file name | string |
| Report.FileID | The file's ID of the report. | string |
