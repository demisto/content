Generates a report summary for past incidents.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Cortex XSOAR Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name | Template name of the generated report in the incident. |
| type | The report type to generate. |
| ids | The incident IDs for which to generate. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SummaryReports.IncidentID | The incident ID of each generated report. | number |
| SummaryReports.ReportName | The report name. | string |
| SummaryReports.File | The file name of the report file. | string |
| SummaryReports.FileID | The file ID of the generated report. | string |
