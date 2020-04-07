Generates a report summary for past incidents.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Demisto Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| name | The name of the report to generate. |
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
