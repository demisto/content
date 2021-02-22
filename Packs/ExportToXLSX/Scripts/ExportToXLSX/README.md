Exports context data to a Microsoft Excel Open XML Spreadsheet (XLSX) file.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| file_name | The output file name \(for example "Report.xlsx"\). |
| data | The data to export. Accepts a context key of a dictionary or a list of dictionaries for a single sheet file \($\{data\}\). Separate multiple sheet files using a comma ",". For example, if you are exporting multiple sheet files, the argument would be: $\{data1\},$\{data2\}. |
| sheet_name | The sheet name. Separate multiple sheet names using a comma ",", for example, sheet1,sheet2. |
| headers | A comma-separated list of headers. The order that you pass the headers determines how they display in the exported sheet\(s\). Separated multiple sheets using a semicolon. For example, if you are exporting two sheets that includes two headers each, the argument would be: "header1,header2;header3,header4". |
| bold | Whether table headers should be bold. If this argument is set to "true", table headers are bold. Default is "true". |
| border | Whether borders should be added to table cells. If this argument is set to "true", borders are added to table cells. Default is "true". |

## Outputs
---
There are no outputs for this script.
