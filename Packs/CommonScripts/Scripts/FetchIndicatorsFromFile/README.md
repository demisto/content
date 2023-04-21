Fetches indicators from a file.

## Supported File Types
- TXT
- XLS, XLSX
- CSV
- DOC, DOCX

If an Excel file is supplied (XLS, XLSX, CSV), you need to specify the *column_number* argument, which defines the column to fetch from.


## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | indicators |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The file entry\_id from which to fetch the indicators. |
| auto_detect | Whether to auto\-detect the indicator type from the file. |
| default_type | Sets a default indicator type. |
| limit | The maximum number of indicators to fetch. If this argument is not specified, will parse the entire file. |
| offset | The index for the first indicator to fetch. |
| indicator_column_number | Only for spreadsheet files. The column number in the spreadsheet that contains the indicators. The first column number is 1. If this argument is not specified, will use at the first column. |
| sheet_name | Only for spreadsheet files. The name of the Excel sheet to fetch indicators from. If this argument is not specified, will fetch from the first sheet of the workbook. |
| indicator_type_column_number | Only for spreadsheet files. The column number in the spreadsheet that contains the indicator types. The first column number is 1. |
| starting_row | Only for spreadsheet files. The starting row of the spreadsheet to fetch from. The first row is 1. |

## Automation Example

`!FetchIndicatorsFromFile auto_detect=True entry_id={entry_id}`

## Human Readable Output
---

Indicators from indicator.csv:

|value|type|
|---|---|
| xsoar.com | Domain |
| 8.8.8.8 | IP |
| 8.8.8.8/12 | CIDR |
