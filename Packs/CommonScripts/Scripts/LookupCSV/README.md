Parses a CSV and looks for a specific value in a specific column, returning a dict of the entire matching row. If no column value is specified, the entire CSV is read into the context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | file, csv, Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entryID | EntryID of CSV file. |
| header_row | CSV file has a header row. |
| column | Column to search for value in, if not specified, entire CSV is parsed into the context. |
| value | value to search for |
| add_header_row | Extra row, in CSV format, to function as header if original does not contain headers |

## Outputs

---

| **Path**              | **Description** | **Type** |
|-----------------------| --- | --- |
| LookupCSV.Result      | List of result objects; either a list of dicts \(with header_row\) or a list of lists \(no header row\) | Unknown |
| LookupCSV.FoundResult | Boolean, for whether the result was found in the CSV or not. | Unknown |
| LookupCSV.SearchValue | The value that was searched. | Unknown |
