Find tables inside HTML and extract the contents into objects using the following logic:
- If the table has a single column, just create an array of strings from the values.
- If the table has 2 columns and has no header row, treat the first column as the key and the second column as the value and create a table for the key/value.
- If the table has a header row, create a table of objects where the attribute names are the headers.
- If the table does not have a header row, create table of objects where attribute names are cell1, cell2, cell3...

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| html | The HTML to extract the tables from. |
| indexes | Extracts only the tables with given indexes. IT will be, 0 based. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HTMLTables | The extracted HTML tables. | Unknown |
