Find tables inside HTML and extract the contents into objects using the following logic:

- If table has 2 columns and has no header row, treat the first column as key and second as value and create a table of key/value
- If table has a header row, create a table of objects where attribute names are the headers
- If table does not have a header row, create table of objects where attribute names are cell1, cell2, cell3...

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The HTML to extract tables from |
| title | The title for tables |
| filter_indexes | Extract only the tables with given indexes - 0 based |
| filter_titles | Extract only the tables with given titles |

## Outputs
---
There are no outputs for this script.
