Parses a list by header and value.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Value to search for. If you supply a value, you need to supply the "header" argument also. |
| header | Header to filter lines by. If you supply a header, you need to supply the "value" argument. |
| list_name | The list name in which to search. |
| parse_all | If "True", parses the entire list into the context. Can be "True" or "False". Default is "False". |
| list_separator | Separator to split the list by (use \\\t in case of tab separated list). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GetListRow.Header | Header in which the search was performed. | String |
| GetListRow.Value | Value to search for. | String |
| GetListRow.ListName | The name of the list that was searched.. | String |
| GetListRow.ParseAll | If "True", the entire list was parsed into the context. | String |
| GetListRow.Results | All parse results of the list. | UnKnown |
