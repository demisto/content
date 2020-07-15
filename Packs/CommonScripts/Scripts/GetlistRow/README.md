Parse list by header and value.
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
| value | Value to search for \(You also need to enter header\). |
| header | Header to search in \(You also need to enter value\)/ |
| list_name | The list name to search in. |
| parse_all | Parse all the list into the context. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GetListRow.Result.Header | Header to search in. | String |
| GetListRow.Result.Value | Value to search for. | String |
| GetListRow.Result.List_Name | The list name to search in. | String |
| GetListRow.Results.Parse_All | Parse all the list into the context. | String |
