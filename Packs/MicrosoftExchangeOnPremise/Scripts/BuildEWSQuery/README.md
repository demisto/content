Returns an EWS query according to the automation's arguments.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | ews |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| from | The value of the email's **From** attribute. |
| subject | The value of the email's **Subject** attribute. |
| attachmentName | The value of the email's **attachmentName** attribute. |
| body | The value of the email's **Body** attribute. |
| searchThisWeek | Whether to limit the search to the current week. Must be "true" or "false". |
| stripSubject | Removes the prefix from the subject of reply and forward messages (e.g., FW:). |
| escapeSemicolons | Whether to escape the semicolons. Must be "true" or "false". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EWS.Query | The result query. | string |
