Extracts the domain risk list from the recorded future and creates indicators accordingly.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | RecordedFuture |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| list | Specifies a domain list by a risk rule name. This can be retrieved with the `get-domain-riskrules` command. |
| threshold | The minimum threshold score to consider indicators as malicious (65-99, greater than or equal to). |
| delete_existing | Wether to delete the existing recorded future's malicious domain indicators. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| InfoFile.Name | The name of the file. | string |
| InfoFile.EntryID | The entry ID of the file. | string |
| InfoFile.Size | The size of the file. | number |
| InfoFile.Type | The type of teh file. For example, "PE". | string |
| InfoFile.Info | The basic information of the file. | string |
| InfoFile.Extension | The extension of the file. | string |
