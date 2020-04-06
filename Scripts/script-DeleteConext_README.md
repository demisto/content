Deletes fields from context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to delete from the context. |
| all | Whether all context will be deleted. |
| subplaybook | Whether the context key is inside of a sub-playbook. Use **auto** to delete either from the sub-playbook context (if the playbook is called as a sub-playbook) or from the global context (if the playbook is the top playbook). |
| keysToKeep | The context keys to keep when deleting all context. Supports comma-separated values and nested objects. For example, "URL.Data" and "IP.Address". |
| index | The index to delete in case the 'key' argument was specified. |

## Outputs
---
There are no outputs for this script.
