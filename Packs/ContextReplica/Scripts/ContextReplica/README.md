Extracts the current incident context or issue context and merges with global contexts and then downloads it as a flattened JSON file. So it will be replica json data of what we see in an  Incident or Issue context in UI view.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility, Context |

## Inputs

---
There are no inputs for this script.

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | The name of the downloaded context file | string |
| File.EntryID | The Entry ID of the downloaded context file | string |
