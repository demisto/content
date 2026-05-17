Extracts the current incident context or issue context, merges it with global contexts, and then downloads it as a flattened JSON file. This provides a replica of the JSON data seen in an Incident or Issue context in the UI.

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
