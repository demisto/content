This script updates an indicator's grid field in Cortex XSOAR with provided row data. You can input the rows directly or extract them from the context.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | The value of the indicator to be updated. |
| grid_field | The name of the grid field you want to update. |
| headers | A comma-separated string listing the column headers for the grid. |
| input | Either a JSON or list of lists. This argument is mandatory. |
| keys_from_context | A comma-separated string listing the keys to extract values from the provided dictionaries in the input. The extracted values will be mapped to the headers in the order provided. |
| append | When set to True, appends the new content to the existing grid content instead of overwriting it. |

## Outputs

---
There are no outputs for this script.
