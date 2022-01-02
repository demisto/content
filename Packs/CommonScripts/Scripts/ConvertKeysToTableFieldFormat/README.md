Converts object keys to match table keys. Use this when mapping object/collection to table (grid) field.
(An array of objects/collections is also supported).

Example:
 * Input: { "Engine": "val1", "Max Results": 13892378, "Key_With^Special   (characters)": true }
 * Output: { "engine": "val1", "maxresults": 13892378, "keywithspecialcharacters": true }

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | transformer |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The object to convert. |

## Outputs
---
There are no outputs for this script.
