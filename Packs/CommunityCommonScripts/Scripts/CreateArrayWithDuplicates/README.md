Will create an array object in context from a given string input , allowing for duplicate values to be retained

Output is to ContextKey.array as JSON does not permit duplicate key names

e.g., ContextKey.array.value1, ContextKey.array.value2, ContextKey.array.value3, etc.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| arrayData | This is the array data to create array from, should be in the format of comma separator by default: val1,val2,val3 |
| separator | Separator to use to split arrayData, by default will be comma ',' . |
| contextKey | The key to place result array in context, by default will be "array". |

## Outputs

---
There are no outputs for this script.
