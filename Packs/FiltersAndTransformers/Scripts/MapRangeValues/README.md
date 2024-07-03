This script converts an input value into another value using two lists. The input value or range is searched in the first list (map_from). 
If it exists, the value at the same index from the second list (map_to) is returned. If there is no match, the original value is returned.
This script supports mapping from either ranges of float numbers or text strings.

Example 1:

map_from = "1,2,3,4"
map_to = "4,3,2,1"
value = 3

Output is "2"

Example 2:

map_from = "1-3,4"
map_to = "5,1"
value = 3

Output is "5"

map_from = "0,0.5,1,2,3,4"
map_to = "Unknown,Informational,Low,Medium,High,Critical"
value = 3

Output is "High"

map_from = "Unknown,Informational,Low,Medium,High,Critical"
map_to = "0,0.5,1,2,3,4"
value = Informational

Output is "0.5"

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| map_from | A comma-separated list of values to map from. |
| map_to | A comma-separated list of values to map to. |
| sep | The separator between the start and end of range values. |
| value | the input value to map. |

## Outputs

---
There are no outputs for this script.
