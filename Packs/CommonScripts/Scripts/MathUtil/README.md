Runs the provided mathematical action on 2 provided values and produce a result.
The result can be stored on the context using the `contextKey` argument.

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
| lh | The left hand parameter. |
| rh | The right hand parameter. |
| action | The math expression (+, -, >, <, ==, *, /, %). |
| rhRegex | The regex used to filter only a specific part of the right hand argument. |
| lhRegex | The regex used to filter only a specific part of the left hand argument. |
| lhRadix | The radix for the left hand value. The default is 10. |
| rhRadix | Radix for right hand value, defaults to 10 |
| contextKey | The path to store the result. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MathResult | The result of the math action. This might be overriden by `contextKey`. | Unknown |
