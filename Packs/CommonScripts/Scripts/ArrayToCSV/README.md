Converts a simple Array into a textual comma separated string

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | An array of strings input |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!ArrayToCSV value=`["example","example"]````
### Context Example
```json
{}
```

### Human Readable Output

>example,example

### Example command
```!ArrayToCSV value="example,example,example"```
### Context Example
```json
{}
```

### Human Readable Output

>example,example,example
