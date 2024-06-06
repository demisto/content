Prints a value to the specified alert's warroom.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to print to the warroom of specified alert. |
| alert_id | The alert ID to print to. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!PrintToAlert alert_id=5 value="Hello from the other side"```

## Context Example
```json
{}
```

## Human Readable Output

>Successfully printed to alert 5.
