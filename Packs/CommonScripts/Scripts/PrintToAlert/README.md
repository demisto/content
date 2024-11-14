Prints a value to the specified alert's war-room. The alert must be in status "Under Investigation".

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 8.7.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to print to the war-room of specified alert. |
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
