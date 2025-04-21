Prints a value to the specified incident's war-room.

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
| value | The value to print to the war-room of specified incident. |
| incident_id | The incident ID to print to. |

## Outputs
---
There are no outputs for this script.


## Script Example
```!PrintToIncident incident_id=INCIDENT-8 value="Hello from the other side"```

## Context Example
```json
{}
```

## Human Readable Output

>Successfully printed to incident INCIDENT-8.
