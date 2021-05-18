Optionally increases the incident severity to the new value if it is greater than the existing severity.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags |  |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| severity | The incident severity to increase the incident to. Can be "Unknown", "Informational", "Low", "Medium", "High", "Critical", "0", "0.5", "1", "2", "3", or "4".|

## Outputs
---
There are no outputs for this script.


## Script Example
```!IncreaseIncidentSeverity severity=High```


## Human Readable Output
Severity increased to 3
