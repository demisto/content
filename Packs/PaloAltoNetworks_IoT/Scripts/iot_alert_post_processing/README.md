IoT alert post processing script to resolve the alert in IoT security portal using API.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | iot, post-processing |
| Cortex XSOAR Version | 5.5.0 |

This script executes the 'iot-security-resolve-alert' command to resolve an alert in PANW IoT security portal during post-processing.

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| close_reason | The reason the alert was closed \(either 'Resolved' or 'No Action Needed'\). |

## Outputs
---
There are no outputs for this script.
