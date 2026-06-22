Device Security alert post processing script to resolve the alert in Device Security portal using API.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | device security, post-processing |
| Cortex XSOAR Version | 5.5.0 |

This script executes the 'device-security-resolve-alert' command to resolve an alert in PANW Device Security portal during post-processing.

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| close_reason | The reason the alert was closed \(either 'Resolved' or 'No Action Needed'\). |

## Outputs

---
There are no outputs for this script.
