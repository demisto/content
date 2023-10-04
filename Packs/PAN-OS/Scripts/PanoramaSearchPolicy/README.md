Automation that searches for a security policy by name for all device-groups found on Panorama to include "shared".  If found, output is the same as the !pan-os-list-rules command.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Panorama
* pan-os-list-rules
* pan-os-platform-get-device-groups

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| rule_name | policy rule name to search. |

## Outputs

---
There are no outputs for this script.
