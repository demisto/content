Runs the xsoaredlchecker-get-edl command for all configured instances, and returns a consolidated output.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities, training |
| Cortex XSOAR Version | 6.5.0 |

## Dependencies
---
This script uses the following commands and scripts.
* xsoaredlchecker-get-edl

## Inputs
---
There are no inputs for this script.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EDLChecker.Name | The Name of the EDL from the Generic Indicators Export Service instance | Unknown |
| EDLChecker.Status | The HTTP Status Code returned by the EDL | Unknown |
| EDLChecker.Response | The Response or Error from the check. | Unknown |
| EDLChecker.ItemsOnList | The number of indicators on the list, assuming a successful response\! | Unknown |
