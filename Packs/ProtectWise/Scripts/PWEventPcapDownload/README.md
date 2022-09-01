Downloads PCAPs related to the requested events. This supports rate throttling.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | protectwise |


## Dependencies
---
This script uses the following commands and scripts.
* event-pcap-download

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| eventId | The event ID(s). (comma-seperated)|
| filename | The filename for the download. |
| burstsize | Downloads `burstsize` files every time, and wait `waitms` milliseconds each time. The defaults are 10 files and 500ms. |
| waitms | Downloads `burstsize` files every time, and wait `waitms` milliseconds each time. The defaults are 10 files and 500ms. |

## Outputs
---
There are no outputs for this script.
