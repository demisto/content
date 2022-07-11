Downloads PCAPs related to the specified observations. This supports rate throttling.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | protectwise |


## Dependencies
---
This script uses the following commands and scripts.
* observation-pcap-download

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| id | The observation ID. Can be, a comma-separated list of IDs. |
| sensorId | The sensor ID. Can be, a comma-separated list of IDs. |
| filename | The filename provided for the download. |
| burstsize | The download `burstsize` files every time, and wait `waitms` milliseconds each time. The defaults are 10 files and 1 second. |
| waitms | The download `burstsize` files every time, and wait `waitms` milliseconds each time. The defaults are 10 files and 1 second. |

## Outputs
---
There are no outputs for this script.
