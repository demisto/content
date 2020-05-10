Creates a schedule task that's called `ImpSfRevokeUnaccessedDevices`.
Gets all of a device's data from the server. If a device hasn't been accessed in over two months (and is still managed), the script will send the corresponding user a warning mail.
If the device hasn't been accessed in over three months, the script will revoke the device credentials and notify the user by mail.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Imperva Skyfence |


## Dependencies
---
This script uses the following commands and scripts.
* scheduleEntry
* ImpSfRevokeUnaccessedDevices

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| cron | The interval between each check (in cron format). |
| times | The number of times to execute the check. |

## Outputs
---
There are no outputs for this script.
