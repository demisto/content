Periodically runs the `IncapWhitelistCompliance` script, which queries the Incapsula monitored websites for white-list compliance (see script for further details).
The script then saves the new periodic ID into incident context under the `ScheduleTaskID` key for later use.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Incapsula |


## Dependencies
---
This script uses the following commands and scripts.
* scheduleEntry
* IncapWhitelistCompliance

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| SSHValidationServer | The name of the non-allow listed server RemoteAccess instance. |
| cron | The interval between each check (in cron format). |
| times | The number of times to execute the check. |

## Outputs
---
There are no outputs for this script.
