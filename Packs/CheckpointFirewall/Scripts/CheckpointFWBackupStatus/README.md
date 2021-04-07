Connects a Checkpoint firewall appliance using SSH and retrieves the status of backup tasks. The user account that accesses the device must be setup to use the SSH shell and not the built in Checkpoint CLI. Consult the Checkpoint documentation for instructions on how to do this.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | checkpoint |


## Dependencies
---
This script uses the following commands and scripts.
* ssh

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| devices | The list of devices to backup (comma-separated). |
| waittimeout | The wait time in seconds. If not provided, it will not wait. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckpointBackup.DeviceName | The name of the backed-up device. | Unknown |
| CheckpointBackup.System | The backed up system. | Unknown |
| CheckpointBackup.Status | The status of the backup process. | Unknown |
| CheckpointBackup.Path | The path of the backup file. | Unknown |
