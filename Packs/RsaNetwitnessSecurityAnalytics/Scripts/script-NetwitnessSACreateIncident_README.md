Creates an incident inside NetWitness SA from a set of NetWitness events.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | RSA NetWitness Security Analytics |


## Dependencies
---
This script uses the following commands and scripts.
* nw-create-incident

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| alertSummary | The short summary of the alert which will be attached to incident. (string) |
| severity | The severity level. The default set to "50". (optional string) |
| name | The name of the incident. (string) |
| assigned | Sets the assignee login name if the assignee has changed. You can execute `nw-get-available-assignees` to get the list of users. For example, demisto123. (optional string) |
| eventList | The list of event IDs separated by comma (,). This must not include spaces in it. In order to get the list of events you can should use the `nw-get-events` command. |
| deviceId | The ID of the device/component (Concentrator, Log Decoder, Packet Decoder, etc.) from which the events are retrieved. The list of devices can be retrieved by executing the `command nw-get-components`. |
| priority | The priority of the incident. |
| summary | The summary of the incident. |
| incidentManagementId | The ID of NetWitness INCIDENT_MANAGEMENT device/component ID. It can be received by running `nw-get-component` command. If this argument is not filled/passed, the script will automatically get the first device of type INCIDENT_MANAGEMENT from the SA server. (optional number) 

## Outputs
---
There are no outputs for this script.
