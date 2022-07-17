Adds new events to an existing NetWitness SA incident.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | RSA NetWitness Security Analytics |


## Dependencies
---
This script uses the following commands and scripts.
* nw-add-events-to-incident

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| incidentId | The existing incident ID. (string)  |
| eventList | The list of event IDs separated by a comma (,), this must not include spaces in it. In order to get list of events you can use `nw-get-events`. For example, "23,12,3". (array of strings) |
| alertSummary | The short summary of the alert that will be attached to incident. (string) |
| severity | The severity of the incident. For example, 50. (number) |
| deviceId | The ID of the device/component. For example, Concentrator, Log Decoder, Packet Decoder, etc... from which the events are. The list of devices can be viewed by executing the `command nw-get-components`. (number) |
| incidentManagementId | The ID of the NetWitness INCIDENT_MANAGEMENT device/component ID. It can be received by running `nw-get-component` command. If this argument is not filled/passed, the script will automatically get the first device of type INCIDENT_MANAGEMENT from the SA server. (optional number) |

## Outputs
---
There are no outputs for this script.
