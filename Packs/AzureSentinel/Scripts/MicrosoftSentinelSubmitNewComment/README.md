
Use this script to add a comment which will then be mirrored as a comment to a Sentinal event. This script should be run within an incident.

Note: Comments in Cortex XSOAR can only be added when the *Mirroring Direction* in the *Instance Settings* is set to *Incoming* or *Incoming and Outgoing*.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| new_comment | The comment text to be added to the incident comments. | Required |
| incident_id | The ID of the incident to add the comment to. This argument is relevant only when the script is called directly from the War Room. | Optional (Required When the script is called directly from the War Room).|

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AzureSentinel.AddComment.InstanceName | The name of the instance where the comment is added. | string |
| AzureSentinel.AddComment.IncidentId | The ID of the incident where the comment was added. | string |
| AzureSentinel.AddComment.Message | The message of the comment added to the incident. | string |
