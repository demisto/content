This script is used to add a new comment to incident.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| new_comment | The comment text to be added to the incident comments. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AzureSentinel.AddComment.InstanceName | The name of the instance where the comment is added. | string |
| AzureSentinel.AddComment.IncidentId | The ID of the incident where the comment was added. | string |
| AzureSentinel.AddComment.Message | The message of the comment added to the incident. | string |
