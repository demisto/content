This script is used to set owner in remote system.

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
| owner_email | The owner email to set as user principal name. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AzureSentinel.Incident.Owner.assignedTo | The name of the person assigned as the owner. | string |
| AzureSentinel.Incident.Owner.email | The email of the new owner. | string |
| AzureSentinel.Incident.Owner.objectId | The object ID of the new owner. | string |
| AzureSentinel.Incident.Owner.userPrincipalName | The user principal name of the new owner. | string |
