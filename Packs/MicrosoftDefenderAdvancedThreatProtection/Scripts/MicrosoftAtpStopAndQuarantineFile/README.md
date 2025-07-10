A polling wrapper script; Stop the execution of a file on a machine and delete it.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utilities |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| machine_id | The machine ID. When providing multiple values, each value is checked for the same hash. |
| file_hash | The file SHA1 hash to stop and quarantine on the machine.<br/>When providing multiple values, each value is checked for the same machine_id. |
| comment | Comment to associate with the action. |
| ran_once_flag | Flag for the rate limit retry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | String |
| MicrosoftATP.MachineAction.Type | The type of the action. | String |
| MicrosoftATP.MachineAction.Scope | The scope of the action. | String |
| MicrosoftATP.MachineAction.Requestor | The ID of the user that executed the action. | String |
| MicrosoftATP.MachineAction.RequestorComment | The comment that was written when issuing the action. | String |
| MicrosoftATP.MachineAction.Status | The current status of the command. | String |
| MicrosoftATP.MachineAction.MachineID | The machine ID on which the action was executed. | String |
| MicrosoftATP.MachineAction.ComputerDNSName | The machine DNS name on which the action was executed. | String |
| MicrosoftATP.MachineAction.CreationDateTimeUtc | The date and time the action was created. | Date |
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | The last date and time the action status was updated. | Date |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | The file identifier. | String |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | The file identifier type. Possible values: "SHA1" ,"SHA256", and "MD5". | String |
