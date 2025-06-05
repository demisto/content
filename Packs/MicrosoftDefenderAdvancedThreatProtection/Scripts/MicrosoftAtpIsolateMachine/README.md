Isolates a machine from accessing external networks.

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
| machine_id | A comma-separated list of machine IDs to be used for isolation. e.g., 0a3250e0693a109f1affc9217be9459028aa8426,0a3250e0693a109f1affc9217be9459028aa8424. |
| comment | A comment to associate with the action. |
| isolation_type | Full isolation or selective isolation. \(Restrict only limited set of applications from accessing the network\). |
| ran_once_flag | Flag for the rate limit retry. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | String |
| MicrosoftATP.MachineAction.Type | Type of the machine action. | String |
| MicrosoftATP.MachineAction.Scope | Scope of the action. | Unknown |
| MicrosoftATP.MachineAction.Requestor | The ID of the user that executed the action. | String |
| MicrosoftATP.MachineAction.RequestorComment | Comment that was written when issuing the action. | String |
| MicrosoftATP.MachineAction.Status | The current status of the command. | String |
| MicrosoftATP.MachineAction.MachineID | The machine ID on which the action was executed. | String |
| MicrosoftATP.MachineAction.ComputerDNSName | The machine DNS name on which the action was executed. | String |
| MicrosoftATP.MachineAction.CreationDateTimeUtc | The date and time when the action was created. | Date |
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | The last date and time when the action status was updated. | Date |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | The file identifier. | String |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | The type of the file identifier. Possible values: "SHA1" ,"SHA256", and "MD5". | String |
