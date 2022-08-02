This playbook uses generic polling to get machine action information.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
**GenericPolling**

### Integrations
**MicrosoftDefenderAdvancedThreatProtection**

### Scripts
This playbook does not use any scripts.

### Commands
***microsoft-atp-list-machine-actions-details***

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| machine_action_id |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | The machine action ID. | string |
| MicrosoftATP.MachineAction.Type | Action type. | string |
| MicrosoftATP.MachineAction.Scope | Scope of the action. | unknown |
| MicrosoftATP.MachineAction.Requestor | The ID of the user that executed the action. | string |
| MicrosoftATP.MachineAction.RequestorComment | Comment that was written when issuing the action. | string |
| MicrosoftATP.MachineAction.Status | The current status of the command. | string |
| MicrosoftATP.MachineAction.MachineID | The machine ID on which the action was executed. | string |
| MicrosoftATP.MachineAction.ComputerDNSName | The machine DNS name on which the action was executed. | string |
| MicrosoftATP.MachineAction.CreationDateTimeUtc | The date and time when the action was created. | date |
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | The last date and time when the action status was updated. | date |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | The file identifier. | string |
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | The type of the file identifier with the possible values: "Sha1" ,"Sha256" and "Md5" | string |
