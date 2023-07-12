Executes a command in Cortex XSOAR in debug mode and pulls logs from the command execution.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | troubleshoot |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Integration Troubleshooting

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| command | The command to run. |
| arguments | The arguments of the command. |
| instance_name | The instance name. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TroubleshootExecuteCommand.command | The command executed. | String |
| TroubleshootExecuteCommand.instance_name | On which instance of the integration the command executed. | String |
| TroubleshootExecuteCommand.Error | The errors from the command. | String |
| File.Name | The full file name \(including file extension\). | String |
| File.EntryID | The ID for locating the file in the War Room. | String |
| File.Size | The size of the file in bytes. | Number |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA1 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.SSDeep | The ssdeep hash of the file \(same as displayed in file entries\). | String |
| File.Extension | The file extension, for example: 'xls'. | String |
| File.Type | The file type, as determined by libmagic \(same as displayed in the file entries\). | String |
