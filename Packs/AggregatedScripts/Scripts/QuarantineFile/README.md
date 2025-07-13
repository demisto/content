This script executes the ***quarantine-file*** command on a specified file via the appropriate agent. This script is used to isolate files identified as suspicious. The integration used to perform the quarantine action is selected either by user input or based on the available configured instances.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| endpoint_ids | List of endpoint IDs. |
| file_hash | Hash of the file. Supported types are: SHA1, SHA256. |
| file_path | Path of the file to quarantine. |
| timeout | Polling timeout in seconds for the quarantine commands. |
| quarantine_brands | Integrations brands to use for running quarantine-file. If not provided, the command will run the command for all relevant integrations by file_hash that implement quarantine-file command.<br/>For multi-select, provide a comma-separated list of integration IDs. For example: "Microsoft Defender Advanced Threat Protection, Cortex Core - IR". |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QuarantineFile.FilePath. | Path of the file that was quarantined. | String |
| QuarantineFile.FileHash. | Hash of the file. | String |
| QuarantineFile.Status | whether the command was running succussefully or not. | Boolean |
| QuarantineFile.Result | whether the command was running succussefully or not. | String |
| QuarantineFile.Message | If the command run successfully - message for success else message that contain the error. | String |
| QuarantineFile.Brand | The integration that used to run the command. | String |
| QuarantineFile.EndpointID | The endpoint_id which the command was executed on. | String |
