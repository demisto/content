This script executes the 'quarantine-file' command on a specified file via the appropriate agent. This script is used to isolate files identified as suspicious.

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
| endpoint_id | A comma-separated list of endpoint IDs. |
| file_hash | The hash of the file to quarantine. Supported types are: SHA1, SHA256. |
| file_path | The path of the file to quarantine. |
| timeout | The polling timeout in seconds for the quarantine commands. |
| quarantine_brands | Integrations to execute the 'quarantine-file' command. If not specified, the integration will be automatically selected based on the file hash type and the available configured instances.<br/>To specify multiple integrations, provide a comma-separated list of integration brand IDs \(e.g., "Palo Alto Networks Cortex XDR - Investigation and Response, Cortex Core - IR"\). |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QuarantineFile.FilePath. | The path of the quarantined file. | String |
| QuarantineFile.FileHash. | The hash of the quarantined file. | String |
| QuarantineFile.Status | Whether the command execution was successful or not. | String |
| QuarantineFile.Message | A success message if the command runs successfully, otherwise a message that contains the error. | String |
| QuarantineFile.Brand | The integration that executed the command. | String |
| QuarantineFile.EndpointID | The endpoint_id which the command was executed on. | String |