This script gathers file reputation data from multiple integrations and returns a File entity with consolidated information to the context output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| file_hash | Hash of the file. Supported types are: MD5, SHA1, SHA256, and SHA512. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select, provide a comma-separated list. For example: "VirusTotal (API v3),Cortex Core - IR". |
| verbose | Whether to retrieve human readable entry for every command or only the final result. Set to true to get a human-readable entry for every command. Set to false to get a human-readable summary of the final result. |
| external_enrichment | Whether to run additional external indicator enrichment commands. Set to true to enrich with information from the specified source brands. Set to false to only query for existing indicators in the Threat Intelligence Module (TIM). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | The name of the associated file. | String |
| File.Extension | The file extension. | String |
| File.Type | The file type. | String |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.Size | The file size in bytes. | String |
| File.Signature.Authentihash | The authentihash of the file signature. | String |
| File.Signature.Copyright | The copyright information in the file signature. | String |
| File.Signature.Description | The description provided in the file signature. | String |
| File.Signature.FileVersion | The file version from the file signature. | String |
| File.Signature.InternalName | The internal name from the file signature. | String |
| File.Signature.OriginalName | The original name of the file from the file signature. | String |
| File.SSDeep | The SSDeep fuzzy hash of the file. | String |
| File.Tags | The tags associated with the file. | Array |
