This automation extracts all possible files from a PCAP file.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | pcap, file, Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The EntryID of the PCAP file to extract the files from. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PcapExtractedFiles.FileName | File name. | String |
| PcapExtractedFiles.FileSize | File size. | Number |
| PcapExtractedFiles.FileMD5 | The MD5 hash of the file. | String |
| PcapExtractedFiles.FileSHA1 | The SHA1 hash of the file. | String |
| PcapExtractedFiles.FileSHA256 | The SHA256 hash of the file. | String |
| PcapExtractedFiles.FileExtension | The extension of the file. | String |
| File.Size | The size of the file in bytes. | Number |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.Name | The full file name. | String |
| File.SSDeep | The ssdeep hash of the file. | String |
| File.EntryID | The ID for locating the file in the War Room. | String |
| File.Info | The file information. | String |
| File.Type | The file type. | String |
| File.MD5 | The MD5 hash of the file. | String |
| File.Extension | The file extension, for example: 'txt'. | String |
