This automation extracts all possible files from a PCAP file.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | pcap, file, Utility |
| Demisto Version | 5.5.0 |

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
| PcapExtractedFiles.FileType | File type. | String |
| PcapExtractedFiles.EntryID | The entry ID of the file. | String |
| PcapExtractedFiles.SourceIP | Extracted file source IP. | String |
| PcapExtractedFiles.DestinationIP | Extracted file destination IP. | String |
| PcapExtractedFiles.DetectedInProtocol | Detected protocol. | String |
| PcapExtractedFiles.FileMD5 | The MD5 hash of the file. | String |
| PcapExtractedFiles.FileSHA1 | The SHA1 hash of the file. | String |
| PcapExtractedFiles.FileSHA256 | The SHA256 hash of the file. | String |
| PcapExtractedFiles.FileExtensaion | The extension of the file. | String |
