Parses PCAP files and returns, the extracted files that are found, HTTP flows, and other information. PCAPMiner uses a Docker instance located on the Docker hub `trorabaugh/dempcap:1.0`.  To use this script, upload a PCAP file and then run `PCAPMiner entryId="<your_entry_id>"`. To get the entry ID, click on the link on the top right hand corner of a file attachment.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility, file, pcap |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entryId | The entryID of the file. |
| demistoLibLocation | The Demisto lib location. The default is "/var/lib/demisto/". |

## Outputs
---
There are no outputs for this script.
