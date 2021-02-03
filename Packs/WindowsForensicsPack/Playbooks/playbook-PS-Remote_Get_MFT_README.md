This playbook leverages the windows builtin Powershell and WinRM capabilities to connect to a Windows host to acquire and export the MFT (Master File Table) as a forensic evidence for further analysis.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* UnzipFile
* AddEvidence
* Set
* Sleep

### Commands
* ps-remote-export-mft
* ps-remote-download-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Host | The host name for which to export the registry file. For example testpc01 |  | Optional |
| FilePath | The path on the hostname on which to create the MFT file. The default path will be c:\\mft.mft<br/>In case you use the AddHostNameToFile input as true the file downloaded to XSOAR will be comprised of the hostname. | c:\mft.mft | Optional |
| VolumeForMft | Specify the volume for which to create the MFT, The default is c.<br/> | c | Optional |
| ZipMft | Specify true to zip the MFT file before sending it to XSOAR. | true | Optional |
| AddHostNameToFile | Specify true for the downloaded file name to be comprised of the host name or false  to keep the file name as configured in the FilePath argument. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MftDetails | The MFT file details. | string |

## Playbook Image
---
![PS-Remote Get MFT](Insert the link to your image here)