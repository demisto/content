This playbook leverages the windows builtin Powershell and WinRM capabilities to connect to a Windows host to acquire and export the MFT (Master File Table) as a forensic evidence for further analysis.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* PowerShellRemoting

### Scripts
This playbook does not use any scripts.

### Commands
* ps-remote-download-file
* ps-remote-export-mft

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Host | The host name for which to export the registry file. For example testpc01 |  | Optional |
| FilePath | The path on the hostname on which to create the registry file. For example c:\\mft.mft | c:\mft.mft | Optional |
| VolumeForMft | Specify the volume for which to create the MFT, The default is c.<br/> | c | Optional |
| ZipMft | Specify true to zip the MFT file before sending it to XSOAR. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MftDetails | The MFT file details. | string |

## Playbook Image
---
![PS-Remote Get MFT](https://raw.githubusercontent.com/demisto/content/0b9313b1f786faac00ad2d0e2fbb49e59a37d4b3/Packs/WindowsForensicsPack/doc_files/PS-Remote_Get_MFT.png)