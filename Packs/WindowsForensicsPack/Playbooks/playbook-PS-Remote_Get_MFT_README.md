This playbook leverages the windows builtin Powershell and WinRM capabilities to connect to a Windows host to acquire and export the MFT (Master File Table) as a forensic evidence for further analysis.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* UnzipFile
* Sleep
* Set

### Commands
* ps-remote-export-mft
* ps-remote-download-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Host | The host name for which to export the registry file. For example testpc01 |  | Optional |
| FilePath | The path on the hostname on which to create the registry file. The default path will be c:\\&amp;lt;The host name&amp;gt;.mft | inputs.Host.None | Optional |
| VolumeForMft | Specify the volume for which to create the MFT, The default is c.<br/> | c | Optional |
| ZipMft | Specify true to zip the MFT file before sending it to XSOAR. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MftDetails | The MFT file details. | string |

## Playbook Image
---
![PS-Remote Get MFT](Insert the link to your image here)