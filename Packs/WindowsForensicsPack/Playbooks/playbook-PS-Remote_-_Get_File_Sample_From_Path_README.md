This playbook leverages the windows builtin Powershell and WinRM capabilities to connect to a Windows host to acquire and acquire a file as forensic evidence for further analysis.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* UnzipFile
* AddEvidence
* IsIntegrationAvailable
* Set

### Commands
* ps-remote-download-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Host | Hostname of the machine on which the file is located. For example testpc01 | EC2AMAZ-UIPUP0R | Optional |
| FilePath | The path on the hostname from which to retrieve the file. <br/>For example c:\\tmp\\test.txt<br/>In case you use the AddHostNameToFile input as true the file downloaded to XSOAR will be comprised of the hostname. | C:\test.txt.txt | Optional |
| ZipFile | Specify true to zip the MFT file before sending it to XSOAR. | true | Optional |
| AddHostNameToFile | Specify true for the downloaded file name to be comprised of the host name or false  to keep the file name as configured in the FilePath argument. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AcquiredFile | The acquired file details. | string |

## Playbook Image
---
![PS Remote - Get File Sample From Path](Insert the link to your image here)