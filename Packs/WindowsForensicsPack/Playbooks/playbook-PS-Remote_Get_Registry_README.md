This playbook leverages the windows builtin Powershell and WinRM capabilities to connect to a Windows host to acquire and export the registry as a forensic evidence for further analysis. The capture can be for the entire registry or for a specific hive or path.

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
* ps-remote-export-registry
* ps-remote-download-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Host | The host name for which to export the registry file. For example testpc01 | EC2AMAZ-UIPUP0R | Optional |
| RegistryPath | The registry hive/path to export, if no value is specified the entire registry will be exported. | all | Optional |
| FilePath | The path on the hostname on which to create the registry file. The default path will be c:\\&amp;lt;The host name&amp;gt;.reg | inputs.Host.None | Optional |
| ZipRegistry | Specify true to zip the reg file before sending it to XSOAR. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RegistryDetails | The Registry file details. | string |

## Playbook Image
---
![PS-Remote Get Registry](Insert the link to your image here)