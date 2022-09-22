This playbook is part of the 'Malware Investigation And Response' pack. For more information, refer to https://xsoar.pan.dev/docs/reference/packs/malware-investigation-and-response.
This playbook uses the Live Response feature to retrieve a file from an endpoint./nNote that the endpoint id will be set from the incident field "Device ID".

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* MicrosoftDefenderAdvancedThreatProtection

### Scripts
* UnzipFile
* isError
* DeleteContext

### Commands
* microsoft-atp-live-response-get-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| paths | The file paths to be provided. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![MDE - Retrieve File](../doc_files/MDE_-_Retrieve_File.png)