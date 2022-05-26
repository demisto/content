This playbook aims to simplify the collection of investigation package retrieval into XSOAR from only supported machines (according to the article -  https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/collect-investigation-package?view=o365-worldwide). 

The playbook receives information regarding the target devices (by hostnames, IPs, device ids), validates that those devices exist, and retrieves the collection package from those machines into the XSOAR console. Note that this action may time and the average size of such a package is around ~15 MB.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Microsoft Defender Advanced Threat Protection

### Scripts
This playbook does not use any scripts.

### Commands
* endpoint
* microsoft-atp-request-and-download-investigation-package

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoCollectinvestigationPackege | Choose if to skip user validation on retrieving the Investigation pack within the provided assets. | True | Optional |
| Hostnames | Comma-separated values of hostnames |  | Optional |
| MachineIDs | Comma-separated values of machine IDs |  | Optional |
| IPs | Comma-separated values of machine IPs |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP.MachineAction | Microsoft Defender For Endpoint machine action details. | unknown |

## Playbook Image
---
![Microsoft Defender For Endpoint - Collect investigation package](../doc_files/Microsoft_Defender_For_Endpoint_-_Collect_investigation_package.png)