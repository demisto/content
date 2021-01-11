This playbook allows the user to gather multiple forensic data from a windows endpoint. Including network traffic, MFT (Master File Table) or registry export by using the PS remote automation which enables to connect to a windows host without the need to install any 3rd party tools using just native Windows management tools.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PS-Remote Get MFT
* PS-Remote Get Network Traffic
* PS-Remote Get Registry

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| GetNetworkTraffic | This input specifies whether to capture network traffic on the host. | true | Optional |
| GetMft | This input specifies whether to acquire the MFT for the host. | true | Optional |
| GetRegistry | This input specifies whether to export the registry on the host. | true | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PcapDetails | Pcap file details. | string |
| RegistryDetails | Registry file details. | string |
| MftDetails | MFT file details | string |

## Playbook Image
---
![PS-Remote Acquire Host Forensics](https://raw.githubusercontent.com/demisto/content/0b9313b1f786faac00ad2d0e2fbb49e59a37d4b3/Packs/WindowsForensicsPack/doc_files/PS-Remote__Acquire_Host_Forensics.png)