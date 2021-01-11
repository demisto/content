This playbook allows the user to analyze forensic evidence acquired from a host. Such as registry files, memory dump files or PCAP files.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Regipy Data Analysis
* PCAP Search

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
| PcapEntryID | The entryid for the PCAP file to analyze. |  | Optional |
| RegistryEntryId | The entryid for the registry file to analyze. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Forensics Tools Analysis](https://raw.githubusercontent.com/demisto/content/0b9313b1f786faac00ad2d0e2fbb49e59a37d4b3/Packs/WindowsForensicsPack/doc_files/Forensics_Tools_Analysis.png)