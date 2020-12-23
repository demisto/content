This playbook blocks a Destination IP and Service (TCP or UDP port) by creating a rule for a specific Device Group on PAN-OS. 
Supported Cortex XSOAR versions: 5.0.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS Commit Configuration

### Integrations
* Panorama

### Scripts
* SetAndHandleEmpty
* Set

### Commands
* panorama-create-address
* panorama-create-rule
* panorama-create-service
* panorama-list-services

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| LogForwarding | Panorama log forwarding object name. |  | Optional |
| IP | IP address to block. |  | Optional |
| AutoCommit | This input establishes whether to commit the configuration automatically.<br/>True - Commit automatically.<br/>False - Commit manually. | False | Optional |
| DeviceGroup | Target Device Group. |  | Optional |
| Port | Destination port to block. |  | Optional |
| Protocol | Protocol |  | Optional |
| ServiceNamePrefix | Prefix of the Service name to be created. | xsoar-service- | Optional |
| RuleNamePrefix | Prefix of the Rule name to be created. | xsoar-rule- | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS - Block Destination Service](https://raw.githubusercontent.com/demisto/content/8d80d2e630f4a6aafd1fb1a27102d14565d429b1/Packs/PAN-OS/doc_files/PAN-OS_-_Block_Destination_Service.png)
