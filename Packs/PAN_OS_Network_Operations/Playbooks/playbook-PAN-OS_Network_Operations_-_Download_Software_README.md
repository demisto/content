Download PAN-OS System software.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
* PrintErrorEntry

### Commands
* setIncident
* pan-os-platform-download-software
* pan-os-platform-get-jobs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| target | Target Firewall - Serial or IP address |  | Optional |
| target_version | Target Software Version to Download |  | Optional |
| timeout | Default max timeout value | 45 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Download Software](../doc_files/PAN-OS_Network_Operations_-_Download_Software.png)