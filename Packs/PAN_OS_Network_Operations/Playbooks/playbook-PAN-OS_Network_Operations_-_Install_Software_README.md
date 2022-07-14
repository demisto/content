Installs PAN-OS system software.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
* PrintErrorEntry

### Commands
* pan-os-platform-install-software
* setIncident
* pan-os-platform-get-jobs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| target_version | Target Version to INstall |  | Optional |
| target | Target Device |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PAN-OS Network Operations - Install Software](../doc_files/PAN-OS_Network_Operations_-_Install_Software.png)