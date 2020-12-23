Find GCP resources by Public IP using Prisma Cloud inventory.
Supported services: GCE, Load Balancing, GKE.

Supported Cortex XSOAR versions: 6.0.0 and later.


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* RedLock

### Scripts
This playbook does not use any scripts.

### Commands
* redlock-search-config

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| PublicIPAddress | Public IP Address to look up |  | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloud.Attribution | Prisma Cloud attributed asset information. | unknown |

## Playbook Image
---
![Prisma Cloud - Find GCP Resource by Public IP](https://raw.githubusercontent.com/demisto/content/852016ad0103ba42e8b5c8f596246fd14a4e7a90/doc_files/Prisma_Cloud_-_Find_GCP_Resource_by_Public_IP.png)