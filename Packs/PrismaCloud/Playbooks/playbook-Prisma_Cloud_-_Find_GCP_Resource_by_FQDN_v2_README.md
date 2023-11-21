Find GCP resources by FQDN using Prisma Cloud inventory.
Supported services: Cloud DNS.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

PrismaCloud v2

### Scripts

* SetAndHandleEmpty
* PrismaCloudAttribution

### Commands

prisma-cloud-config-search

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FQDN | FQDN to look up. |  | Required |
| GCPDomains | A comma-separated list of GCP domains. | .google.com | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloud.Attribution | Prisma Cloud attributed asset information. | unknown |

## Playbook Image

---

![Prisma Cloud - Find GCP Resource by FQDN v2](../doc_files/Prisma_Cloud_-_Find_GCP_Resource_by_FQDN_v2.png)
