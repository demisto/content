Find AWS resources by FQDN using Prisma Cloud inventory.
Supported services: EC2, Application Load Balancer, ECS, Route53, CloudFront, S3, API Gateway.

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
| FQDN | FQDN to look up |  | Required |
| AWSDomains | AWS domains \(comma separated\) | .amazonaws.com,.cloudfront.net | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloud.Attribution | Prisma Cloud attributed asset information. | unknown |

## Playbook Image
---
![Prisma Cloud - Find AWS Resource by FQDN](https://raw.githubusercontent.com/demisto/content/852016ad0103ba42e8b5c8f596246fd14a4e7a90/doc_files/Prisma_Cloud_-_Find_AWS_Resource_by_FQDN.png)