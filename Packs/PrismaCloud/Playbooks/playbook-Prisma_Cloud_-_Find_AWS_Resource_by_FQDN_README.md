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
![Prisma Cloud - Find AWS Resource by FQDN](https://raw.githubusercontent.com/demisto/content/8d80d2e630f4a6aafd1fb1a27102d14565d429b1/Packs/PrismaCloud/Playbooks/playbook-Prisma_Cloud_-_Find_AWS_Resource_by_FQDN.png)