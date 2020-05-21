Retrieve Prisma Access Egress IP for specific geographic Zones and populate in security groups within cloud services.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* IP Whitelist - AWS Security Group
* IP Whitelist - Okta Zone
* IP Whitelist - GCP Firewall

### Integrations
* PrismaAccessEgressIPFeed

### Scripts
This playbook does not use any scripts.

### Commands
* prisma-access-get-indicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Indicator Query | Indicators matching the indicator query will be used as playbook input |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

<!-- Playbook PNG image comes here -->