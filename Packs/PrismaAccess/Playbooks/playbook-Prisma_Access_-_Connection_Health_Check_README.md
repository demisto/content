Use Prisma Access integration to run SSH CLI commands and query the connection states for all tunnels. If any tunnels are down - Escalates to manual task for remediation and provides recommendations on next steps in the task description.

Can be run as a job or triggered from incoming event to confirm an initial suspicion (such as a tunnel log from Cortex Data Lake) to validate that there is actually still an issue before calling in engineers.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* PrismaAccess

### Scripts
This playbook does not use any scripts.

### Commands
* prisma-access-query
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Prisma Access - Connection Health Check](https://raw.githubusercontent.com/demisto/content/b3a446de893a8ab8b0b256640c206d7533f45ae6/Packs/PrismaAccess/doc_files/Prisma_Access_Tunnel_Health.png)