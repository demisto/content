Use Prisma Access integration to run SSH CLI commands and query the connection states for all tunnels. If any tunnels are down - sends a slack message to the #netops channel.

Can be run as a job or triggered from incoming event to confirm an initial suspicion (such as a tunnel log from Cortex Data Lake) to validate that there is actually still an issue before calling in engineers.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* SlackV2
* PrismaAccess

### Scripts
This playbook does not use any scripts.

### Commands
* send-notification
* prisma-access-query
* closeInvestigation

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

![Playbook Image](https://raw.githubusercontent.com/demisto/content/44148aecb246da472a5cd17e2920fc4f918a2cc9/Packs/PrismaAccess/doc_files/Prisma_Access_Tunnel_Health.png)