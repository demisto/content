## Prisma Access Content Pack
---

This content pack enables XSOAR to integrate with Palo Alto Networks Prisma Access. It includes 2 integrations.


### Prisma Access Egress IP feed
---

Dynamically retrieve and allow IPs Prisma Access uses to egress traffic to the internet and SaaS apps.

This integration can be used as a TIM feed to fetch indicators, or if a playbook starts from a non-indicator trigger it can use the command to get the IPs.


### Prisma Access
---

Integrate with Prisma Access to query the status of the service and take actions.

The integration includes commands to:
 - Force logout a specific user from Prisma Access
 - List currently active users
 - Run a Prisma Access query (e.g. getGPaaSLast90DaysUniqueUsers)
 - Run a custom CLI command

The integration uses both the Panorama XML API and SSH into the PAN-OS CLI. SSH is based on the netmiko library and will use the netmiko docker image.