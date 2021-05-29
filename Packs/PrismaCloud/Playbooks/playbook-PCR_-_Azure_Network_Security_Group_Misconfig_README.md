This playbook remediates the following Prisma Cloud Azure Network security group alerts.

Prisma Cloud policies remediated:

- Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source on any protocol
- Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source on TCP protocol
- Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source on UDP protocol
- Azure Network Security Group (NSG) allows SSH traffic from internet on port 22
- Azure Network Security Group (NSG) allows traffic from internet on port 3389
- Azure Network Security Group allows DNS (TCP Port 53)
- Azure Network Security Group allows FTP (TCP Port 21)
- Azure Network Security Group allows FTP-Data (TCP Port 20)
- Azure Network Security Group allows MSQL (TCP Port 4333)
- Azure Network Security Group allows MySQL (TCP Port 3306)
- Azure Network Security Group allows Windows RPC (TCP Port 135)
- Azure Network Security Group allows Windows SMB (TCP Port 445)
- Azure Network Security Group allows PostgreSQL (TCP Port 5432)
- Azure Network Security Group allows SMTP (TCP Port 25)
- Azure Network Security Group allows SqlServer (TCP Port 1433)
- Azure Network Security Group allows Telnet (TCP Port 23)
- Azure Network Security Group allows VNC Listener (TCP Port 5500)
- Azure Network Security Group allows all traffic on ICMP (Ping)
- Azure Network Security Group allows CIFS (UDP Port 445)
- Azure Network Security Group allows NetBIOS (UDP Port 137)
- Azure Network Security Group allows NetBIOS (UDP Port 138)
- Azure Network Security Group allows SQLServer (UDP Port 1434)
- Azure Network Security Group allows DNS (UDP Port 53)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* Azure Network Security Groups

### Scripts
* IsIntegrationAvailable
* Set

### Commands
* azure-nsg-security-rule-delete

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |
| portNumber | Port number. |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| incident.resourcename | Security group name. | string |

## Playbook Image
---
![Prisma Cloud Remediation - Azure Network Security Group Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_Azure_Network_Security_Group_Misconfig.png)
