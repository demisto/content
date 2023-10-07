Remediates Prisma Cloud AWS EC2 alerts.  It calls the following sub-playbooks to perform the remediation:
  - AWS Default Security Group Does Not Restrict All Traffic
  - AWS Security Groups Allow Internet Traffic
  - AWS Security Groups With Inbound Rule Overly Permissive To All Traffic
  - AWS Security Groups allow internet traffic from internet to FTP-Data port (20)
  - AWS Security Groups allow internet traffic from internet to FTP port (21)
  - AWS Security Groups allow internet traffic to SSH port (22)
  - AWS Security Group allows all traffic on SSH port (22)
  - AWS Security Groups allow internet traffic from internet to Telnet port (23)
  - AWS Security Groups allow internet traffic from internet to SMTP port (25)
  - AWS Security Groups allow internet traffic from internet to DNS port (53)
  - AWS Security Groups allow internet traffic from internet to Windows RPC port (135)
  - AWS Security Groups allow internet traffic from internet to NetBIOS port (137)
  - AWS Security Groups allow internet traffic from internet to NetBIOS port (138)
  - AWS Security Groups allow internet traffic from internet to CIFS port (445)
  - AWS Security Groups allow internet traffic from internet to SQLServer port (1433)
  - AWS Security Groups allow internet traffic from internet to SQLServer port (1434)
  - AWS Security Groups allow internet traffic from internet to MYSQL port (3306)
  - AWS Security Groups allow internet traffic from internet to RDP port (3389)
  - AWS Security Groups allow internet traffic from internet to MSQL port (4333)
  - AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)
  - AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)
  - AWS Security Groups allow internet traffic from internet to VNC Server port (5900)


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Prisma Cloud Remediation - AWS EC2 Security Group Misconfiguration
* Prisma Cloud Remediation - AWS Security Groups Allows Internet Traffic To TCP Port

### Integrations
* Builtin
* PrismaCloud v2

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* redlock-dismiss-alerts

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| AutoUpdateEC2 | Whether to update the AWS EC2 instance automatically. | no | - | Optional |
| policyId | Returns the Prisma Cloud policy ID. | labels.policy | incident | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PCR_AWS_EC2_Instance_Misconfig](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PCR_AWS_EC2_Instance_Misconfig.png)
