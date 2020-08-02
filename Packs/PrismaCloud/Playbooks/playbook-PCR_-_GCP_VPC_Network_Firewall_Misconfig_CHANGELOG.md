## [Unreleased]

New Prisma Cloud policies remediated:

- GCP Default Firewall rule should not have any rules (except http and https)
- GCP Firewall with Inbound rule overly permissive to All Traffic


## [20.5.0] - 2020-05-12
#### New Playbook

This playbook remediates the following Prisma Cloud GCP VPC Network Firewall alerts.

Prisma Cloud policies remediated:

- GCP Firewall rule allows internet traffic to FTP port (21)
- GCP Firewall rule allows internet traffic to HTTP port (80)
- GCP Firewall rule allows internet traffic to MongoDB port (27017)
- GCP Firewall rule allows internet traffic to MySQL DB port (3306)
- GCP Firewall rule allows internet traffic to Oracle DB port (1521)
- GCP Firewall rule allows internet traffic to PostgreSQL port (5432)
- GCP Firewall rule allows internet traffic to RDP port (3389)
- GCP Firewall rule allows internet traffic to SSH port (22)
- GCP Firewall rule allows internet traffic to Telnet port (23)
- GCP Firewall rule allows internet traffic to DNS port (53)
- GCP Firewall rule allows internet traffic to Microsoft-DS port (445)
- GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)
- GCP Firewall rule allows internet traffic to POP3 port (110)
- GCP Firewall rule allows internet traffic to SMTP port (25)
