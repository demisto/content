Automation to determine which interface on an EC2 instance has an over-permissive security group, determine which security groups have over-permissive rules and replace them with a copy of the security group that has only the over-permissive portion removed.  Over-permissive is defined as sensitive ports (SSH, RDP, etc.) being exposed to the internet via IPv4.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Dependencies

---
This script uses the following commands and scripts.

* aws-ec2-revoke-security-group-egress-rule
* aws-ec2-authorize-security-group-ingress-rule
* aws-ec2-authorize-security-group-egress-rule
* aws-ec2-describe-instances
* aws-ec2-revoke-security-group-ingress-rule
* aws-ec2-create-security-group

## Used In

---
This script is used in the following playbooks and scripts.

* AWS - Security Group Remediation v2

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| instance_id | EC2 Instance ID. |
| port | TCP/UDP port to be restricted. |
| protocol | Protocol of the port to be restricted. |
| public_ip | Public IP address of the EC2 instance. |
| assume_role | Name of an AWS role to assume \(should be the same for all organizations\). |
| region | Region where EC2 instance is present. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| awssgrecreated | Sets the value to true or false if the security group is created. | boolean |
