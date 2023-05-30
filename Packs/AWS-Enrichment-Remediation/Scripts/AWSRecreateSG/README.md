Automation to determine what interface on an EC2 instance has an over-permissive security group on, determine which security groups have over-permissive rules and to replace them with a copy of the security group that has only the over-permissive portion removed.  Over-permissive is defined as sensitive ports (SSH, RDP, etc) being exposed to the internet via IPv4.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Dependencies

---
This script uses the following commands and scripts.

* aws-ec2-create-security-group
* aws-ec2-authorize-security-group-ingress-rule
* aws-ec2-revoke-security-group-egress-rule
* aws-ec2-authorize-security-group-egress-rule
* aws-ec2-revoke-security-group-ingress-rule
* aws-ec2-describe-instances

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| instance_id | EC2 Instance ID. |
| port | TCP/UDP Port to be restricted. |
| protocol | Protocol of the port to be restricted. |
| public_ip | Public IP address of the EC2 instance. |

## Outputs

---
There are no outputs for this script.
