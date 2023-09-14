Find Security Group rules which allows ::/0 (IPv4) or 0.0.0.0/0.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Amazon Web Services |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Prisma Cloud Remediation - AWS Security Groups Allows Internet Traffic To TCP Port

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| groupId | Security Group ID \(sg-xxxxxxxxx\) |
| ipPermissions | JSON string of the ipPermissions. IpPermissions should have one or more rules which are composed of IpProtocol, FromPort, ToPort, or IpRanges. Refer to aws-ec2-describe-security-groups \(https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html\) for example/reference. |
| protocol | Protocol to check. TCP/UDP/All\(-1\) |
| fromPort | Lower bound port range to be checked. If fromPort and toPort are not specified, all ports will be included. |
| toPort | Upper bound port range to be checked. If fromPort and toPort are not specified, all ports will be included. |
| region | Security group region |
| includeIPv6 | Include IPv6 in the result. By default, IPv6 is not included |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWS.EC2.SecurityGroup.PublicRules | List public Security Group rules | Unknown |
| AWS.EC2.SecurityGroup.PublicRules.groupId | Security Group ID | String |
| AWS.EC2.SecurityGroup.PublicRules.ipProtocol | IP Protocol \(TCP/UDP/-1\) | String |
| AWS.EC2.SecurityGroup.PublicRules.fromPort | Security Group rule's lower bound port range | Number |
| AWS.EC2.SecurityGroup.PublicRules.toPort | Security Group rule's upper bound port range | Number |
| AWS.EC2.SecurityGroup.PublicRules.cidrIp | Security Group rule's CIDR range | String |
| AWS.EC2.SecurityGroup.PublicRules.region | Region of the security group | String |
