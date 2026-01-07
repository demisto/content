Automation to recreate Security Groups with the over-permissive portion removed.  Over-permissive is defined as sensitive ports (SSH, RDP, etc) being exposed to the internet via IPv4.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Dependencies

---
This script uses the following commands and scripts.

* AWS
* aws-ec2-security-group-create
* aws-ec2-security-group-egress-authorize
* aws-ec2-security-group-egress-revoke
* aws-ec2-security-group-ingress-authorize
* aws-ec2-security-groups-describe

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| account_id | The AWS Account ID. |
| resource_id | The EC2 Resource ID whose Security Groups are to be remediated. |
| sg_list | The Security Group ID\(s\) to be recreated, given as a comma separated list. |
| port | TCP/UDP port to be restricted. |
| protocol | Protocol of the port to be restricted. |
| region | Region where EC2 instance is present. |
| integration_instance | The AWS Integration Instance to use. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWSPublicExposure.SGReplacements.ResourceID | The EC2 Resource ID whose Security Groups are to be remediated. | string |
| AWSPublicExposure.SGReplacements.ReplacementSet | List of existing \(old\) Security Groups and the newly created equivalent with over-permissive rules removed. | unknown |
| AWSPublicExposure.SGReplacements.UpdatedSGList | List of Security Groups to associate to the EC2 resource after remediation. | unknown |
