Automation to duplicate Security Groups with rules modified to remove public exposure of the given port.  The updated list of security groups can then be used to remediate public exposure of an AWS resource by replacing the current list.

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
| region | Region where EC2 instance resides. |
| integration_instance | The AWS Integration Instance to use. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWSPublicExposure.SGReplacements.ReplacementSet.new-sg | ID of the newly created security group with restricted permissions. | String |
| AWSPublicExposure.SGReplacements.ReplacementSet.old-sg | ID of the original security group before remediation. | String |
| AWSPublicExposure.SGReplacements.ResourceID | The EC2 Resource ID whose Security Groups are to be remediated. | String |
| AWSPublicExposure.SGReplacements.UpdatedSGList | List of Security Groups to associate to the EC2 resource after remediation. | String |
| AWSPublicExposure.SGReplacements.RemediationRequired | Indicates whether or not any of the provided Security Groups contained rules requiring remediation. | boolean |
