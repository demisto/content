Duplicates security groups and modifies rules to remove public exposure for the specified port. The updated security groups can then be used to remediate public exposure of an AWS resource by replacing the existing list.

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
* aws-ec2-tags-create

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| account_id | The AWS account ID. |
| resource_id | The EC2 resource ID to remediate security groups for. |
| sg_list | A comma-separated list of security group IDs to recreate. |
| port | TCP/UDP port to be restricted. |
| protocol | The protocol of the port to be restricted. |
| region | The region where the EC2 instance resides. |
| tags | The tags to apply to the recreated security groups. Use the format \`key=abc,value=123;key=fed,value=456\`, with tags separated by a semicolon \(;\). |
| integration_instance | The AWS integration instance to use. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWSPublicExposure.SGReplacements.ReplacementSet.new-sg | ID of the newly created security group with restricted permissions. | String |
| AWSPublicExposure.SGReplacements.ReplacementSet.old-sg | ID of the original security group before remediation. | String |
| AWSPublicExposure.SGReplacements.ResourceID | The EC2 resource ID to remediate security groups for. | String |
| AWSPublicExposure.SGReplacements.UpdatedSGList | List of Security Groups to associate to the EC2 resource after remediation. | String |
| AWSPublicExposure.SGReplacements.RemediationRequired | Indicates whether any of the provided security groups contained rules requiring remediation. | boolean |
