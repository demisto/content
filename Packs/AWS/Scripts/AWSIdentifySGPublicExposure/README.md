Automation to determine which interface on an EC2 instance has a given public IP and identify associated security groups.

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
* aws-ec2-instances-describe

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| account_id | The AWS Account ID. |
| instance_id | EC2 Instance ID. |
| public_ip | Public IP address whose network interface to identify. |
| region | Region where EC2 instance resides. |
| integration_instance | The AWS Integration Instance to use. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AWSPublicExposure.SGAssociations.EC2InstanceID | ID of the EC2 instance with public exposure. | string |
| AWSPublicExposure.SGAssociations.NetworkInterfaceID | ID of the Elastic Network Interface with public exposure. | string |
| AWSPublicExposure.SGAssociations.SecurityGroups | Security Group IDs associated with this interface. | Unknown |
| AWSPublicExposure.SGAssociations.PublicIP | Public IP address exposed. | string |
| AWSPublicExposure.SGAssociations.IntegrationInstance | The AWS Integration Instance used for identification. | string |
