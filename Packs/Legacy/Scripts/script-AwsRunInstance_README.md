Creates an EC2 AWS instances from an image.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Amazon Web Services |


## Dependencies
---
This script uses the following commands and scripts.
* run-instance

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| imageId | The ID of the AMI. |
| instanceType | The instance type. For more information, see Instance Types in the Amazon Elastic Compute Cloud User Guide.  The default is m1.small. |
| keyName | The name of the key pair. A key pair can be created using `CreateKeyPair` or `ImportKeyPair`. |
| subnetId | [EC2-VPC] The ID of the subnet to launch the instance into. |
| privateIpAddress | [EC2-VPC] The primary IP address. You must specify a value from the IP address range of the subnet.  Only one private IP address can be designated as primary. Therefore, you can't specify this parameter if `PrivateIpAddresses.n.Primary` is set to "true" and `PrivateIpAddresses.n.PrivateIpAddress` is set to an IP address. |
| availabilityZone | The availability zone of the instance. |
| securityGroup | The security group name. Amazon EC2 uses the default security group as its default. |

## Outputs
---
There are no outputs for this script.
