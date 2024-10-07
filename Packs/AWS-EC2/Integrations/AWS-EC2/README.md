Amazon Web Services Elastic Compute Cloud (EC2).

## Configure AWS - EC2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region |  | False |
| Role Arn |  | False |
| Role Session Name |  | False |
| Role Session Duration |  | False |
| Access Key |  | False |
| Secret Key |  | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| PrivateLink service URL |  | False |
| STS PrivateLink URL |  | False |
| AWS organization accounts | A comma-separated list of AWS Organization accounts to use when running EC2 commands. A role name for cross-organization account access must be provided to use this feature. This feature is explained below. | False |
| Role name for cross-organization account access | The role name used to access accounts in the organization. This role name must exist in the accounts provided in "AWS Organization accounts" and be assumable with the credentials provided. This feature is explained below. | False |
| Max concurrent command calls | The maximum number of concurrent calls to allow when running a command on all accounts provided in "AWS Organization accounts". | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


### Run commands in multiple AWS accounts

The EC2 integration supports running commands across multiple AWS accounts in an organization.
To use this feature, configure the parameter `AWS organization accounts` with a comma-separated list of AWS Organization accounts and the `Role name for cross-organization account access` parameter with a role name that grants full access to the EC2 API in each account.
Using the `roleArn`, `roleSessionName` and `roleSessionDuration` arguments in EC2 commands will override this feature.
 
#### Example:

---

**AWS organization accounts**
> 12345678,98765432

**Role name for cross-organization account access** 
> CrossAccountAccessRole

---

In this case, the user configured with `Access Key` and `Secret Key` must be able to perform ***AssumeRole*** with the ***RoleArn***:
`arn:aws:iam::12345678:role/CrossAccountAccessRole`
`arn:aws:iam::98765432:role/CrossAccountAccessRole`

#### AwsEC2SyncAccounts Script
The script ***AwsEC2SyncAccounts*** can be used to configure an AWS - EC2 instance with all accounts in an organization.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-ec2-describe-instances

***
Describes one or more of your instances.

#### Base Command

`aws-ec2-describe-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options.  | Optional | 
| instanceIds | One or more instance IDs. Seprated by comma. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.AmiLaunchIndex | number | The AMI launch index, which can be used to find this instance in the launch group. | 
| AWS.EC2.Instances.ImageId | string | The ID of the AMI used to launch the instance. | 
| AWS.EC2.Instances.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Instances.InstanceType | string | The instance type. | 
| AWS.EC2.Instances.KernelId | string | The kernel associated with this instance, if applicable. | 
| AWS.EC2.Instances.KeyName | string | The name of the key pair, if this instance was launched with an associated key pair. | 
| AWS.EC2.Instances.LaunchTime | date | The time the instance was launched. | 
| AWS.EC2.Instances.Monitoring.State | string | Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled. | 
| AWS.EC2.Instances.Placement.AvailabilityZone | string | The Availability Zone of the instance. | 
| AWS.EC2.Instances.Placement.Affinity | string | The affinity setting for the instance on the Dedicated Host. | 
| AWS.EC2.Instances.Placement.GroupName | string | The name of the placement group the instance is in \(for cluster compute instances\). | 
| AWS.EC2.Instances.Placement.HostId | string | he ID of the Dedicated Host on which the instance resides. | 
| AWS.EC2.Instances.Placement.Tenancy | string | The tenancy of the instance \(if the instance is running in a VPC\). | 
| AWS.EC2.Instances.Platform | string | The value is Windows for Windows instances; otherwise blank. | 
| AWS.EC2.Instances.PrivateDnsName | string | \(IPv4 only\) The private DNS hostname name assigned to the instance. This DNS hostname can only be used inside the Amazon EC2 network. This name is not available until the instance enters the running state. | 
| AWS.EC2.Instances.PrivateIpAddress | string | The private IPv4 address assigned to the instance. | 
| AWS.EC2.Instances.ProductCodes.ProductCodeId | string | The product code. | 
| AWS.EC2.Instances.ProductCodes.ProductCodeType | string | The type of product code. | 
| AWS.EC2.Instances.PublicDnsName | string | \(IPv4 only\) The public DNS name assigned to the instance. This name is not available until the instance enters the running state. | 
| AWS.EC2.Instances.PublicIpAddress | string | The public IPv4 address assigned to the instance, if applicable. | 
| AWS.EC2.Instances.RamdiskId | string | The RAM disk associated with this instance, if applicable. | 
| AWS.EC2.Instances.State.Code | string | The low byte represents the state. | 
| AWS.EC2.Instances.State.Name | string | The current state of the instance. | 
| AWS.EC2.Instances.StateTransitionReason | string | The reason for the most recent state transition. This might be an empty string. | 
| AWS.EC2.Instances.SubnetId | string | The ID of the subnet in which the instance is running. | 
| AWS.EC2.Instances.VpcId | string | The ID of the VPC in which the instance is running. | 
| AWS.EC2.Instances.Architecture | string | The architecture of the image. | 
| AWS.EC2.Instances.BlockDeviceMappings.DeviceName | string | The device name \(for example, /dev/sdh or xvdh\). | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.AttachTime | string | The time stamp when the attachment initiated. | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.DeleteOnTermination | string | Indicates whether the volume is deleted on instance termination. | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.Status | string | The attachment state. | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.VolumeId | string | The ID of the EBS volume. | 
| AWS.EC2.Instances.ClientToken | string | The idempotency token you provided when you launched the instance, if applicable. | 
| AWS.EC2.Instances.EbsOptimized | boolean | Indicates whether the instance is optimized for Amazon EBS I/O. | 
| AWS.EC2.Instances.EnaSupport | boolean | Specifies whether enhanced networking with ENA is enabled. | 
| AWS.EC2.Instances.Hypervisor | string | The hypervisor type of the instance. | 
| AWS.EC2.Instances.IamInstanceProfile.Arn | string | The Amazon Resource Name \(ARN\) of the instance profile. | 
| AWS.EC2.Instances.IamInstanceProfile.Id | string | The ID of the instance profile. | 
| AWS.EC2.Instances.InstanceLifecycle | string | Indicates whether this is a Spot Instance or a Scheduled Instance. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuId | string | The ID of the Elastic GPU. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationId | string | The ID of the association. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationState | string | The state of the association between the instance and the Elastic GPU. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationTime | string | The time the Elastic GPU was associated with the instance. | 
| AWS.EC2.Instances.NetworkInterfaces.Association.IpOwnerId | string | The ID of the owner of the Elastic IP address. | 
| AWS.EC2.Instances.NetworkInterfaces.Association.PublicDnsName | string | The public DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.Association.PublicIp | string | The public IP address or Elastic IP address bound to the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachTime | date | The time stamp when the attachment initiated. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachmentId | string | The ID of the network interface attachment. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.DeleteOnTermination | boolean | Indicates whether the network interface is deleted when the instance is terminated. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.DeviceIndex | number | The index of the device on the instance for the network interface attachment. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.Status | string | The attachment state. | 
| AWS.EC2.Instances.NetworkInterfaces.Description | string | The description. | 
| AWS.EC2.Instances.NetworkInterfaces.Groups.GroupName | string | The name of the security group. | 
| AWS.EC2.Instances.NetworkInterfaces.Groups.GroupId | string | The ID of the security group. | 
| AWS.EC2.Instances.NetworkInterfaces.Ipv6Addresses.Ipv6Address | string | The IPv6 addresses associated with the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.MacAddress | string | The MAC address. | 
| AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId | string | The ID of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.OwnerId | string | The ID of the AWS account that created the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName | string | The private DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress | string | The IPv4 address of the network interface within the subnet. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.IpOwnerId | string | The ID of the owner of the Elastic IP address. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicDnsName | string | The public DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicIp | string | The public IP address or Elastic IP address bound to the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Primary | boolean | Indicates whether this IPv4 address is the primary private IP address of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateDnsName | string | The private IPv4 DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateIpAddress | string | The private IPv4 address of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck | boolean | Indicates whether to validate network traffic to or from this network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.Status | string | The status of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.SubnetId | string | The ID of the subnet. | 
| AWS.EC2.Instances.NetworkInterfaces.VpcId | string | The ID of the VPC. | 
| AWS.EC2.Instances.RootDeviceName | string | The device name of the root device volume \(for example, /dev/sda1\). | 
| AWS.EC2.Instances.RootDeviceType | string | The root device type used by the AMI. The AMI can use an EBS volume or an instance store volume. | 
| AWS.EC2.Instances.SecurityGroups.GroupName | string | The name of the security group. | 
| AWS.EC2.Instances.SecurityGroups.GroupId | string | The ID of the security group. | 
| AWS.EC2.Instances.SourceDestCheck | boolean | Specifies whether to enable an instance launched in a VPC to perform NAT. | 
| AWS.EC2.Instances.SpotInstanceRequestId | string | If the request is a Spot Instance request, the ID of the request. | 
| AWS.EC2.Instances.SriovNetSupport | string | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. | 
| AWS.EC2.Instances.StateReason.Code | string | The reason code for the state change. | 
| AWS.EC2.Instances.StateReason.Message | string | The message for the state change. | 
| AWS.EC2.Instances.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Instances.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Instances.VirtualizationType | string | The virtualization type of the instance. | 
| AWS.EC2.Instances.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 


#### Command Example
```!aws-ec2-describe-instances```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "Instances": [
                {
                    "AmiLaunchIndex": 0,
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/dev_name",
                            "Ebs": {
                                "AttachTime": "2020-04-26T15:49:18",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-1"
                            }
                        }
                    ],
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "ClientToken": "some_token",
                    "CpuOptions": {
                        "CoreCount": 8,
                        "ThreadsPerCore": 2
                    },
                    "EbsOptimized": false,
                    "EnaSupport": true,
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "some_arn",
                        "Id": "id"
                    },
                    "ImageId": "ami-id",
                    "InstanceId": "i-id",
                    "InstanceType": "m5.4xlarge",
                    "KeyName": "Aqua",
                    "LaunchTime": "2020-04-26T15:49:17",
                    "Monitoring": {
                        "State": "enabled"
                    },
                    "NetworkInterfaces": [
                        {
                            "Attachment": {
                                "AttachTime": "2020-04-26T15:49:28",
                                "AttachmentId": "eni-attach",
                                "DeleteOnTermination": false,
                                "DeviceIndex": 1,
                                "Status": "attached"
                            },
                            "Description": "Floating network interface providing a fixed IP address for AWS Ground Station to connect to.",
                            "Groups": [
                                {
                                    "GroupId": "sg",
                                    "GroupName": "some_group_name"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "add",
                            "NetworkInterfaceId": "eni",
                            "OwnerId": "some_id",
                            "PrivateDnsName": "name",
                            "PrivateIpAddress": "1.1.1.1",
                            "PrivateIpAddresses": [
                                {
                                    "Primary": true,
                                    "PrivateDnsName": "name",
                                    "PrivateIpAddress": "1.1.1.1"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet",
                            "VpcId": "vpc"
                        }
                    ],
                    "Placement": {
                        "AvailabilityZone": "us-west-2a",
                        "GroupName": "name",
                        "Tenancy": "dedicated"
                    },
                    "PrivateDnsName": "dns_name",
                    "PrivateIpAddress": "1.1.1.1",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "Region": "us-west-2",
                    "RootDeviceName": "/dev/dev_name",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg",
                            "GroupName": "name"
                        }
                    ],
                    "SourceDestCheck": true,
                    "State": {
                        "Code": 80,
                        "Name": "stopped"
                    },
                    "StateReason": {
                        "Code": "Client.UserInitiatedShutdown",
                        "Message": "Client.UserInitiatedShutdown: User initiated shutdown"
                    },
                    "StateTransitionReason": "User initiated (2020-04-26 18:28:48 GMT)",
                    "SubnetId": "subnet-1",
                    "Tags": [
                        {
                            "Key": "stack-id",
                            "Value": "some_info"
                        }
                    ],
                    "VirtualizationType": "hvm",
                    "VpcId": "vpc"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### AWS Instances
>|ImageId|InstanceId|KeyName|LaunchDate|Monitoring|Name|PublicDNSName|PublicIPAddress|Region|State|Type|aws:cloudformation:logical-id|aws:cloudformation:stack-id|aws:cloudformation:stack-name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| ami-1 | i-1 | Aqua | 2020-04-26T15:49:17Z | enabled | Receiver-gs-aqua-receiver |  |  | us-west-2 | stopped | m5.4xlarge | ReceiverInstance | arn1 | name1 |
>| ami-2 | i-2 |  | 2020-08-19T11:23:48Z | disabled | flask-env | some_server | 1.2.3.4 | us-west-2 | running | t2.micro | AWSEBAutoScalingGroup | arn2 | name2 |

### aws-ec2-describe-iam-instance-profile-associations

***
Describes your IAM instance profile associations.

#### Base Command

`aws-ec2-describe-iam-instance-profile-associations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options.  | The IAM instance profile associations. | Optional | 
| maxResults | The maximum number of results to return in a single call. Specify a value between 5 and 1000. | Optional | 
| nextToken | The token for the next set of results. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IamInstanceProfileAssociations.IamInstanceProfile.Arn | string | The Amazon Resource Name \(ARN\) of the instance profile. | 
| AWS.EC2.IamInstanceProfileAssociations.IamInstanceProfile.Id | string | The ID of the instance profile. | 
| AWS.EC2.IamInstanceProfileAssociations.State | string | The state of the association. | 
| AWS.EC2.IamInstanceProfileAssociations.InstanceId | string | The ID of the instance. | 
| AWS.EC2.IamInstanceProfileAssociations.AssociationId | string | The ID of the association. | 
| AWS.EC2.IamInstanceProfileAssociations.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 


#### Command Example
```!aws-ec2-describe-iam-instance-profile-associations```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "IamInstanceProfileAssociations": [
                {
                    "AssociationId": "association1",
                    "InstanceId": "instance1",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::000000000000:instance-profile/eks-00000000-0000-0000-0000-00000000",
                        "Id": "AAAAA"
                    },
                    "State": "associated"
                },
                {
                    "AssociationId": "iip-assoc-0fdeba1a2861d2580", 
                    "InstanceId": "i-06bab8afb71d19fea",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::000000000000:instance-profile/eks-00000000-0000-0000-0000-00000001",
                        "Id": "CCCCC"
                    }, 
                    "State": "associated"
                }
            ]
        }
    }
}
```

### aws-ec2-describe-images

***
Describes one or more of the images (AMIs, AKIs, and ARIs) available to you. Images available to you include public images, private images that you own, and private images owned by other AWS accounts but for which you have explicit launch permissions.

#### Base Command

`aws-ec2-describe-images`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options.  | Optional | 
| imageIds | A comma-separated list of image IDs. | Optional | 
| owners | Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon \| aws-marketplace \| microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership. | Optional | 
| executableUsers | Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs). | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.Architecture | string | The architecture of the image. | 
| AWS.EC2.Images.CreationDate | date | The date and time the image was created. | 
| AWS.EC2.Images.ImageId | string | The ID of the AMI. | 
| AWS.EC2.Images.ImageLocation | string | The location of the AMI. | 
| AWS.EC2.Images.ImageType | string | The type of image. | 
| AWS.EC2.Images.Public | boolean | Indicates whether the image has public launch permissions. The value is true if this image has public launch permissions or false if it has only implicit and explicit launch permissions. | 
| AWS.EC2.Images.KernelId | string | The kernel associated with the image, if any. Only applicable for machine images. | 
| AWS.EC2.Images.OwnerId | string | The AWS account ID of the image owner. | 
| AWS.EC2.Images.Platform | string | The value is Windows for Windows AMIs; otherwise blank. | 
| AWS.EC2.Images.ProductCodes.ProductCodeId | string | The product code. | 
| AWS.EC2.Images.ProductCodes.ProductCodeType | string | The type of product code. | 
| AWS.EC2.Images.RamdiskId | string | The RAM disk associated with the image, if any. Only applicable for machine images. | 
| AWS.EC2.Images.State | string | The current state of the AMI. If the state is available , the image is successfully registered and can be used to launch an instance. | 
| AWS.EC2.Images.BlockDeviceMappings.DeviceName | string | The device name \(for example, /dev/sdh or xvdh\). | 
| AWS.EC2.Images.BlockDeviceMappings.VirtualName | string | The virtual device name \(ephemeral N\). | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Encrypted | boolean | Indicates whether the EBS volume is encrypted. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Iops | number | The number of I/O operations per second \(IOPS\) that the volume supports. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.KmsKeyId | string | Identifier \(key ID, key alias, ID ARN, or alias ARN\) for a user-managed CMK under which the EBS volume is encrypted. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.SnapshotId | string | The ID of the snapshot. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeSize | number | The size of the volume, in GiB. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeType | string | The volume type. | 
| AWS.EC2.Images.BlockDeviceMappings.NoDevice | string | Suppresses the specified device included in the block device mapping of the AMI. | 
| AWS.EC2.Images.Description | string | The description of the AMI that was provided during image creation. | 
| AWS.EC2.Images.EnaSupport | boolean | Specifies whether enhanced networking with ENA is enabled. | 
| AWS.EC2.Images.Hypervisor | string | The hypervisor type of the image. | 
| AWS.EC2.Images.ImageOwnerAlias | string | The AWS account alias \(for example, amazon , self \) or the AWS account ID of the AMI owner. | 
| AWS.EC2.Images.Name | string | The name of the AMI that was provided during image creation. | 
| AWS.EC2.Images.RootDeviceName | string | The device name of the root device volume \(for example, /dev/sda1\). | 
| AWS.EC2.Images.RootDeviceType | string | The type of root device used by the AMI. The AMI can use an EBS volume or an instance store volume. | 
| AWS.EC2.Images.SriovNetSupport | string | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. | 
| AWS.EC2.Images.StateReason.Code | string | The reason code for the state change. | 
| AWS.EC2.Images.StateReason.Message | string | The message for the state change. | 
| AWS.EC2.Images.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Images.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Images.VirtualizationType | string | The type of virtualization of the AMI. | 
| AWS.EC2.Images.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-describe-regions

***
Describes one or more regions that are currently available to you.

#### Base Command

`aws-ec2-describe-regions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regionNames | The name of the region (for example, us-east-1 ). | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Regions.Endpoint | string | The region service endpoint. | 
| AWS.Regions.RegionName | string | The name of the region. | 
| AWS.Regions.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 


#### Command Example
```!aws-ec2-describe-regions```

#### Context Example
```json
{
    "AWS": {
        "Regions": [
            {
                "Endpoint": "ec2.eu-north-1.amazonaws.com",
                "RegionName": "eu-north-1"
            },
            {
                "Endpoint": "ec2.ap-south-1.amazonaws.com",
                "RegionName": "ap-south-1"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS Regions
>|Endpoint|RegionName|
>|---|---|
>| ec2.eu-north-1.amazonaws.com | eu-north-1 |
>| ec2.ap-south-1.amazonaws.com | ap-south-1 |


### aws-ec2-describe-addresses

***
Describes one or more of your Elastic IP addresses.

#### Base Command

`aws-ec2-describe-addresses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| publicIps | One or more Elastic IP addresses. | Optional | 
| allocationIds | One or more allocation IDs. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ElasticIPs.InstanceId | string | The ID of the instance that the address is associated with \(if any\). | 
| AWS.EC2.ElasticIPs.PublicIp | string | The Elastic IP address. | 
| AWS.EC2.ElasticIPs.AllocationId | string | The ID representing the allocation of the address for use with EC2-VPC. | 
| AWS.EC2.ElasticIPs.AssociationId | string | The ID representing the association of the address with an instance in a VPC. | 
| AWS.EC2.ElasticIPs.Domain | string | dicates whether this Elastic IP address is for use with instances in EC2-Classic \(standard\) or instances in a VPC. | 
| AWS.EC2.ElasticIPs.NetworkInterfaceId | string | The ID of the network interface. | 
| AWS.EC2.ElasticIPs.NetworkInterfaceOwnerId | string | The ID of the AWS account that owns the network interface. | 
| AWS.EC2.ElasticIPs.PrivateIpAddress | string | The private IP address associated with the Elastic IP address. | 
| AWS.EC2.ElasticIPs.Region | string | The AWS region where the elastic IP is located. | 
| AWS.EC2.ElasticIPs.Tags.Key | string | The key of the tag. | 
| AWS.EC2.ElasticIPs.Tags.Value | string | The value of the tag. | 
| AWS.EC2.ElasticIPs.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command Example
```!aws-ec2-describe-addresses```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "ElasticIPs": [
                {
                    "AllocationId": "eipalloc-1",
                    "Domain": "vpc",
                    "PublicIp": "1.1.1.1",
                    "PublicIpv4Pool": "amazon",
                    "Region": "us-west-2"
                },
                {
                    "AllocationId": "eipalloc-2",
                    "AssociationId": "eipassoc-2",
                    "Domain": "vpc",
                    "InstanceId": "i-1",
                    "NetworkInterfaceId": "eni-1",
                    "NetworkInterfaceOwnerId": "id",
                    "PrivateIpAddress": "1.2.3.4",
                    "PublicIp": "3.4.5.6",
                    "PublicIpv4Pool": "amazon"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 ElasticIPs
>|AllocationId|Domain|PublicIp|Region|
>|---|---|---|---|
>| eipalloc-1 | vpc | 1.1.1.1 | us-west-2 |
>| eipalloc-2 | vpc | 1.2.3.4 | us-west-2 |


### aws-ec2-describe-snapshots
***
Describes one or more of the EBS snapshots available to you.

#### Base Command

`aws-ec2-describe-snapshots`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options.  | Optional | 
| ownerIds | Returns the snapshots owned by the specified owner. Multiple owners can be specified. | Optional | 
| snapshotIds | A comma-separated list of snapshot IDs. | Optional | 
| restorableByUserIds | One or more AWS accounts IDs that can create volumes from the snapshot. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Snapshots.DataEncryptionKeyId | string | The data encryption key identifier for the snapshot. | 
| AWS.EC2.Snapshots.Description | string | The description for the snapshot. | 
| AWS.EC2.Snapshots.Encrypted | boolean | Indicates whether the snapshot is encrypted. | 
| AWS.EC2.Snapshots.KmsKeyId | string | The full ARN of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the parent volume. | 
| AWS.EC2.Snapshots.OwnerId | string | The AWS account ID of the EBS snapshot owner. | 
| AWS.EC2.Snapshots.Progress | string | The progress of the snapshot, as a percentage. | 
| AWS.EC2.Snapshots.SnapshotId | string | The ID of the snapshot. | 
| AWS.EC2.Snapshots.StartTime | string | The time stamp when the snapshot was initiated. | 
| AWS.EC2.Snapshots.State | string | The snapshot state. | 
| AWS.EC2.Snapshots.StateMessage | string | this field displays error state details to help you diagnose why the error occurred. | 
| AWS.EC2.Snapshots.VolumeId | string | The ID of the volume that was used to create the snapshot. | 
| AWS.EC2.Snapshots.VolumeSize | number | The size of the volume, in GiB. | 
| AWS.EC2.Snapshots.OwnerAlias | string | Value from an Amazon-maintained list of snapshot owners. | 
| AWS.EC2.Snapshots.Region | string | The AWS region where the snapshot is located. | 
| AWS.EC2.Snapshots.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Snapshots.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Snapshots.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-describe-launch-templates

***
Describes one or more launch templates.

#### Base Command

`aws-ec2-describe-launch-templates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| LaunchTemplateNames | A comma-separated list of launch template names. | Optional | 
| LaunchTemplateIds | A comma-separated list of launch template IDs. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.LaunchTemplates.LaunchTemplateId | string | The ID of the launch template. | 
| AWS.EC2.LaunchTemplates.LaunchTemplateName | string | The name of the launch template. | 
| AWS.EC2.LaunchTemplates.CreateTime | date | The time launch template was created. | 
| AWS.EC2.LaunchTemplates.CreatedBy | string | The principal that created the launch template. | 
| AWS.EC2.LaunchTemplates.DefaultVersionNumber | number | The version number of the default version of the launch template. | 
| AWS.EC2.LaunchTemplates.LatestVersionNumber | number | The version number of the latest version of the launch template. | 
| AWS.EC2.LaunchTemplates.Tags.Key | string | The key of the tag. | 
| AWS.EC2.LaunchTemplates.Tags.Value | string | The value of the tag. | 
| AWS.EC2.LaunchTemplates.Region | string | The aws region where the template is located | 
| AWS.EC2.LaunchTemplates.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command Example
```!aws-ec2-describe-launch-templates```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "LaunchTemplates": {
                "CreateTime": "2019-04-21T07:54:50",
                "CreatedBy": "some_user",
                "DefaultVersionNumber": 1,
                "LatestVersionNumber": 1,
                "LaunchTemplateId": "lt-1",
                "LaunchTemplateName": "sample_launch_template",
                "Region": "us-west-2"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 LaunchTemplates
>|CreateTime|CreatedBy|DefaultVersionNumber|LatestVersionNumber|LaunchTemplateId|LaunchTemplateName|Region|
>|---|---|---|---|---|---|---|
>| 2019-04-21T07:54:50Z | some_user | 1 | 1 | lt-1 | sample_launch_template | us-west-2 |


### aws-ec2-describe-key-pairs

***
Describes one or more of your key pairs.

#### Base Command

`aws-ec2-describe-key-pairs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| keyNames | A comma-separated list of key pair names.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.KeyPairs.KeyFingerprint | Unknown | If you used CreateKeyPair to create the key pair, this is the SHA-1 digest of the DER encoded private key. If you used ImportKeyPair to provide AWS the public key, this is the MD5 public key fingerprint as specified in section 4 of RFC4716. | 
| AWS.EC2.KeyPairs.KeyName | Unknown | The name of the key pair. | 
| AWS.EC2.KeyPairs.Region | Unknown | The AWS region where the key pair is located. | 
| AWS.EC2.KeyPairs.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-describe-volumes

#### Command Example
```!aws-ec2-describe-key-pairs```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "KeyPairs": [
                {
                    "KeyFingerprint": "fp1",
                    "KeyName": "Aqua",
                    "Region": "us-west-2"
                },
                {
                    "KeyFingerprint": "fp2",
                    "KeyName": "Test Keys",
                    "Region": "us-west-2"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 Key Pairs
>|KeyFingerprint|KeyName|Region|
>|---|---|---|
>| fp1 | Aqua | us-west-2 |
>| fp2 | Test Keys | us-west-2 |


### aws-ec2-describe-volumes
***
Describes the specified EBS volumes.

#### Base Command

`aws-ec2-describe-volumes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| volumeIds | A comma-separated list of volume IDs. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.AvailabilityZone | string | The Availability Zone for the volume. | 
| AWS.EC2.Volumes.CreateTime | date | The time stamp when volume creation was initiated. | 
| AWS.EC2.Volumes.Encrypted | boolean | Indicates whether the volume will be encrypted. | 
| AWS.EC2.Volumes.KmsKeyId | string | The full ARN of the AWS Key Management Service customer master key that was used to protect the volume encryption key for the volume. | 
| AWS.EC2.Volumes.Size | number | The snapshot from which the volume was created, if applicable. | 
| AWS.EC2.Volumes.State | string | The volume state. | 
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. | 
| AWS.EC2.Volumes.Iops | number | The number of I/O operations per second \(IOPS\) that the volume supports. | 
| AWS.EC2.Volumes.VolumeType | string | The volume type. This can be gp2 for General Purpose SSD, io1 for Provisioned IOPS SSD, st1 for Throughput Optimized HDD, sc1 for Cold HDD, or standard for Magnetic volumes. | 
| AWS.EC2.Volumes.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Volumes.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Volumes.Attachments.AttachTime | date | The time stamp when the attachment initiated. | 
| AWS.EC2.Volumes.Attachments.Device | string | The device name. | 
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. | 
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. | 
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. | 
| AWS.EC2.Volumes.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command Example
```!aws-ec2-describe-volumes```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "Volumes": [
                {
                    "Attachments": [
                        {
                            "AttachTime": "2019-04-29T13:05:57",
                            "DeleteOnTermination": true,
                            "Device": "/dev/dev_name",
                            "InstanceId": "i-1",
                            "State": "attached",
                            "VolumeId": "vol-1"
                        }
                    ],
                    "AvailabilityZone": "us-west-2b",
                    "CreateTime": "2019-04-29T13:05:57",
                    "Encrypted": false,
                    "Iops": 100,
                    "Region": "us-west-2",
                    "Size": 8,
                    "SnapshotId": "snap-1",
                    "State": "in-use",
                    "VolumeId": "vol-1",
                    "VolumeType": "gp2"
                },
                {
                    "Attachments": [
                        {
                            "AttachTime": "2020-08-19T11:22:07",
                            "DeleteOnTermination": true,
                            "Device": "/dev/dev_name",
                            "InstanceId": "i-1",
                            "State": "attached",
                            "VolumeId": "vol-1"
                        }
                    ],
                    "AvailabilityZone": "us-west-2b",
                    "CreateTime": "2020-08-19T11:22:07",
                    "Encrypted": false,
                    "Iops": 100,
                    "Size": 8,
                    "SnapshotId": "snap-1",
                    "State": "in-use",
                    "VolumeId": "vol-1",
                    "VolumeType": "gp2"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 Volumes
>|AvailabilityZone|CreateTime|Encrypted|State|VolumeId|VolumeType|
>|---|---|---|---|---|---|
>| us-west-2b | 2019-04-29T13:05:57Z | false | in-use | vol-1 | gp2 |
>| us-west-2b | 2020-08-19T11:22:07Z | false | in-use | vol-2 | gp2 |


### aws-ec2-describe-vpcs

***
Describes one or more of your VPCs.

#### Base Command

`aws-ec2-describe-vpcs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| vpcIds |A comma-separated list of  VPC IDs.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Vpcs.CidrBlock | string | The primary IPv4 CIDR block for the VPC. | 
| AWS.EC2.Vpcs.DhcpOptionsId | string | The ID of the set of DHCP options you have associated with the VPC. | 
| AWS.EC2.Vpcs.State | string | The current state of the VPC. | 
| AWS.EC2.Vpcs.VpcId | string | The ID of the VPC. | 
| AWS.EC2.Vpcs.InstanceTenancy | string | The allowed tenancy of instances launched into the VPC. | 
| AWS.EC2.Vpcs.IsDefault | string | Indicates whether the VPC is the default VPC. | 
| AWS.EC2.Vpcs.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Vpcs.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.AssociationId | string | The association ID for the IPv6 CIDR block. | 
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlock | string | The IPv6 CIDR block. | 
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.State | string | The state of the CIDR block. | 
| AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.StatusMessage | string | A message about the status of the CIDR block, if applicable. | 
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.AssociationId | string | The association ID for the IPv4 CIDR block. | 
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlock | string | The IPv4 CIDR block. | 
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlockState.State | string | The state of the CIDR block. | 
| AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlockState.StatusMessage | string | A message about the status of the CIDR block, if applicable. | 
| AWS.EC2.Vpcs.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command Example
```!aws-ec2-describe-vpcs```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "Vpcs": {
                "CidrBlock": "1.1.1.1/16",
                "CidrBlockAssociationSet": [
                    {
                        "AssociationId": "vpc",
                        "CidrBlock": "1.1.1.1/16",
                        "CidrBlockState": {
                            "State": "associated"
                        }
                    }
                ],
                "DhcpOptionsId": "dopt-1",
                "InstanceTenancy": "default",
                "IsDefault": true,
                "OwnerId": "id",
                "Region": "us-west-2",
                "State": "available",
                "VpcId": "vpc-1"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 Vpcs
>|CidrBlock|DhcpOptionsId|InstanceTenancy|IsDefault|Region|State|VpcId|
>|---|---|---|---|---|---|---|
>| 1.1.1.1/16 | dopt-1 | default | true | us-west-2 | available | vpc-1 |


### aws-ec2-describe-subnets

***
Describes one or more of your subnets.

#### Base Command

`aws-ec2-describe-subnets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| subnetIds | A comma-separated list of subnet IDs.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Subnets.AvailabilityZone | string | The Availability Zone of the subnet. | 
| AWS.EC2.Subnets.AvailableIpAddressCount | number | The number of unused private IPv4 addresses in the subnet. Note that the IPv4 addresses for any stopped instances are considered unavailable. | 
| AWS.EC2.Subnets.CidrBlock | string | The IPv4 CIDR block assigned to the subnet. | 
| AWS.EC2.Subnets.DefaultForAz | boolean | Indicates whether this is the default subnet for the Availability Zone. | 
| AWS.EC2.Subnets.MapPublicIpOnLaunch | boolean | Indicates whether instances launched in this subnet receive a public IPv4 address. | 
| AWS.EC2.Subnets.State | string | The current state of the subnet. | 
| AWS.EC2.Subnets.SubnetId | string | The ID of the subnet. | 
| AWS.EC2.Subnets.VpcId | string | The ID of the VPC the subnet is in. | 
| AWS.EC2.Subnets.AssignIpv6AddressOnCreation | boolean | Indicates whether a network interface created in this subnet \(including a network interface created by RunInstances\) receives an IPv6 address. | 
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.AssociationId | string | The association ID for the CIDR block. | 
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlock | string | The IPv6 CIDR block. | 
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.State | string | The state of a CIDR block. | 
| AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.StatusMessage | string | A message about the status of the CIDR block, if applicable. | 
| AWS.EC2.Subnets.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Subnets.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Subnets.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command Example
```!aws-ec2-describe-subnets```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "Subnets": [
                {
                    "AssignIpv6AddressOnCreation": false,
                    "AvailabilityZone": "us-west-2d",
                    "AvailabilityZoneId": "zone_id",
                    "AvailableIpAddressCount": 4091,
                    "CidrBlock": "1.1.1.1/20",
                    "DefaultForAz": true,
                    "Ipv6CidrBlockAssociationSet": [],
                    "MapPublicIpOnLaunch": true,
                    "OwnerId": "id",
                    "Region": "us-west-2",
                    "State": "available",
                    "SubnetArn": "arn",
                    "SubnetId": "subnet-1",
                    "VpcId": "vpc-1"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 Subnets
>|AvailabilityZone|AvailableIpAddressCount|CidrBlock|DefaultForAz|Region|State|SubnetId|VpcId|
>|---|---|---|---|---|---|---|---|
>| us-west-2d | 4091 | 1.1.1.1/20 | true | us-west-2 | available | subnet-1 | vpc-1 |
>| us-west-2c | 4090 | 2.2.2.2/20 | true | us-west-2 | available | subnet-2 | vpc-2 |


### aws-ec2-describe-security-groups

***
Describes one or more of your security groups.

#### Base Command

`aws-ec2-describe-security-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| groupIds | A comma-separated list of  security group IDs. Required for security groups in a nondefault VPC.  | Optional | 
| groupNames | A comma-separated list of  security group names. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.SecurityGroups.Description | string | A description of the security group. | 
| AWS.EC2.SecurityGroups.GroupName | string | The name of the security group. | 
| AWS.EC2.SecurityGroups.IpPermissions.FromPort | number | The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. | 
| AWS.EC2.SecurityGroups.IpPermissions.IpProtocol | string | The IP protocol name \(tcp , udp , icmp \) or number. | 
| AWS.EC2.SecurityGroups.IpPermissions.IpRanges.CidrIp | string | The IPv4 CIDR range. | 
| AWS.EC2.SecurityGroups.IpPermissions.IpRanges.Description | string | A description for the security group rule that references this IPv4 address range. | 
| AWS.EC2.SecurityGroups.IpPermissions.Ipv6Ranges.CidrIpv6 | string | The IPv6 CIDR range. | 
| AWS.EC2.SecurityGroups.IpPermissions.Ipv6Ranges.Description | string | A description for the security group rule that references this IPv6 address range. | 
| AWS.EC2.SecurityGroups.IpPermissions.PrefixListIds.Description | string | A description for the security group rule that references this prefix list ID. | 
| AWS.EC2.SecurityGroups.IpPermissions.PrefixListIds.PrefixListId | string | The ID of the prefix. | 
| AWS.EC2.SecurityGroups.IpPermissions.ToPort | number | The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.Description | string | A description for the security group rule that references this user ID group pair. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.GroupId | string | The ID of the security group. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.GroupName | string | The name of the security group. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.PeeringStatus | string | The status of a VPC peering connection, if applicable. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.UserId | string | The ID of an AWS account. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.VpcId | string | The ID of the VPC for the referenced security group, if applicable. | 
| AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.VpcPeeringConnectionId | string | The ID of the VPC peering connection, if applicable. | 
| AWS.EC2.SecurityGroups.OwnerId | string | The AWS account ID of the owner of the security group. | 
| AWS.EC2.SecurityGroups.GroupId | string | The ID of the security group. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.FromPort | number | The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.IpProtocol | string | The IP protocol name \(tcp , udp , icmp\) or number. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.IpRanges.CidrIp | string | The IPv4 CIDR range. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.IpRanges.Description | string | A description for the security group rule that references this IPv4 address range. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.Ipv6Ranges.CidrIpv6 | string | The IPv6 CIDR range. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.Ipv6Ranges.Description | string | A description for the security group rule that references this IPv6 address range. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.PrefixListIds.Description | string | A description for the security group rule that references this prefix list ID. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.PrefixListIds.PrefixListId | string | The ID of the prefix. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.ToPort | string | The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.Description | string | A description for the security group rule that references this user ID group pair. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.GroupId | string | The ID of the security group. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.GroupName | string | The name of the security group. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.PeeringStatus | string | The status of a VPC peering connection, if applicable. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.UserId | string | The ID of an AWS account. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.VpcId | string | The ID of the VPC for the referenced security group, if applicable. | 
| AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.VpcPeeringConnectionId | string | The ID of the VPC peering connection, if applicable. | 
| AWS.EC2.SecurityGroups.VpcId | string | The ID of the VPC for the security group. | 
| AWS.EC2.SecurityGroups.Tags.Key | string | The key of the tag. | 
| AWS.EC2.SecurityGroups.Tags.Value | string | The value of the tag. | 
| AWS.EC2.SecurityGroups.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command Example
```!aws-ec2-describe-security-groups```

#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "SecurityGroups": [
                {
                    "Description": "AWS Ground Station receiver instance security group.",
                    "GroupId": "sg-1",
                    "GroupName": "gs-name",
                    "IpPermissions": [
                        {
                            "FromPort": 80,
                            "IpProtocol": "tcp",
                            "IpRanges": [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ],
                            "Ipv6Ranges": [
                                {
                                    "CidrIpv6": "::/0"
                                }
                            ],
                            "PrefixListIds": [],
                            "ToPort": 80,
                            "UserIdGroupPairs": []
                        },
                        {
                            "FromPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [
                                {
                                    "CidrIp": "10.0.0.0/16"
                                }
                            ],
                            "Ipv6Ranges": [],
                            "PrefixListIds": [],
                            "ToPort": 22,
                            "UserIdGroupPairs": []
                        },
                        {
                            "FromPort": 55888,
                            "IpProtocol": "udp",
                            "IpRanges": [],
                            "Ipv6Ranges": [],
                            "PrefixListIds": [],
                            "ToPort": 55888,
                            "UserIdGroupPairs": [
                                {
                                    "Description": "AWS Ground Station Downlink Stream",
                                    "GroupId": "sg-1",
                                    "UserId": "id"
                                }
                            ]
                        }
                    ],
                    "IpPermissionsEgress": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ],
                            "Ipv6Ranges": [],
                            "PrefixListIds": [],
                            "UserIdGroupPairs": []
                        }
                    ],
                    "OwnerId": "id",
                    "Region": "us-west-2",
                    "Tags": [
                        {
                            "Key": "aws:key",
                            "Value": "InstanceSecurityGroup"
                        }
                    ],
                    "VpcId": "vpc-1"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### AWS EC2 SecurityGroups
>|Description|GroupId|GroupName|OwnerId|Region|VpcId|aws:cloudformation:logical-id|aws:cloudformation:stack-id|aws:cloudformation:stack-name|
>|---|---|---|---|---|---|---|---|---|
>| AWS Ground Station receiver instance security group. | sg-1 | gs-name | id | us-west-2 | vpc-1 | InstanceSecurityGroup | arn| gs-aqua-receiver |
>| Demisto-PlaybookTest | sg-2 | Demisto-PlaybookTest | id | us-west-2 | vpc-2 |  |  |  |


### aws-ec2-allocate-address

***
Allocates an Elastic IP address.

#### Base Command

`aws-ec2-allocate-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ElasticIPs.PublicIp | Unknown | The Elastic IP address. | 
| AWS.EC2.ElasticIPs.AllocationId | string | The ID that AWS assigns to represent the allocation of the Elastic IP address for use with instances in a VPC. | 
| AWS.EC2.ElasticIPs.Domain | string | Indicates whether this Elastic IP address is for use with instances in EC2-Classic \(standard \) or instances in a VPC \(vpc\). | 
| AWS.EC2.ElasticIPs.Region | Unknown | The AWS region where the elastic IP is located. | 
| AWS.EC2.ElasticIPs.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-associate-address

***
Associates an Elastic IP address with an instance or a network interface.

#### Base Command

`aws-ec2-associate-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| allocationId | The allocation ID. | Required | 
| instanceId | The ID of the instance. For EC2-VPC, you can specify either the instance ID or the network interface ID, but not both. The operation fails if you specify an instance ID unless exactly one network interface is attached. | Optional | 
| allowReassociation | For a VPC in an EC2-Classic account, specify true to allow an Elastic IP address that is already associated with an instance or network interface to be reassociated with the specified instance or network interface. Otherwise, the operation fails. In a VPC in an EC2-VPC-only account, reassociation is automatic, therefore you can specify false to ensure the operation fails if the Elastic IP address is already associated with another resource. Possible values are: True, False. Default is False. | Optional | 
| networkInterfaceId | The ID of the network interface. If the instance has more than one network interface, you must specify a network interface ID. | Optional | 
| privateIpAddress | The primary or secondary private IP address to associate with the Elastic IP address. If no private IP address is specified, the Elastic IP address is associated with the primary private IP address. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ElasticIPs.AssociationId | string | The ID that represents the association of the Elastic IP address with an instance. | 
| AWS.EC2.ElasticIPs.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-create-snapshot

***
Creates a snapshot of an EBS volume and stores it in Amazon S3. You can use snapshots for backups, to make copies of EBS volumes, and to save data before shutting down an instance.

#### Base Command

`aws-ec2-create-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| volumeId | The ID of the EBS volume. | Required | 
| description | A description for the snapshot. | Optional | 
| tags | The tags to apply to the snapshot during creation. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Snapshots.DataEncryptionKeyId | string | The data encryption key identifier for the snapshot. | 
| AWS.EC2.Snapshots.Description | string | The description for the snapshot. | 
| AWS.EC2.Snapshots.Encrypted | number | Indicates whether the snapshot is encrypted. | 
| AWS.EC2.Snapshots.KmsKeyId | string | The full ARN of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the parent volume. | 
| AWS.EC2.Snapshots.OwnerId | string | The AWS account ID of the EBS snapshot owner. | 
| AWS.EC2.Snapshots.Progress | string | The progress of the snapshot, as a percentage. | 
| AWS.EC2.Snapshots.SnapshotId | string | The ID of the snapshot. | 
| AWS.EC2.Snapshots.StartTime | date | The time stamp when the snapshot was initiated. | 
| AWS.EC2.Snapshots.State | string | The snapshot state. | 
| AWS.EC2.Snapshots.StateMessage | string | this field displays error state details to help you diagnose why the error occurred. | 
| AWS.EC2.Snapshots.VolumeId | string | The ID of the volume that was used to create the snapshot. | 
| AWS.EC2.Snapshots.VolumeSize | number | The size of the volume, in GiB. | 
| AWS.EC2.Snapshots.OwnerAlias | string | Value from an Amazon-maintained list of snapshot owners. | 
| AWS.EC2.Snapshots.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Snapshots.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Snapshots.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-delete-snapshot

***
Deletes the specified snapshot.

#### Base Command

`aws-ec2-delete-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshotId | The ID of the EBS snapshot. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-create-image

***
Creates an Amazon EBS-backed AMI from an Amazon EBS-backed instance that is either running or stopped.

#### Base Command

`aws-ec2-create-image`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A name for the new image. | Required | 
| instanceId | The ID of the instance. | Required | 
| description | A description for the new image. | Optional | 
| noReboot | By default, Amazon EC2 attempts to shut down and reboot the instance before creating the image. If the noReboot option is set, Amazon EC2 won't shut down the instance before creating the image. When this option is used, file system integrity on the created image cant be guaranteed. Possible values are: True, False. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.ImageId | string | The ID of the new AMI. | 
| AWS.EC2.Images.Name | string | The name of the new AMI. | 
| AWS.EC2.Images.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Images.Region | string | The AWS region where the image is located. | 
| AWS.EC2.Images.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-deregister-image

***
Deregisters the specified AMI.

#### Base Command

`aws-ec2-deregister-image`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| imageId | The ID of the AMI. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-modify-volume

***
You can modify several parameters of an existing EBS volume, including volume size, volume type, and IOPS capacity.

#### Base Command

`aws-ec2-modify-volume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| volumeId | The ID of the volume. | Required | 
| size | Target size in GiB of the volume to be modified. | Optional | 
| volumeType | Target EBS volume type of the volume to be modified  The API does not support modifications for volume type standard . You also cannot change the type of a volume to standard . | Optional | 
| iops | Target IOPS rate of the volume to be modified. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.Modification.VolumeId | string | ID of the volume being modified. | 
| AWS.EC2.Volumes.Modification.ModificationState | string | Current state of modification. Modification state is null for unmodified. volumes. | 
| AWS.EC2.Volumes.Modification.StatusMessage | string | Generic status message on modification progress or failure. | 
| AWS.EC2.Volumes.Modification.TargetSize | number | Target size of the volume being modified. | 
| AWS.EC2.Volumes.Modification.TargetIops | number | Target IOPS rate of the volume being modified. | 
| AWS.EC2.Volumes.Modification.TargetVolumeType | string | Target EBS volume type of the volume being modified. | 
| AWS.EC2.Volumes.Modification.OriginalSize | number | Original size of the volume being modified. | 
| AWS.EC2.Volumes.Modification.OriginalIops | number | Original IOPS rate of the volume being modified. | 
| AWS.EC2.Volumes.Modification.OriginalVolumeType | string | Original EBS volume type of the volume being modified. | 
| AWS.EC2.Volumes.Modification.Progress | string | Modification progress from 0 to 100%. | 
| AWS.EC2.Volumes.Modification.StartTime | date | Modification start time. | 
| AWS.EC2.Volumes.Modification.EndTime | date | Modification completion or failure time. | 
| AWS.EC2.Volumes.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-create-tags

***
Adds or overwrites one or more tags for the specified Amazon EC2 resource or resources.

#### Base Command

`aws-ec2-create-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resources | The IDs of one or more resources to tag. For example, ami-1a2b3c4d. | Required | 
| tags | One or more tags. | Required | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-disassociate-address

***
Disassociates an Elastic IP address from the instance or network interface its associated with.

#### Base Command

`aws-ec2-disassociate-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| associationId | The association ID. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-release-address

***
Releases the specified Elastic IP address.

#### Base Command

`aws-ec2-release-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| allocationId | The allocation ID. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-start-instances

***
Starts an Amazon EBS-backed instance that you have previously stopped.

#### Base Command

`aws-ec2-start-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceIds | One or more instance IDs. Sepereted by comma. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-stop-instances

***
Stops an Amazon EBS-backed instance.

#### Base Command

`aws-ec2-stop-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceIds | One or more instance IDs. | Required | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-terminate-instances

***
Shuts down one or more instances. This operation is idempotent; if you terminate an instance more than once, each call succeeds.

#### Base Command

`aws-ec2-terminate-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceIds | One or more instance IDs. | Required | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-create-volume

***
Creates an EBS volume that can be attached to an instance in the same Availability Zone.

#### Base Command

`aws-ec2-create-volume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| availabilityZone | The Availability Zone in which to create the volume. Use DescribeAvailabilityZones to list the Availability Zones that are currently available to you. | Required | 
| encrypted | Specifies whether the volume should be encrypted. Possible values are: True, False. | Optional | 
| iops | The number of I/O operations per second (IOPS) to provision for the volume, with a maximum ratio of 50 IOPS/GiB. Range is 100 to 32000 IOPS for volumes in most regions. | Optional | 
| kmsKeyId | An identifier for the AWS Key Management Service (AWS KMS) customer master key (CMK) to use when creating the encrypted volume. This parameter is only required if you want to use a non-default CMK; if this parameter is not specified, the default CMK for EBS is used. If a KmsKeyId is specified, the Encrypted flag must also be set. | Optional | 
| size | The size of the volume, in GiBs. | Optional | 
| snapshotId | The snapshot from which to create the volume. | Optional | 
| volumeType | The volume type. Possible values are: standard, io1, gp2, sc1, st1. | Optional | 
| tags | One or more tags. Example key=Name,value=test;key=Owner,value=Bob. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.AvailabilityZone | string | The Availability Zone for the volume. | 
| AWS.EC2.Volumes.CreateTime | date | The time stamp when volume creation was initiated. | 
| AWS.EC2.Volumes.Encrypted | boolean | Indicates whether the volume will be encrypted. | 
| AWS.EC2.Volumes.KmsKeyId | string | The full ARN of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the volume. | 
| AWS.EC2.Volumes.Size | number | The size of the volume, in GiBs. | 
| AWS.EC2.Volumes.SnapshotId | string | The snapshot from which the volume was created, if applicable. | 
| AWS.EC2.Volumes.State | string | The volume state. | 
| AWS.EC2.Volumes.VolumeId | string | The ID of the volume. | 
| AWS.EC2.Volumes.Iops | number | The number of I/O operations per second \(IOPS\) that the volume supports. | 
| AWS.EC2.Volumes.VolumeType | string | The volume type. This can be gp2 for General Purpose SSD, io1 for Provisioned IOPS SSD, st1 for Throughput Optimized HDD, sc1 for Cold HDD, or standard for Magnetic volumes. | 
| AWS.EC2.Volumes.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Volumes.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Volumes.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-attach-volume

***
Attaches an EBS volume to a running or stopped instance and exposes it to the instance with the specified device name.

#### Base Command

`aws-ec2-attach-volume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device | The device name (for example, /dev/sdh or xvdh). | Required | 
| instanceId | The ID of the instance. | Required | 
| volumeId | The ID of the EBS volume. The volume and instance must be within the same Availability Zone. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.Attachments.AttachTime | date | The time stamp when the attachment initiated. | 
| AWS.EC2.Volumes.Attachments.Device | string | The device name. | 
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. | 
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. | 
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. | 
| AWS.EC2.Volumes.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-detach-volume

***
Detaches an EBS volume from an instance.

#### Base Command

`aws-ec2-detach-volume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| volumeId | The ID of the volume. | Required | 
| force | Forces detachment if the previous detachment attempt did not occur cleanly. This option can lead to data loss or a corrupted file system. Use this option only as a last resort to detach a volume from a failed instance. | Optional | 
| device | The device name (for example, /dev/sdh or xvdh). | Optional | 
| instanceId | The ID of the instance. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Volumes.Attachments.AttachTime | date | The time stamp when the attachment initiated. | 
| AWS.EC2.Volumes.Attachments.Device | string | The device name. | 
| AWS.EC2.Volumes.Attachments.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Volumes.Attachments.State | string | The attachment state of the volume. | 
| AWS.EC2.Volumes.Attachments.VolumeId | string | The ID of the volume. | 
| AWS.EC2.Volumes.Attachments.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. | 
| AWS.EC2.Volumes.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-delete-volume

***
Deletes the specified EBS volume. The volume must be in the available state (not attached to an instance).

#### Base Command

`aws-ec2-delete-volume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| volumeId | The ID of the volume. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-run-instances

***
Launches the specified number of instances using an AMI for which you have permissions. You can create a launch template , which is a resource that contains the parameters to launch an instance. When you launch an instance using RunInstances , you can specify the launch template instead of specifying the launch parameters. An instance is ready for you to use when its in the running state. You can check the state of your instance using DescribeInstances.

#### Base Command

`aws-ec2-run-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| count | The number of instances to launch. Must be greater than 0. Default is 1. | Required | 
| imageId | The ID of the AMI, which you can get by calling DescribeImages . An AMI is required to launch an instance and must be specified here or in a launch template. | Optional | 
| instanceType | The instance type. For example: t2.large. | Optional | 
| securityGroupIds | A comma-separated list of security group IDs.  | Optional | 
| securityGroups | One or more security group names. For a nondefault VPC, you must use security group IDs instead. | Optional | 
| subnetId | The ID of the subnet to launch the instance into. | Optional | 
| userData | The user data to make available to the instance.This value will be base64 encoded automatically. Do not base64 encode this value prior to performing the operation. | Optional | 
| disableApiTermination | If you set this parameter to true , you cant terminate the instance using the Amazon EC2 console, CLI, or API. Possible values are: True, False. | Optional | 
| iamInstanceProfileArn | The Amazon Resource Name (ARN) of the instance profile. Both iamInstanceProfileArn and iamInstanceProfile are required if you would like to associate an instance profile. | Optional | 
| iamInstanceProfileName | The name of the instance profile. Both iamInstanceProfileArn and iamInstanceProfile are required if you would like to associate an instance profile. | Optional | 
| keyName | The name of the key pair. Warning - If you do not specify a key pair, you cant connect to the instance unless you choose an AMI that is configured to allow users another way to log in. | Optional | 
| ebsOptimized | Indicates whether the instance is optimized for Amazon EBS I/O. Possible values are: True, False. | Optional | 
| deviceName | The device name (for example, /dev/sdh or xvdh). | Optional | 
| ebsVolumeSize | The size of the volume, in GiB. | Optional | 
| ebsVolumeType | The volume type. Possible values are: gp2, io1, st1, sc1, standard. | Optional | 
| ebsIops | The number of I/O operations per second (IOPS) that the volume supports. | Optional | 
| ebsDeleteOnTermination | Indicates whether the EBS volume is deleted on instance termination. Possible values are: True, False. | Optional | 
| ebsKmsKeyId | Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted. | Optional | 
| ebsSnapshotId | The ID of the snapshot. | Optional | 
| ebsEncrypted | Indicates whether the EBS volume is encrypted. | Optional | 
| launchTemplateId | The ID of the launch template. The launch template to use to launch the instances. Any parameters that you specify in RunInstances override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both. | Optional | 
| launchTemplateName | The name of the launch template. The launch template to use to launch the instances. Any parameters that you specify in RunInstances override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both. | Optional | 
| launchTemplateVersion | The version number of the launch template. | Optional | 
| tags | The tags to apply to the instance. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| host_id | The dedicated Host ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.AmiLaunchIndex | number | The AMI launch index, which can be used to find this instance in the launch group. | 
| AWS.EC2.Instances.ImageId | string | The ID of the AMI used to launch the instance. | 
| AWS.EC2.Instances.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Instances.InstanceType | string | The instance type. | 
| AWS.EC2.Instances.KernelId | string | The kernel associated with this instance, if applicable. | 
| AWS.EC2.Instances.KeyName | string | The name of the key pair, if this instance was launched with an associated key pair. | 
| AWS.EC2.Instances.LaunchTime | date | The time the instance was launched. | 
| AWS.EC2.Instances.Monitoring.State | string | Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled. | 
| AWS.EC2.Instances.Placement.AvailabilityZone | string | The Availability Zone of the instance. | 
| AWS.EC2.Instances.Placement.Affinity | string | The affinity setting for the instance on the Dedicated Host. | 
| AWS.EC2.Instances.Placement.GroupName | string | The name of the placement group the instance is in \(for cluster compute instances\). | 
| AWS.EC2.Instances.Placement.HostId | string | he ID of the Dedicated Host on which the instance resides. | 
| AWS.EC2.Instances.Placement.Tenancy | string | The tenancy of the instance \(if the instance is running in a VPC\). | 
| AWS.EC2.Instances.Platform | string | The value is Windows for Windows instances; otherwise blank. | 
| AWS.EC2.Instances.PrivateDnsName | string | \(IPv4 only\) The private DNS hostname name assigned to the instance. This DNS hostname can only be used inside the Amazon EC2 network. This name is not available until the instance enters the running state. | 
| AWS.EC2.Instances.PrivateIpAddress | string | The private IPv4 address assigned to the instance. | 
| AWS.EC2.Instances.ProductCodes.ProductCodeId | string | The product code. | 
| AWS.EC2.Instances.ProductCodes.ProductCodeType | string | The type of product code. | 
| AWS.EC2.Instances.PublicDnsName | string | \(IPv4 only\) The public DNS name assigned to the instance. This name is not available until the instance enters the running state. | 
| AWS.EC2.Instances.PublicIpAddress | string | The public IPv4 address assigned to the instance, if applicable. | 
| AWS.EC2.Instances.RamdiskId | string | The RAM disk associated with this instance, if applicable. | 
| AWS.EC2.Instances.State.Code | string | The low byte represents the state. | 
| AWS.EC2.Instances.State.Name | string | The current state of the instance. | 
| AWS.EC2.Instances.StateTransitionReason | string | The reason for the most recent state transition. This might be an empty string. | 
| AWS.EC2.Instances.SubnetId | string | The ID of the subnet in which the instance is running. | 
| AWS.EC2.Instances.VpcId | string | The ID of the VPC in which the instance is running. | 
| AWS.EC2.Instances.Architecture | string | The architecture of the image. | 
| AWS.EC2.Instances.BlockDeviceMappings.DeviceName | string | The device name \(for example, /dev/sdh or xvdh\). | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.AttachTime | string | The time stamp when the attachment initiated. | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.DeleteOnTermination | string | Indicates whether the volume is deleted on instance termination. | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.Status | string | The attachment state. | 
| AWS.EC2.Instances.BlockDeviceMappings.Ebs.VolumeId | string | The ID of the EBS volume. | 
| AWS.EC2.Instances.ClientToken | string | The idempotency token you provided when you launched the instance, if applicable. | 
| AWS.EC2.Instances.EbsOptimized | boolean | Indicates whether the instance is optimized for Amazon EBS I/O. | 
| AWS.EC2.Instances.EnaSupport | boolean | Specifies whether enhanced networking with ENA is enabled. | 
| AWS.EC2.Instances.Hypervisor | string | The hypervisor type of the instance. | 
| AWS.EC2.Instances.IamInstanceProfile.Arn | string | The Amazon Resource Name \(ARN\) of the instance profile. | 
| AWS.EC2.Instances.IamInstanceProfile.Id | string | The ID of the instance profile. | 
| AWS.EC2.Instances.InstanceLifecycle | string | Indicates whether this is a Spot Instance or a Scheduled Instance. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuId | string | The ID of the Elastic GPU. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationId | string | The ID of the association. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationState | string | The state of the association between the instance and the Elastic GPU. | 
| AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationTime | string | The time the Elastic GPU was associated with the instance. | 
| AWS.EC2.Instances.NetworkInterfaces.Association.IpOwnerId | string | The ID of the owner of the Elastic IP address. | 
| AWS.EC2.Instances.NetworkInterfaces.Association.PublicDnsName | string | The public DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.Association.PublicIp | string | The public IP address or Elastic IP address bound to the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachTime | date | The time stamp when the attachment initiated. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachmentId | string | The ID of the network interface attachment. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.DeleteOnTermination | boolean | Indicates whether the network interface is deleted when the instance is terminated. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.DeviceIndex | number | The index of the device on the instance for the network interface attachment. | 
| AWS.EC2.Instances.NetworkInterfaces.Attachment.Status | string | The attachment state. | 
| AWS.EC2.Instances.NetworkInterfaces.Description | string | The description. | 
| AWS.EC2.Instances.NetworkInterfaces.Groups.GroupName | string | The name of the security group. | 
| AWS.EC2.Instances.NetworkInterfaces.Groups.GroupId | string | The ID of the security group. | 
| AWS.EC2.Instances.NetworkInterfaces.Ipv6Addresses.Ipv6Address | string | The IPv6 addresses associated with the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.MacAddress | string | The MAC address. | 
| AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId | string | The ID of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.OwnerId | string | The ID of the AWS account that created the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName | string | The private DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress | string | The IPv4 address of the network interface within the subnet. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.IpOwnerId | string | The ID of the owner of the Elastic IP address. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicDnsName | string | The public DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicIp | string | The public IP address or Elastic IP address bound to the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Primary | boolean | Indicates whether this IPv4 address is the primary private IP address of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateDnsName | string | The private IPv4 DNS name. | 
| AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateIpAddress | string | The private IPv4 address of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck | boolean | Indicates whether to validate network traffic to or from this network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.Status | string | The status of the network interface. | 
| AWS.EC2.Instances.NetworkInterfaces.SubnetId | string | The ID of the subnet. | 
| AWS.EC2.Instances.NetworkInterfaces.VpcId | string | The ID of the VPC. | 
| AWS.EC2.Instances.RootDeviceName | string | The device name of the root device volume \(for example, /dev/sda1\). | 
| AWS.EC2.Instances.RootDeviceType | string | The root device type used by the AMI. The AMI can use an EBS volume or an instance store volume. | 
| AWS.EC2.Instances.SecurityGroups.GroupName | string | The name of the security group. | 
| AWS.EC2.Instances.SecurityGroups.GroupId | string | The ID of the security group. | 
| AWS.EC2.Instances.SourceDestCheck | boolean | Specifies whether to enable an instance launched in a VPC to perform NAT. | 
| AWS.EC2.Instances.SpotInstanceRequestId | string | If the request is a Spot Instance request, the ID of the request. | 
| AWS.EC2.Instances.SriovNetSupport | string | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. | 
| AWS.EC2.Instances.StateReason.Code | string | The reason code for the state change. | 
| AWS.EC2.Instances.StateReason.Message | string | The message for the state change. | 
| AWS.EC2.Instances.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Instances.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Instances.VirtualizationType | string | The virtualization type of the instance. | 
| AWS.EC2.Instances.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-waiter-instance-running

***
A waiter function that runs every 15  seconds until a successful state is reached.

#### Base Command

`aws-ec2-waiter-instance-running`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | One or more filters. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| instanceIds | One or more instance IDs. Sepreted by comma. | Optional | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default 15. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default 40. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-waiter-instance-status-ok

***
A waiter function that runs every 15 seconds until a successful state is reached.

#### Base Command

`aws-ec2-waiter-instance-status-ok`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | One or more filters. See documentation for details &amp; filter options. | Optional | 
| instanceIds | One or more instance IDs. Seprated by comma. | Optional | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default 15. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default 40. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-waiter-instance-stopped

***
A waiter function that runs every 15  seconds until a successful state is reached.

#### Base Command

`aws-ec2-waiter-instance-stopped`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | One or more filters. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| instanceIds | A comma-separated list of instance IDs. | Optional | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default 15. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default 40. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-waiter-instance-terminated

***
A waiter function that runs every 15 seconds until a successful state is reached.

#### Base Command

`aws-ec2-waiter-instance-terminated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | One or more filters. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| instanceIds | A comma-separated list of instance IDs.  | Optional | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default 15. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default 40. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-waiter-image-available

***
A waiter function that waits until image is avilable.

#### Base Command

`aws-ec2-waiter-image-available`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| imageIds | One or more image IDs. Sperated by comma. | Optional | 
| owners | Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon \| aws-marketplace \| microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership. | Optional | 
| executableUsers | Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs). | Optional | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default 15. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default 40. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-waiter-snapshot_completed

***
A waiter function that waits until the snapshot is complate.

#### Base Command

`aws-ec2-waiter-snapshot_completed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| ownerIds | Returns the snapshots owned by the specified owner. Multiple owners can be specified. Sperated by comma. | Optional | 
| snapshotIds | One or more snapshot IDs. Sperated by comma. | Optional | 
| restorableByUserIds | One or more AWS accounts IDs that can create volumes from the snapshot. | Optional | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default 15. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default 40. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-get-latest-ami

***
Get The latest AMI.

#### Base Command

`aws-ec2-get-latest-ami`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| owners | Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon \| aws-marketplace \| microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership. | Optional | 
| executableUsers | Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs). | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.Architecture | string | The architecture of the image. | 
| AWS.EC2.Images.CreationDate | date | The date and time the image was created. | 
| AWS.EC2.Images.ImageId | string | The ID of the AMI. | 
| AWS.EC2.Images.ImageLocation | string | The location of the AMI. | 
| AWS.EC2.Images.ImageType | string | The type of image. | 
| AWS.EC2.Images.Public | boolean | Indicates whether the image has public launch permissions. The value is true if this image has public launch permissions or false if it has only implicit and explicit launch permissions. | 
| AWS.EC2.Images.KernelId | string | The kernel associated with the image, if any. Only applicable for machine images. | 
| AWS.EC2.Images.OwnerId | string | The AWS account ID of the image owner. | 
| AWS.EC2.Images.Platform | string | The value is Windows for Windows AMIs; otherwise blank. | 
| AWS.EC2.Images.ProductCodes.ProductCodeId | string | The product code. | 
| AWS.EC2.Images.ProductCodes.ProductCodeType | string | The type of product code. | 
| AWS.EC2.Images.RamdiskId | string | The RAM disk associated with the image, if any. Only applicable for machine images. | 
| AWS.EC2.Images.State | string | The current state of the AMI. If the state is available , the image is successfully registered and can be used to launch an instance. | 
| AWS.EC2.Images.BlockDeviceMappings.DeviceName | string | The device name \(for example, /dev/sdh or xvdh \). | 
| AWS.EC2.Images.BlockDeviceMappings.VirtualName | string | The virtual device name \(ephemeral N\). | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Encrypted | boolean | Indicates whether the EBS volume is encrypted. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.DeleteOnTermination | boolean | Indicates whether the EBS volume is deleted on instance termination. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.Iops | number | The number of I/O operations per second \(IOPS\) that the volume supports. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.KmsKeyId | string | Identifier \(key ID, key alias, ID ARN, or alias ARN\) for a user-managed CMK under which the EBS volume is encrypted. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.SnapshotId | string | The ID of the snapshot. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeSize | number | The size of the volume, in GiB. | 
| AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeType | string | The volume type. | 
| AWS.EC2.Images.BlockDeviceMappings.NoDevice | string | Suppresses the specified device included in the block device mapping of the AMI. | 
| AWS.EC2.Images.Description | string | The description of the AMI that was provided during image creation. | 
| AWS.EC2.Images.EnaSupport | boolean | Specifies whether enhanced networking with ENA is enabled. | 
| AWS.EC2.Images.Hypervisor | string | The hypervisor type of the image. | 
| AWS.EC2.Images.ImageOwnerAlias | string | The AWS account alias \(for example, amazon , self \) or the AWS account ID of the AMI owner. | 
| AWS.EC2.Images.Name | string | The name of the AMI that was provided during image creation. | 
| AWS.EC2.Images.RootDeviceName | string | The device name of the root device volume \(for example, /dev/sda1\). | 
| AWS.EC2.Images.RootDeviceType | string | The type of root device used by the AMI. The AMI can use an EBS volume or an instance store volume. | 
| AWS.EC2.Images.SriovNetSupport | string | Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled. | 
| AWS.EC2.Images.StateReason.Code | string | The reason code for the state change. | 
| AWS.EC2.Images.StateReason.Message | string | The message for the state change. | 
| AWS.EC2.Images.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Images.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Images.VirtualizationType | string | The type of virtualization of the AMI. | 
| AWS.EC2.Images.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-create-security-group

***
Creates a security group.

#### Base Command

`aws-ec2-create-security-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | The name of the security group. | Required | 
| description | A description for the security group. | Required | 
| vpcId | The ID of the VPC. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.SecurityGroups.GroupName | string | The name of the security group. | 
| AWS.EC2.SecurityGroups.Description | string | A description for the security group. | 
| AWS.EC2.SecurityGroups.VpcId | string | The ID of the VPC. | 
| AWS.EC2.SecurityGroups.GroupId | string | The ID of the security group. | 
| AWS.EC2.SecurityGroups.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-delete-security-group

***
Deletes a security group.

#### Base Command

`aws-ec2-delete-security-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | The ID of the security group. Required for a nondefault VPC. | Optional | 
| groupName | default VPC only.  The name of the security group. You can specify either the security group name or the security group ID. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-authorize-security-group-ingress-rule

***
Adds ingress rule to a security group.

#### Base Command

`aws-ec2-authorize-security-group-ingress-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | The ID of the security group. You must specify either the security group ID or the security group name in the request. For security groups in a nondefault VPC, you must specify the security group ID. | Required | 
| fromPort | The start of port range for the TCP and UDP protocols. | Optional | 
| toPort | The end of port range for the TCP and UDP protocols. | Optional | 
| cidrIp | The CIDR IPv4 address range. | Optional | 
| ipProtocol | The IP protocol name (tcp , udp , icmp) or number.  Use -1 to specify all protocols. | Optional | 
| sourceSecurityGroupName | The name of the source security group. The source security group must be in the same VPC. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| IpPermissionsfromPort | The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpPermissionsIpProtocol | The IP protocol name (tcp, udp, icmp, icmpv6) or number. | Optional | 
| IpPermissionsToPort | The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpRangesCidrIp | The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv4 address, use the /32 prefix length. | Optional | 
| IpRangesDesc | A description for the security group rule that references this IPv4 address range.<br/><br/>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| Ipv6RangesCidrIp | The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length. | Optional | 
| Ipv6RangesDesc | A description for the security group rule that references this IPv6 address range.<br/><br/>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| PrefixListId | The ID of the prefix. | Optional | 
| PrefixListIdDesc | A description for the security group rule that references this prefix list ID.<br/><br/>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| UserIdGroupPairsDescription | A description for the security group rule that references this user ID group pair.<br/><br/>Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| UserIdGroupPairsGroupId | The ID of the security group. | Optional | 
| UserIdGroupPairsGroupName | The name of the security group. In a request, use this parameter for a security group in EC2-Classic or a default VPC only. For a security group in a nondefault VPC, use the security group ID. | Optional | 
| UserIdGroupPairsPeeringStatus | The status of a VPC peering connection, if applicable. | Optional | 
| UserIdGroupPairsUserId | The ID of an AWS account. | Optional | 
| UserIdGroupPairsVpcId | The ID of the VPC for the referenced security group, if applicable. | Optional | 
| UserIdGroupPairsVpcPeeringConnectionId | The ID of the VPC peering connection, if applicable. | Optional | 
| IpPermissionsFull | Full IpPermissions argument as a string to more easily copy rules (e.x. """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""). | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-authorize-security-group-egress-rule

***
Adds egress rule to a security group.

#### Base Command

`aws-ec2-authorize-security-group-egress-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | The ID of the security group. You must specify either the security group ID or the security group name in the request. For security groups in a nondefault VPC, you must specify the security group ID. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| IpPermissionsfromPort | The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpPermissionsIpProtocol | The IP protocol name (tcp, udp, icmp, icmpv6) or number. | Optional | 
| IpPermissionsToPort | The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpRangesCidrIp | The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv4 address, use the /32 prefix length. | Optional | 
| IpRangesDesc | A description for the security group rule that references this IPv4 address range. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| Ipv6RangesCidrIp | The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length. | Optional | 
| Ipv6RangesDesc | A description for the security group rule that references this IPv6 address range. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| PrefixListId | The ID of the prefix. | Optional | 
| PrefixListIdDesc | A description for the security group rule that references this prefix list ID. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| UserIdGroupPairsDescription | A description for the security group rule that references this user ID group pair. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| UserIdGroupPairsGroupId | The ID of the security group. | Optional | 
| UserIdGroupPairsGroupName | The name of the security group. In a request, use this parameter for a security group in EC2-Classic or a default VPC only. For a security group in a nondefault VPC, use the security group ID. | Optional | 
| UserIdGroupPairsPeeringStatus | The status of a VPC peering connection, if applicable. | Optional | 
| UserIdGroupPairsUserId | The ID of an AWS account. | Optional | 
| UserIdGroupPairsVpcId | The ID of the VPC for the referenced security group, if applicable. | Optional | 
| UserIdGroupPairsVpcPeeringConnectionId | The ID of the VPC peering connection, if applicable. | Optional | 
| IpPermissionsFull | Full IpPermissions argument as a string to more easily copy rules (e.x. """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""). | Optional | 


#### Context Output

There is no context output for this command.

### aws-ec2-revoke-security-group-ingress-rule
***
Removes egress rule from a security group. To remove a rule, the values that you specify (for example, ports) must match the existing rule's values exactly.


#### Base Command

`aws-ec2-revoke-security-group-ingress-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | The ID of the security group. | Required | 
| fromPort | The start of port range for the TCP and UDP protocols. | Optional | 
| toPort | The end of port range for the TCP and UDP protocols. | Optional | 
| cidrIp | The CIDR IPv4 address range. | Optional | 
| cidrIpv6 | The CIDR IPv6 address range. | Optional | 
| ipProtocol | The IP protocol name (tcp , udp , icmp) or number. Use -1 to specify all protocols. | Optional | 
| sourceSecurityGroupName | The name of the source security group. The source security group must be in the same VPC. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| IpPermissionsFull | Full IpPermissions argument as a string to more easily target rules (e.x. """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""). | Optional | 


#### Context Output

There is no context output for this command.


### aws-ec2-revoke-security-group-egress-rule
***
(VPC only) Removes the specified egress rules from a security group for EC2-VPC. This action does not apply to security groups for use in EC2-Classic. To remove a rule, the values that you specify (for example, ports) must match the existing rule's values exactly.


#### Base Command

`aws-ec2-revoke-security-group-egress-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | The ID of the security group. | Required | 
| IpPermissionsfromPort | The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpPermissionsToPort | The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpPermissionsIpProtocol | The IP protocol name (tcp, udp, icmp, icmpv6) or number. | Optional | 
| IpRangesCidrIp | The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv4 address, use the /32 prefix length. | Optional | 
| IpRangesDescription | A description for the security group rule that references this IPv4 address range.Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$* | Optional | 
| Ipv6RangesCidrIp | The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length. | Optional | 
| Ipv6RangesDescription | A description for the security group rule that references this IPv6 address range. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$* | Optional | 
| PrefixListId | The ID of the prefix. | Optional | 
| PrefixListIdDescription | A description for the security group rule that references this prefix list ID. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$* | Optional | 
| UserIdGroupPairsDescription | A description for the security group rule that references this prefix list ID. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$* | Optional | 
| UserIdGroupPairsGroupId | The ID of the security group. | Optional | 
| UserIdGroupPairsGroupName | The name of the security group. In a request, use this parameter for a security group in EC2-Classic or a default VPC only. For a security group in a nondefault VPC, use the security group ID. For a referenced security group in another VPC, this value is not returned if the referenced security group is deleted. | Optional | 
| UserIdGroupPairsPeeringStatus | The status of a VPC peering connection, if applicable. | Optional | 
| UserIdGroupPairsUserId | The ID of an AWS account. For a referenced security group in another VPC, the account ID of the referenced security group is returned in the response. If the referenced security group is deleted, this value is not returned. [EC2-Classic] Required when adding or removing rules that reference a security group in another AWS account. | Optional | 
| UserIdGroupPairsVpcId | The ID of the VPC for the referenced security group, if applicable. | Optional | 
| UserIdGroupPairsVpcPeeringConnectionId | The ID of the VPC peering connection, if applicable. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| IpPermissionsFull | Full IpPermissions argument as a string to more easily target rules (e.x. """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""). | Optional | 


#### Context Output

There is no context output for this command.
### aws-ec2-copy-image

***
Initiates the copy of an AMI from the specified source region to the current region.

#### Base Command

`aws-ec2-copy-image`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new AMI in the destination region. | Required | 
| sourceImageId | The ID of the AMI to copy. | Required | 
| sourceRegion | The name of the region that contains the AMI to copy. | Required | 
| description | A description for the new AMI in the destination region. | Optional | 
| encrypted | Specifies whether the destination snapshots of the copied image should be encrypted. The default CMK for EBS is used unless a non-default AWS Key Management Service (AWS KMS) CMK is specified with KmsKeyId . Possible values are: True, False. | Optional | 
| kmsKeyId | An identifier for the AWS Key Management Service (AWS KMS) customer master key (CMK) to use when creating the encrypted volume. This parameter is only required if you want to use a non-default CMK; if this parameter is not specified, the default CMK for EBS is used. If a KmsKeyId is specified, the Encrypted flag must also be set. | Optional | 
| clientToken | nique, case-sensitive identifier you provide to ensure idempotency of the request. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Images.ImageId | string | The ID of the new AMI. | 
| AWS.EC2.Images.Region | string | The Region where the image is located. | 
| AWS.EC2.Images.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-copy-snapshot

***
Copies a point-in-time snapshot of an EBS volume and stores it in Amazon S3. You can copy the snapshot within the same region or from one region to another.

#### Base Command

`aws-ec2-copy-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sourceSnapshotId | The ID of the EBS snapshot to copy. | Required | 
| sourceRegion | The ID of the region that contains the snapshot to be copied. | Required | 
| description | A description for the EBS snapshot. | Optional | 
| encrypted |  Specifies whether the destination snapshot should be encrypted. You can encrypt a copy of an unencrypted snapshot using this flag, but you cannot use it to create an unencrypted copy from an encrypted snapshot. Your default CMK for EBS is used unless a non-default AWS Key Management Service (AWS KMS) CMK is specified with KmsKeyId . | Optional | 
| kmsKeyId | An identifier for the AWS Key Management Service (AWS KMS) customer master key (CMK) to use when creating the encrypted volume. This parameter is only required if you want to use a non-default CMK; if this parameter is not specified, the default CMK for EBS is used. If a KmsKeyId is specified, the Encrypted flag must also be set. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Snapshots.SnapshotId | string | The ID of the new snapshot. | 
| AWS.EC2.Snapshots.Region | string | The Region where the snapshot is located. | 
| AWS.EC2.Snapshots.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-describe-reserved-instances

***
Describes one or more of the Reserved Instances that you purchased.

#### Base Command

`aws-ec2-describe-reserved-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| reservedInstancesIds | One or more Reserved Instance IDs. Separated by comma. | Optional | 
| offeringClass | Describes whether the Reserved Instance is Standard or Convertible. Possible values are: standard, convertible. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.ReservedInstances.AvailabilityZone | string | The Availability Zone in which the Reserved Instance can be used. | 
| AWS.EC2.ReservedInstances.Duration | number | The duration of the Reserved Instance, in seconds. | 
| AWS.EC2.ReservedInstances.End | date | The time when the Reserved Instance expires. | 
| AWS.EC2.ReservedInstances.FixedPrice | number | The purchase price of the Reserved Instance. | 
| AWS.EC2.ReservedInstances.InstanceCount | number | The number of reservations purchased. | 
| AWS.EC2.ReservedInstances.InstanceType | string | The instance type on which the Reserved Instance can be used. | 
| AWS.EC2.ReservedInstances.ProductDescription | string | The Reserved Instance product platform description. | 
| AWS.EC2.ReservedInstances.ReservedInstancesId | string | The ID of the Reserved Instance. | 
| AWS.EC2.ReservedInstances.Start | date | The date and time the Reserved Instance started. | 
| AWS.EC2.ReservedInstances.State | string | The state of the Reserved Instance purchase. | 
| AWS.EC2.ReservedInstances.UsagePrice | number | The usage price of the Reserved Instance, per hour. | 
| AWS.EC2.ReservedInstances.CurrencyCode | string | The currency of the Reserved Instance. It's specified using ISO 4217 standard currency codes. At this time, the only supported currency is USD . | 
| AWS.EC2.ReservedInstances.InstanceTenancy | string | The tenancy of the instance. | 
| AWS.EC2.ReservedInstances.OfferingClass | string | The offering class of the Reserved Instance. | 
| AWS.EC2.ReservedInstances.OfferingType | string | The Reserved Instance offering type. | 
| AWS.EC2.ReservedInstances.RecurringCharges.Amount | number | The amount of the recurring charge. | 
| AWS.EC2.ReservedInstances.RecurringCharges.Frequency | string | he frequency of the recurring charge. | 
| AWS.EC2.ReservedInstances.Scope | string | The scope of the Reserved Instance. | 
| AWS.EC2.ReservedInstances.Tags.Key | string | The key of the tag. | 
| AWS.EC2.ReservedInstances.Tags.Value | string | The value of the tag. | 
| AWS.EC2.ReservedInstances.Region | string | The AWS region where the reserved instance is located. | 
| AWS.EC2.ReservedInstances.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-monitor-instances

***
Enables detailed monitoring for a running instance.

#### Base Command

`aws-ec2-monitor-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instancesIds | One or more instance IDs. Separated by comma. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.InstanceId | string | The ID of the instance. | 
| AWS.EC2.Instances.Monitoring.State | string | Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled. | 
| AWS.EC2.Instances.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-unmonitor-instances

***
Disables detailed monitoring for a running instance.

#### Base Command

`aws-ec2-unmonitor-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instancesIds | One or more instance IDs. Separated by comma. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.InstanceId | Unknown | The ID of the instance. | 
| AWS.EC2.Instances.Monitoring.State | Unknown | Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled. | 
| AWS.EC2.Instances.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-reboot-instances

***
Requests a reboot of one or more instances. This operation is asynchronous; it only queues a request to reboot the specified instances. The operation succeeds if the instances are valid and belong to you. Requests to reboot terminated instances are ignored. If an instance does not cleanly shut down within four minutes, Amazon EC2 performs a hard reboot.

#### Base Command

`aws-ec2-reboot-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceIds | One or more instance IDs. Separated by comma. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-get-password-data

***
Retrieves the encrypted administrator password for a running Windows instance.

#### Base Command

`aws-ec2-get-password-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceId | The ID of the Windows instance. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Instances.PasswordData.PasswordData | string | The password of the instance. Returns an empty string if the password is not available. | 
| AWS.EC2.Instances.PasswordData.Timestamp | date | The time the data was last updated. | 
| AWS.EC2.Instances.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-modify-network-interface-attribute

***
Modifies the specified network interface attribute. You can specify only one attribute at a time.

#### Base Command

`aws-ec2-modify-network-interface-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkInterfaceId | The ID of the network interface. | Required | 
| groups | Changes the security groups for the network interface. The new set of groups you specify replaces the current set. You must specify at least one group, even if it's just the default security group in the VPC. You must specify the ID of the security group, not the name. | Optional | 
| sourceDestCheck | Indicates whether source/destination checking is enabled. A value of true means checking is enabled, and false means checking is disabled. This value must be false for a NAT instance to perform NAT. Possible values are: True, False. | Optional | 
| description | A description for the network interface. | Optional | 
| attachmentId | The ID of the network interface attachment. Information about the interface attachment. If modifying the 'delete on termination' attribute, you must specify the ID of the interface attachment. | Optional | 
| deleteOnTermination | Indicates whether the network interface is deleted when the instance is terminated. Information about the interface attachment. If modifying the 'delete on termination' attribute, you must specify the ID of the interface attachment. Possible values are: True, False. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-modify-instance-attribute

***
Modifies the specified attribute of the specified instance. You can specify only one attribute at a time. Using this action to change the security groups associated with an elastic network interface (ENI) attached to an instance in a VPC can result in an error if the instance has more than one ENI. To change the security groups associated with an ENI attached to an instance that has multiple ENIs, we recommend that you use the ModifyNetworkInterfaceAttribute action.

#### Base Command

`aws-ec2-modify-instance-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instanceId | The ID of the instance. | Required | 
| sourceDestCheck | Specifies whether source/destination checking is enabled. A value of true means that checking is enabled, and false means that checking is disabled. This value must be false for a NAT instance to perform NAT. Possible values are: True, False. | Optional | 
| disableApiTermination | If the value is true , you can't terminate the instance using the Amazon EC2 console, CLI, or API; otherwise, you can. You cannot use this parameter for Spot Instances. Possible values are: True, False. | Optional | 
| ebsOptimized | Specifies whether the instance is optimized for Amazon EBS I/O. This optimization provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal EBS I/O performance. This optimization isn't available with all instance types. Additional usage charges apply when using an EBS Optimized instance. Possible values are: True, False. | Optional | 
| enaSupport | Set to true to enable enhanced networking with ENA for the instance.  This option is supported only for HVM instances. Specifying this option with a PV instance can make it unreachable. Possible values are: True, False. | Optional | 
| instanceType | Changes the instance type to the specified value. | Optional | 
| instanceInitiatedShutdownBehavior | Specifies whether an instance stops or terminates when you initiate shutdown from the instance (using the operating system command for system shutdown). Possible values are: Stop, Terminate. | Optional | 
| groups | [EC2-VPC] Changes the security groups of the instance. You must specify at least one security group, even if it's just the default security group for the VPC. You must specify the security group ID, not the security group name. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-create-network-acl

***
Creates a network ACL in a VPC. Network ACLs provide an optional layer of security (in addition to security groups) for the instances in your VPC.

#### Base Command

`aws-ec2-create-network-acl`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| DryRun | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. Possible values are: True, False. | Optional | 
| VpcId | The ID of the VPC. | Required | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.VpcId.NetworkAcl.Associations.NetworkAclAssociationId | String | The ID of the association between a network ACL and a subnet. | 
| AWS.EC2.VpcId.NetworkAcl.Associations.NetworkAclId | String | The ID of the network ACL. | 
| AWS.EC2.VpcId.NetworkAcl.Associations.SubnetId | String | The ID of the subnet. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.CidrBlock | String | The IPv4 network range to allow or deny, in CIDR notation. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.Egress | Boolean | Indicates whether the rule is an egress rule \(applied to traffic leaving the subnet\). | 
| AWS.EC2.VpcId.NetworkAcl.Entries.IcmpTypeCode.Code | Number | The ICMP code. A value of -1 means all codes for the specified ICMP type. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.IcmpTypeCode.Type | Number | The ICMP type. A value of -1 means all types. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.Ipv6CidrBlock | String | The IPv6 network range to allow or deny, in CIDR notation. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.PortRange.From | Number | The first port in the range. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.PortRange.To | Number | The last port in the range. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.Protocol | String | The protocol number. A value of "-1" means all protocols. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.RuleAction | String | Indicates whether to allow or deny the traffic that matches the rule. | 
| AWS.EC2.VpcId.NetworkAcl.Entries.RuleNumber | Number | The rule number for the entry. ACL entries are processed in ascending order by rule number. | 
| AWS.EC2.VpcId.NetworkAcl.NetworkAclId | String | The ID of the network ACL. | 
| AWS.EC2.VpcId.NetworkAcl.Tags.Key | String | The key of the tag. | 
| AWS.EC2.VpcId.NetworkAcl.Tags.Value | String | The value of the tag. | 
| AWS.EC2.VpcId.NetworkAcl.VpcId | String | The ID of the VPC for the network ACL. | 
| AWS.EC2.VpcId.NetworkAcl.OwnerId | String | The ID of the AWS account that owns the network ACL. | 
| AWS.EC2.VpcId.NetworkAcl.AccountId | String | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-create-network-acl-entry

***
Creates an entry (a rule) in a network ACL with the specified rule number.

#### Base Command

`aws-ec2-create-network-acl-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CidrBlock | The IPv4 network range to allow or deny, in CIDR notation (for example 172.16.0.0/24 ). | Optional | 
| DryRun | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. Possible values are: True, False. | Optional | 
| Egress | Indicates whether this is an egress rule (rule is applied to traffic leaving the subnet). Possible values are: True, False. | Required | 
| Code | The ICMP code. A value of -1 means all codes for the specified ICMP type. | Optional | 
| Type | The ICMP type. A value of -1 means all types. | Optional | 
| Ipv6CidrBlock | The IPv6 network range to allow or deny, in CIDR notation (for example 2001:db8:1234:1a00::/64 ). | Optional | 
| NetworkAclId | The ID of the network ACL. | Required | 
| From | The first port in the range. | Optional | 
| To | The last port in the range. | Optional | 
| Protocol | The protocol number. A value of "-1" means all protocols. If you specify "-1" or a protocol number other than "6" (TCP), "17" (UDP), or "1" (ICMP), traffic on all ports is allowed, regardless of any ports or ICMP types or codes that you specify. If you specify protocol "58" (ICMPv6) and specify an IPv4 CIDR block, traffic for all ICMP types and codes allowed, regardless of any that you specify. If you specify protocol "58" (ICMPv6) and specify an IPv6 CIDR block, you must specify an ICMP type and code. | Required | 
| RuleAction | Indicates whether to allow or deny the traffic that matches the rule. | Required | 
| RuleNumber | The rule number for the entry (for example, 100). ACL entries are processed in ascending order by rule number. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-create-fleet

***
Launches an EC2 Fleet.

#### Base Command

`aws-ec2-create-fleet`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| DryRun | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. Possible values are: True, False. | Optional | 
| ClientToken | Unique, case-sensitive identifier you provide to ensure the idempotency of the request. | Optional | 
| SpotAllocationStrategy | Indicates how to allocate the target capacity across the Spot pools specified by the Spot Fleet request. | Optional | 
| InstanceInterruptionBehavior | The behavior when a Spot Instance is interrupted. | Optional | 
| InstancePoolsToUseCount | The number of Spot pools across which to allocate your target Spot capacity. | Optional | 
| SpotSingleInstanceType | Indicates that the fleet uses a single instance type to launch all Spot Instances in the fleet. Possible values are: True, False. | Optional | 
| SpotMinTargetCapacity | The minimum target capacity for Spot Instances in the fleet. If the minimum target capacity is not reached, the fleet launches no instances. | Optional | 
| OnDemandAllocationStrategy | The order of the launch template overrides to use in fulfilling On-Demand capacity. | Optional | 
| OnDemandSingleInstanceType | Indicates that the fleet uses a single instance type to launch all On-Demand Instances in the fleet. | Optional | 
| OnDemandSingleAvailabilityZone | Indicates that the fleet launches all On-Demand Instances into a single Availability Zone. | Optional | 
| OnDemandMinTargetCapacity | The minimum target capacity for On-Demand Instances in the fleet. If the minimum target capacity is not reached, the fleet launches no instances. | Optional | 
| ExcessCapacityTerminationPolicy |  Indicates whether running instances should be terminated if the total target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet. | Optional | 
| LaunchTemplateId | The ID of the launch template. | Required | 
| LaunchTemplateName | The name of the launch template. | Required | 
| Version | The version number of the launch template. | Required | 
| OverrideInstanceType | The instance type. | Optional | 
| OverrideMaxPrice | The maximum price per unit hour that you are willing to pay for a Spot Instance. | Optional | 
| OverrideSubnetId | The ID of the subnet in which to launch the instances. | Optional | 
| OverrideAvailabilityZone | The Availability Zone in which to launch the instances. | Optional | 
| OverrideWeightedCapacity | The number of units provided by the specified instance type. | Optional | 
| OverridePriority | The priority for the launch template override. | Optional | 
| TotalTargetCapacity | The number of units to request, filled using DefaultTargetCapacityType . | Required | 
| OnDemandTargetCapacity | The number of On-Demand units to request. | Required | 
| SpotTargetCapacity | The number of Spot units to request. | Required | 
| DefaultTargetCapacityType | The default TotalTargetCapacity, which is either Spot or On-Demand . | Required | 
| Type | The type of the request. | Optional | 
| ValidFrom | The start date and time of the request, in UTC format (for example, YYYY -MM -DD T*HH* :MM :SS Z). | Optional | 
| ValidUntil | The end date and time of the request, in UTC format (for example, YYYY -MM -DD T*HH* :MM :SS Z). | Optional | 
| ReplaceUnhealthyInstances | Indicates whether EC2 Fleet should replace unhealthy instances. | Optional | 
| Tags | The tags to apply to the resource. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Fleet.FleetId | String | The ID of the EC2 Fleet. | 
| AWS.EC2.Fleet.Errors | String | Information about the instances that could not be launched by the fleet. Valid only when Type is set to instant. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId | String | The ID of the launch template. You must specify either a template ID or a template name. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName | String | The name of the launch template. You must specify either a template name or a template ID. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version | String | The version number of the launch template. You must specify a version number. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.InstanceType | String | The instance type. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.MaxPrice | String | The maximum price per unit hour that you are willing to pay for a Spot Instance. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.SubnetId | String | The ID of the subnet in which to launch the instances. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.AvailabilityZone | String | The Availability Zone in which to launch the instances. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.WeightedCapacity | String | The number of units provided by the specified instance type. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.Priority | String | The priority for the launch template override. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.Placement.GroupName | String | The name of the placement group the instance is in. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.Lifecycle | String | Indicates if the instance that could not be launched was a Spot Instance or On-Demand Instance. | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.ErrorCode | String | The error code that indicates why the instance could not be launched.  | 
| AWS.EC2.Fleet.LaunchTemplateAndOverrides.ErrorMessage | String | The error message that describes why the instance could not be launched. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId | String | The ID of the launch template. You must specify either a template ID or a template name. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName | String | The name of the launch template. You must specify either a template name or a template ID. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version | String | The version number of the launch template. You must specify a version number. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.InstanceType | String | The instance type. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.MaxPrice | String | The maximum price per unit hour that you are willing to pay for a Spot Instance. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.SubnetId | String | The ID of the subnet in which to launch the instances. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.AvailabilityZone | String | The Availability Zone in which to launch the instances. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.WeightedCapacity | Number | The number of units provided by the specified instance type. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Priority | Number | The priority for the launch template override. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Placement.GroupName | String | The name of the placement group the instance is in. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Lifecycle | String | Indicates if the instance that was launched is a Spot Instance or On-Demand Instance. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.InstanceIds | String | The IDs of the instances. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.InstanceType | String | The instance type. | 
| AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Platform | String | The value is Windows for Windows instances; otherwise blank. | 
| AWS.EC2.Fleet.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-delete-fleet

***
Deletes the specified EC2 Fleet.

#### Base Command

`aws-ec2-delete-fleet`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| DryRun | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. | Optional | 
| FleetIds | The IDs of the EC2 Fleets. | Required | 
| TerminateInstances | Indicates whether to terminate instances for an EC2 Fleet if it is deleted successfully. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.CurrentFleetState | String | The current state of the EC2 Fleet. | 
| AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.PreviousFleetState | String | The previous state of the EC2 Fleet. | 
| AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.FleetId | String | The ID of the EC2 Fleet. | 
| AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.Error.Code | String | The error code. | 
| AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.Error.Message | String | The description for the error code. | 
| AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.FleetId | String | The ID of the EC2 Fleet. | 
| AWS.EC2.DeletedFleets.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-describe-fleets

***
Describes one or more of your EC2 Fleets.

#### Base Command

`aws-ec2-describe-fleets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| FleetIds | The ID of the EC2 Fleets. | Optional | 
| MaxResults | The maximum number of results to return in a single call. Specify a value between 1 and 1000. | Optional | 
| NextToken | The token for the next set of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Fleet.NextToken | string | The token for the next set of results. | 
| AWS.EC2.Fleet.Fleets.ActivityStatus | string | The progress of the EC2 Fleet. If there is an error, the status is error .  | 
| AWS.EC2.Fleet.Fleets.CreateTime | date | The creation date and time of the EC2 Fleet. | 
| AWS.EC2.Fleet.Fleets.FleetId | string | The ID of the EC2 Fleet. | 
| AWS.EC2.Fleet.Fleets.FleetState | string | The state of the EC2 Fleet. | 
| AWS.EC2.Fleet.Fleets.ClientToken | string | Unique, case-sensitive identifier you provide to ensure the idempotency of the request. | 
| AWS.EC2.Fleet.Fleets.ExcessCapacityTerminationPolicy | string | Indicates whether running instances should be terminated if the target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet. | 
| AWS.EC2.Fleet.Fleets.FulfilledCapacity | number | The number of units fulfilled by this request compared to the set target capacity. | 
| AWS.EC2.Fleet.Fleets.FulfilledOnDemandCapacity | number | The number of units fulfilled by this request compared to the set target On-Demand capacity. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.LaunchTemplateId | string | The ID of the launch template. You must specify either a template ID or a template name. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.LaunchTemplateName | string | The name of the launch template. You must specify either a template name or a template ID. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Version | string | The version number of the launch template. You must specify a version number. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.InstanceType | string | The instance type. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.MaxPrice | string | The maximum price per unit hour that you are willing to pay for a Spot Instance. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.SubnetId | string | The ID of the subnet in which to launch the instances. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.AvailabilityZone | string | The Availability Zone in which to launch the instances. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.WeightedCapacity | number | The number of units provided by the specified instance type. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.Priority | number | The priority for the launch template override. | 
| AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.Placement.GroupName | string | The name of the placement group the instance is in. | 
| AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.TotalTargetCapacity | number | The number of units to request, filled using DefaultTargetCapacityType . | 
| AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.OnDemandTargetCapacity | number | The number of On-Demand units to request. | 
| AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.SpotTargetCapacity | number | The maximum number of Spot units to launch. | 
| AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.DefaultTargetCapacityType | string | The default TotalTargetCapacity , which is either Spot or On-Demand. | 
| AWS.EC2.Fleet.Fleets.TerminateInstancesWithExpiration | boolean | Indicates whether running instances should be terminated when the EC2 Fleet expires. | 
| AWS.EC2.Fleet.Fleets.Type | string | The type of request. Indicates whether the EC2 Fleet only requests the target capacity, or also attempts to maintain it. | 
| AWS.EC2.Fleet.Fleets.ValidFrom | date | The start date and time of the request, in UTC format \(for example, YYYY -MM -DD T\*HH\* :MM :SS Z\). | 
| AWS.EC2.Fleet.Fleets.ValidUntil | date | The end date and time of the request, in UTC format \(for example, YYYY -MM -DD T\*HH\* :MM :SS Z\). | 
| AWS.EC2.Fleet.Fleets.ReplaceUnhealthyInstances | boolean | Indicates whether EC2 Fleet should replace unhealthy instances. | 
| AWS.EC2.Fleet.Fleets.SpotOptions.AllocationStrategy | string | Indicates how to allocate the target capacity across the Spot pools specified by the Spot Fleet request. | 
| AWS.EC2.Fleet.Fleets.SpotOptions.InstanceInterruptionBehavior | string | The behavior when a Spot Instance is interrupted. The default is terminate. | 
| AWS.EC2.Fleet.Fleets.SpotOptions.InstancePoolsToUseCount | number | The number of Spot pools across which to allocate your target Spot capacity. | 
| AWS.EC2.Fleet.Fleets.SpotOptions.SingleInstanceType | boolean | Indicates that the fleet uses a single instance type to launch all Spot Instances in the fleet. | 
| AWS.EC2.Fleet.Fleets.SpotOptions.SingleAvailabilityZone | boolean | Indicates that the fleet launches all Spot Instances into a single Availability Zone. | 
| AWS.EC2.Fleet.Fleets.SpotOptions.MinTargetCapacity | number | The minimum target capacity for Spot Instances in the fleet. | 
| AWS.EC2.Fleet.Fleets.OnDemandOptions.AllocationStrategy | string | The order of the launch template overrides to use in fulfilling On-Demand capacity. | 
| AWS.EC2.Fleet.Fleets.OnDemandOptions.SingleInstanceType | boolean | Indicates that the fleet uses a single instance type to launch all On-Demand Instances in the fleet. | 
| AWS.EC2.Fleet.Fleets.OnDemandOptions.SingleAvailabilityZone | boolean | Indicates that the fleet launches all On-Demand Instances into a single Availability Zone. | 
| AWS.EC2.Fleet.Fleets.OnDemandOptions.MinTargetCapacity | number | The minimum target capacity for On-Demand Instances in the fleet.  | 
| AWS.EC2.Fleet.Fleets.Tags.Key | string | The key of the tag. | 
| AWS.EC2.Fleet.Fleets.Tags.Value | string | The value of the tag. | 
| AWS.EC2.Fleet.Fleets.Errors.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId | string | The ID of the launch template. You must specify either a template ID or a template name. | 
| AWS.EC2.Fleet.Fleets.Errors.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName | string | The name of the launch template. You must specify either a template name or a template ID. | 
| AWS.EC2.Fleet.Fleets.Errors.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version | string | The version number of the launch template. You must specify a version number. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.InstanceType | string | The instance type. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.MaxPrice | string | The maximum price per unit hour that you are willing to pay for a Spot Instance. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.SubnetId | string | The ID of the subnet in which to launch the instances. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.AvailabilityZone | string | The Availability Zone in which to launch the instances. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.WeightedCapacity | number | The number of units provided by the specified instance type. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.Priority | number | The priority for the launch template override. | 
| AWS.EC2.Fleet.Fleets.Errors.Overrides.Placement.GroupName | string | The name of the placement group the instance is in. | 
| AWS.EC2.Fleet.Fleets.Errors.Lifecycle | string | Indicates if the instance that could not be launched was a Spot Instance or On-Demand Instance. | 
| AWS.EC2.Fleet.Fleets.Errors.ErrorCode | string | The error code that indicates why the instance could not be launched. | 
| AWS.EC2.Fleet.Fleets.Errors.ErrorMessage | string | The error message that describes why the instance could not be launched. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId | string | The ID of the launch template. You must specify either a template ID or a template name. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName | string | The name of the launch template. You must specify either a template name or a template ID. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version | string | The version number of the launch template. You must specify a version number. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.InstanceType | string | The instance type. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.MaxPrice | string | The maximum price per unit hour that you are willing to pay for a Spot Instance. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.SubnetId | string | The ID of the subnet in which to launch the instances. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.AvailabilityZone | string | The Availability Zone in which to launch the instances. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.WeightedCapacity | number | The number of units provided by the specified instance type. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.Priority | number | The priority for the launch template override. | 
| AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.Placement.GroupName | string | The name of the placement group the instance is in. | 
| AWS.EC2.Fleet.Fleets.Instances.Lifecycle | string | Indicates if the instance that was launched is a Spot Instance or On-Demand Instance. | 
| AWS.EC2.Fleet.Fleets.Instances.InstanceIds | string | The IDs of the instances. | 
| AWS.EC2.Fleet.Fleets.Instances.InstanceType | string | The instance type. | 
| AWS.EC2.Fleet.Fleets.Instances.Platform | string | The value is Windows for Windows instances; otherwise blank. | 
| AWS.EC2.Fleet.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-describe-fleet-instances

***
Describes the running instances for the specified EC2 Fleet.

#### Base Command

`aws-ec2-describe-fleet-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| FleetId | The ID of the EC2 Fleet. | Required | 
| MaxResults | The maximum number of results to return in a single call. Specify a value between 1 and 1000. | Optional | 
| NextToken | The token for the next set of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Fleet.ActiveInstances.InstanceId | String | The ID of the instance. | 
| AWS.EC2.Fleet.ActiveInstances.InstanceType | String | The instance type. | 
| AWS.EC2.Fleet.ActiveInstances.SpotInstanceRequestId | String | The ID of the Spot Instance request. | 
| AWS.EC2.Fleet.ActiveInstances.InstanceHealth | String | The health status of the instance. | 
| AWS.EC2.Fleet.NextToken | String | The token for the next set of results. | 
| AWS.EC2.Fleet.FleetId | String | The ID of the EC2 Fleet. | 
| AWS.EC2.Fleet.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-modify-fleet

***
Modifies the specified EC2 Fleet.

#### Base Command

`aws-ec2-modify-fleet`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| FleetId | The ID of the EC2 Fleet. | Required | 
| TotalTargetCapacity | The number of units to request, filled using DefaultTargetCapacityType. | Required | 
| OnDemandTargetCapacity | The number of On-Demand units to request. | Optional | 
| SpotTargetCapacity | The number of Spot units to request. | Optional | 
| DefaultTargetCapacityType | The default TotalTargetCapacity, which is either Spot or On-Demand. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-create-launch-template

***
Creates a launch template. A launch template contains the parameters to launch an instance.

#### Base Command

`aws-ec2-create-launch-template`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| ClientToken | Unique, case-sensitive identifier you provide to ensure the idempotency of the request. | Optional | 
| LaunchTemplateName | A name for the launch template. | Required | 
| VersionDescription | A description for the first version of the launch template. | Optional | 
| KernelId | The ID of the kernel. | Optional | 
| EbsOptimized | Indicates whether the instance is optimized for Amazon EBS I/O. Possible values are: True, False. | Optional | 
| iamInstanceProfileArn | The Amazon Resource Name (ARN) of the instance profile. | Optional | 
| iamInstanceProfileName | The name of the instance profile. | Optional | 
| deviceName | The device name (for example, /dev/sdh or xvdh). | Optional | 
| VirtualName | The virtual device name (ephemeralN). Instance store volumes are numbered starting from 0. | Optional | 
| ebsEncrypted | Indicates whether the EBS volume is encrypted. Possible values are: True, False. | Optional | 
| ebsDeleteOnTermination | Indicates whether the EBS volume is deleted on instance termination. Possible values are: True, False. | Optional | 
| ebsIops | The number of I/O operations per second (IOPS) that the volume supports. | Optional | 
| ebsKmsKeyId | The ARN of the AWS Key Management Service (AWS KMS) CMK used for encryption. | Optional | 
| ebsSnapshotId | The ID of the snapshot. | Optional | 
| ebsVolumeSize | The size of the volume, in GiB. | Optional | 
| ebsVolumeType | The volume type. | Optional | 
| NoDevice | Suppresses the specified device included in the block device mapping of the AMI. | Optional | 
| AssociatePublicIpAddress | Associates a public IPv4 address with eth0 for a new network interface. Possible values are: True, False. | Optional | 
| NetworkInterfacesDeleteOnTermination | Indicates whether the network interface is deleted when the instance is terminated. Possible values are: True, False. | Optional | 
| NetworkInterfacesDescription | A description for the network interface. | Optional | 
| NetworkInterfacesDeviceIndex | The device index for the network interface attachment. | Optional | 
| NetworkInterfaceGroups | The IDs of one or more security groups. | Optional | 
| Ipv6AddressCount | The number of IPv6 addresses to assign to a network interface. . | Optional | 
| Ipv6Addresses | One or more specific IPv6 addresses from the IPv6 CIDR block range of your subnet. | Optional | 
| NetworkInterfaceId | The ID of the network interface. | Optional | 
| PrivateIpAddress | The primary private IPv4 address of the network interface. | Optional | 
| SubnetId | The ID of the subnet for the network interface. | Optional | 
| ImageId | The ID of the AMI, which you can get by using DescribeImages. | Optional | 
| InstanceType | The instance type. | Optional | 
| KeyName | The name of the key pair. | Optional | 
| Monitoring | Specify true to enable detailed monitoring. Otherwise, basic monitoring is enabled. Possible values are: True, False. | Optional | 
| AvailabilityZone | The Availability Zone for the instance. | Optional | 
| PlacementAffinity | The affinity setting for an instance on a Dedicated Host. | Optional | 
| AvailabilityZoneGroupName | The name of the placement group for the instance. | Optional | 
| PlacementHostId | The ID of the Dedicated Host for the instance. | Optional | 
| PlacementTenancy | The tenancy of the instance (if the instance is running in a VPC). | Optional | 
| PlacementSpreadDomain | Reserved for future use. | Optional | 
| RamDiskId | The ID of the RAM disk. | Optional | 
| DisableApiTermination | If set to true , you can't terminate the instance using the Amazon EC2 console, CLI, or API. Possible values are: True, False. | Optional | 
| InstanceInitiatedShutdownBehavior | Indicates whether an instance stops or terminates when you initiate shutdown from the instance (using the operating system command for system shutdown). | Optional | 
| UserData | The Base64-encoded user data to make available to the instance. | Optional | 
| Tags | The tags to apply to the resource. | Optional | 
| ElasticGpuSpecificationsType | The type of Elastic Graphics accelerator. | Optional | 
| ElasticInferenceAcceleratorsType | The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge. | Optional | 
| securityGroupIds | One or more security group IDs. | Optional | 
| securityGroups | One or more security group names. | Optional | 
| MarketType | The market type. | Optional | 
| SpotInstanceType | The Spot Instance request type. | Optional | 
| BlockDurationMinutes | The required duration for the Spot Instances (also known as Spot blocks), in minutes. This value must be a multiple of 60 (60, 120, 180, 240, 300, or 360). | Optional | 
| SpotValidUntil | The end date of the request. | Optional | 
| SpotInstanceInterruptionBehavior | The behavior when a Spot Instance is interrupted. The default is terminate. | Optional | 
| SpotMaxPrice | The maximum hourly price you're willing to pay for the Spot Instances. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.LaunchTemplates.LaunchTemplateId | String | The ID of the launch template. | 
| AWS.EC2.LaunchTemplates.LaunchTemplateName | String | The name of the launch template. | 
| AWS.EC2.LaunchTemplates.CreateTime | Date | The time launch template was created. | 
| AWS.EC2.LaunchTemplates.CreatedBy | String | The principal that created the launch template. | 
| AWS.EC2.LaunchTemplates.DefaultVersionNumber | Number | The version number of the default version of the launch template. | 
| AWS.EC2.LaunchTemplates.LatestVersionNumber | Number | The version number of the latest version of the launch template. | 
| AWS.EC2.LaunchTemplates.Tags.Key | String | The key of the tag. | 
| AWS.EC2.LaunchTemplates.Tags.Value | String | The value of the tag. | 
| AWS.EC2.LaunchTemplates.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-delete-launch-template

***
Deletes a launch template. Deleting a launch template deletes all of its versions.

#### Base Command

`aws-ec2-delete-launch-template`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| LaunchTemplateId | The ID of the launch template. | Optional | 
| LaunchTemplateName | The name of the launch template. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.DeletedLaunchTemplates.LaunchTemplateId | String | The ID of the launch template. | 
| AWS.EC2.DeletedLaunchTemplates.LaunchTemplateName | String | The name of the launch template. | 
| AWS.EC2.DeletedLaunchTemplates.CreateTime | Date | The time launch template was created. | 
| AWS.EC2.DeletedLaunchTemplates.CreatedBy | String | The principal that created the launch template. | 
| AWS.EC2.DeletedLaunchTemplates.DefaultVersionNumber | Number | The version number of the default version of the launch template. | 
| AWS.EC2.DeletedLaunchTemplates.LatestVersionNumber | Number | The version number of the latest version of the launch template. | 
| AWS.EC2.DeletedLaunchTemplates.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-modify-image-attribute

***
Modifies the specified attribute of the specified AMI.

#### Base Command

`aws-ec2-modify-image-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| Attribute | The name of the attribute to modify. The valid values are description, launchPermission, and productCodes. | Optional | 
| Description | A new description for the AMI. | Optional | 
| ImageId | The ID of the AMI. | Required | 
| LaunchPermission-Add-Group | The name of the group. | Optional | 
| LaunchPermission-Add-UserId | The AWS account ID. | Optional | 
| LaunchPermission-Remove-Group | The name of the group. | Optional | 
| LaunchPermission-Remove-UserId | The AWS account ID. | Optional | 
| OperationType | The operation type. | Optional | 
| ProductCodes | One or more DevPay product codes. After you add a product code to an AMI, it can't be removed. | Optional | 
| UserGroups | One or more user groups. This parameter can be used only when the Attribute parameter is launchPermission. | Optional | 
| UserIds | One or more AWS account IDs. This parameter can be used only when the Attribute parameter is launchPermission. | Optional | 
| Value | The value of the attribute being modified. This parameter can be used only when the Attribute parameter is description or productCodes. | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-delete-subnet

***
Deletes the specified subnet. You must terminate all running instances in the subnet before you can delete the subnet.

#### Base Command

`aws-ec2-delete-subnet`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| SubnetId | The ID of the subnet. | Required | 

#### Context Output

There is no context output for this command.
### aws-ec2-delete-vpc

***
Deletes the specified VPC. You must detach or delete all gateways and resources that are associated with the VPC before you can delete it. For example, you must terminate all instances running in the VPC, delete all security groups associated with the VPC (except the default one), delete all route tables associated with the VPC (except the default one), and so on.

#### Base Command

`aws-ec2-delete-vpc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| VpcId | The ID of the VPC. | Required | 

#### Context Output

There is no context output for this command.
### aws-ec2-delete-internet-gateway

***
Deletes the specified internet gateway. You must detach the internet gateway from the VPC before you can delete it.

#### Base Command

`aws-ec2-delete-internet-gateway`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| InternetGatewayId | The ID of the internet gateway. | Required | 

#### Context Output

There is no context output for this command.
### aws-ec2-describe-internet-gateway

***
Describes one or more of your internet gateways.

#### Base Command

`aws-ec2-describe-internet-gateway`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| filters | One or more filters separated by ';'. See the [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Filter.html) for details &amp; filter options. | Optional | 
| InternetGatewayIds | One or more internet gateway IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.InternetGateways.InternetGatewayId | string | The ID of the internet gateway. | 
| AWS.EC2.InternetGateways.OwnerId | string | The ID of the AWS account that owns the internet gateway. | 
| AWS.EC2.InternetGateways.Tags | string | Any tags assigned to the internet gateway. | 
| AWS.EC2.InternetGateways.Attachments.State | string | The current state of the attachment. | 
| AWS.EC2.InternetGateways.Attachments.VpcId | string | The ID of the VPC. | 
| AWS.EC2.InternetGateways.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-detach-internet-gateway

***
Detaches an internet gateway from a VPC, disabling connectivity between the internet and the VPC. The VPC must not contain any running instances with Elastic IP addresses or public IPv4 addresses.

#### Base Command

`aws-ec2-detach-internet-gateway`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| InternetGatewayId | The ID of the internet gateway. | Required | 
| VpcId | The ID of the VPC. | Required | 

#### Context Output

There is no context output for this command.
### aws-ec2-create-traffic-mirror-session

***
Creates a Traffic Mirror session.

#### Base Command

`aws-ec2-create-traffic-mirror-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| NetworkInterfaceId | The ID of the source network interface. | Required | 
| TrafficMirrorTargetId | The ID of the Traffic Mirror target. | Required | 
| TrafficMirrorFilterId | The ID of the Traffic Mirror filter. | Required | 
| PacketLength | The number of bytes in each packet to mirror. | Optional | 
| SessionNumber | The session number determines the order in which sessions are evaluated when an interface is used by multiple sessions. | Required | 
| VirtualNetworkId | The VXLAN ID for the Traffic Mirror session. | Optional | 
| Description | The description of the Traffic Mirror session. | Optional | 
| Tags | The tags to assign to a Traffic Mirror session. | Optional | 
| DryRun | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. | Optional | 
| ClientToken | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.TrafficMirrorSession.TrafficMirrorSessionId | String | The ID for the Traffic Mirror session. | 
| AWS.EC2.TrafficMirrorSession.TrafficMirrorTargetId | String | The ID of the Traffic Mirror target. | 
| AWS.EC2.TrafficMirrorSession.TrafficMirrorFilterId | String | The ID of the Traffic Mirror filter. | 
| AWS.EC2.TrafficMirrorSession.NetworkInterfaceId | String | The ID of the Traffic Mirror session's network interface. | 
| AWS.EC2.TrafficMirrorSession.OwnerId | String | The ID of the account that owns the Traffic Mirror session. | 
| AWS.EC2.TrafficMirrorSession.PacketLength | Number | The number of bytes in each packet to mirror. | 
| AWS.EC2.TrafficMirrorSession.SessionNumber | Number | The session number determines the order in which sessions are evaluated when an interface is used by multiple sessions. | 
| AWS.EC2.TrafficMirrorSession.VirtualNetworkId | Number | The virtual network ID associated with the Traffic Mirror session. | 
| AWS.EC2.TrafficMirrorSession.Description | String | The description of the Traffic Mirror session. | 
| AWS.EC2.TrafficMirrorSession.Tags.Key | String | The key of the tag. | 
| AWS.EC2.TrafficMirrorSession.Tags.Value | String | The value of the tag. | 
| AWS.EC2.TrafficMirrorSession.ClientToken | String | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | 
| AWS.EC2.TrafficMirrorSession.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

### aws-ec2-revoke-security-group-egress-rule

***
Removes egress rule from a security group. To remove a rule, the values that you specify (for example, ports) must match the existing rule's values exactly.

#### Base Command

`aws-ec2-revoke-security-group-egress-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | The ID of the security group. | Required | 
| IpPermissionsfromPort | The start of the port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpPermissionsToPort | The end of the port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes. | Optional | 
| IpPermissionsIpProtocol | The IP protocol name (tcp, udp, icmp, icmpv6) or number. | Optional | 
| IpRangesCidrIp | The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv4 address, use the /32 prefix length. | Optional | 
| IpRangesDescription | A description for the security group rule that references this IPv4 address range. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| Ipv6RangesCidrIp | The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length. | Optional | 
| Ipv6RangesDescription | A description for the security group rule that references this IPv6 address range. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&amp;;{}!$*. | Optional | 
| PrefixListId | The ID of the prefix. | Optional | 
| PrefixListIdDescription | A description for the security group rule that references this prefix list ID. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| UserIdGroupPairsDescription | A description for the security group rule that references this user ID group pair. Constraints: Up to 255 characters in length. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}$*!. | Optional | 
| UserIdGroupPairsGroupId | The ID of the security group. | Optional | 
| UserIdGroupPairsGroupName | The name of the security group. In a request, use this parameter for a security group in EC2-Classic or a default VPC only. For a security group in a nondefault VPC, use the security group ID. For a referenced security group in another VPC, this value is not returned if the referenced security group is deleted. | Optional | 
| UserIdGroupPairsPeeringStatus | The status of a VPC peering connection, if applicable. | Optional | 
| UserIdGroupPairsUserId | The ID of an AWS account. For a referenced security group in another VPC, the account ID of the referenced security group is returned in the response. If the referenced security group is deleted, this value is not returned. [EC2-Classic] Required when adding or removing rules that reference a security group in another AWS account. | Optional | 
| UserIdGroupPairsVpcId | The ID of the VPC for the referenced security group, if applicable. | Optional | 
| UserIdGroupPairsVpcPeeringConnectionId | The ID of the VPC peering connection, if applicable. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| IpPermissionsFull | Full IpPermissions argument as a string to more easily target rules (for example, """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""). | Optional | 

#### Context Output

There is no context output for this command.
### aws-ec2-allocate-hosts

***
Allocates a Dedicated Host to your account.

#### Base Command

`aws-ec2-allocate-hosts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| availability_zone | The Availability Zone in which to allocate the Dedicated Host. | Required | 
| quantity | The number of Dedicated Hosts to allocate to your account with these parameters. | Required | 
| auto_placement | Indicates whether the host accepts any untargeted instance launches that match its instance type configuration, or if it only accepts Host tenancy instance launches that specify its unique host ID. The default is "on". Possible values are: on, off. | Optional | 
| client_token | Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | Optional | 
| instance_type | Specifies the instance type to be supported by the Dedicated Hosts. If you specify an instance type, the Dedicated Hosts support instances of the specified instance type only. If you want the Dedicated Hosts to support multiple instance types in a specific instance family, omit this parameter and specify InstanceFamily instead. You cannot specify InstanceType and InstanceFamily in the same request. | Optional | 
| instance_family | Specifies the instance family to be supported by the Dedicated Hosts. If you specify an instance family, the Dedicated Hosts support multiple instance types within that instance family. If you want the Dedicated Hosts to support a specific instance type only, omit this parameter and specify InstanceType instead. You cannot specify InstanceFamily and InstanceType in the same request. | Optional | 
| host_recovery | Indicates whether to enable or disable host recovery for the Dedicated Host. Host recovery is disabled by default. Possible values are: on, off. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Host.HostId | String | The ID of the allocated Dedicated Host. This is used to launch an instance onto a specific host. | 
| AWS.EC2.Host.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 



#### Command Example
```!aws-ec2-allocate-hosts availability_zone="us-east-1b" quantity=1 instance_type="m5.large" ```

#### Human Readable Output
>### AWS EC2 Dedicated Host ID
>|HostId|
>|---|
>| h-00548908djdsgfs|


### aws-ec2-release-hosts

***
Release on demand dedicated host.

#### Base Command

`aws-ec2-release-hosts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | A comma-separated list of IDs of the Dedicated Hosts to release. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example
```!aws-ec2-release-hosts host_id="h-00548908djdsgfs" ```

#### Human Readable Output
>The host was successfully released.

### aws-ec2-modify-snapshot-permission

***
Adds or removes permission settings for the specified snapshot.

#### Base Command

`aws-ec2-modify-snapshot-permission`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshotId | The ID of the EBS snapshot. | Required | 
| operationType | The operation type, add or remove. Possible values are: add, remove. | Required | 
| groupNames | CSV of security group names. This parameter can be used only when UserIds not provided. | Optional | 
| userIds | CSV of AWS account IDs. This parameter can be used only when groupNames not provided. | Optional | 
| dryRun | Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. Possible values are: True, False. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!aws-ec2-modify-snapshot-permission operationType=remove snapshotId=snap-04b2d21f20d2388f2 userIds=123456789012```
#### Human Readable Output

>Snapshot snap-04b2d21f20d2388f2 permissions was successfully updated.

### aws-ec2-describe-ipam-resource-discoveries

***
Describes IPAM resource discoveries. A resource discovery is an IPAM component that enables IPAM to manage and monitor resources that belong to the owning account.

#### Base Command

`aws-ec2-describe-ipam-resource-discoveries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IpamResourceDiscoveryIds | A comma-separated list of the IPAM resource discovery IDs. | Optional | 
| Filters | One or more filters separated by ';'. See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional | 
| MaxResults | The maximum number of results to return in a single call. Specify a value between 5 and 1000. | Optional | 
| NextToken | The token for the next set of results. | Optional | 
| AddressRegion | The Amazon Web Services region for the IP address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IpamResourceDiscoveries.IpamResourceDiscoveryId | String | The resource discovery ID. | 
| AWS.EC2.IpamResourceDiscoveries.OwnerId | String | The ID of the owner. | 
| AWS.EC2.IpamResourceDiscoveries.IpamResourceDiscoveryRegion | String | The resource discovery region. | 
| AWS.EC2.IpamResourceDiscoveries.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command example
```!aws-ec2-describe-ipam-resource-discoveries```
#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "IpamResourceDiscoveries": {
                "IpamResourceDiscoveryArn": "arn:aws:ec2::222222222222:ipam-resource-discovery/ipam-res-disco-11111111111111111",
                "IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
                "IpamResourceDiscoveryRegion": "us-east-1",
                "IsDefault": true,
                "OperatingRegions": [
                    {
                        "RegionName": "ap-south-1"
                    },
                    {
                        "RegionName": "eu-north-1"
                    },
                    {
                        "RegionName": "eu-west-3"
                    },
                    {
                        "RegionName": "eu-west-2"
                    },
                    {
                        "RegionName": "eu-west-1"
                    },
                    {
                        "RegionName": "ap-northeast-3"
                    },
                    {
                        "RegionName": "ap-northeast-2"
                    },
                    {
                        "RegionName": "ap-northeast-1"
                    },
                    {
                        "RegionName": "ca-central-1"
                    },
                    {
                        "RegionName": "sa-east-1"
                    },
                    {
                        "RegionName": "ap-southeast-1"
                    },
                    {
                        "RegionName": "ap-southeast-2"
                    },
                    {
                        "RegionName": "eu-central-1"
                    },
                    {
                        "RegionName": "us-east-1"
                    },
                    {
                        "RegionName": "us-east-2"
                    },
                    {
                        "RegionName": "us-west-1"
                    },
                    {
                        "RegionName": "us-west-2"
                    }
                ],
                "OwnerId": "222222222222",
                "State": "create-complete",
                "Tags": []
            }
        }
    }
}
```

#### Human Readable Output

>### Ipam Resource Discoveries
>|IpamResourceDiscoveryArn|IpamResourceDiscoveryId|IpamResourceDiscoveryRegion|IsDefault|OperatingRegions|OwnerId|State|Tags|
>|---|---|---|---|---|---|---|---|
>| arn:aws:ec2::222222222222:ipam-resource-discovery/ipam-res-disco-11111111111111111 | ipam-res-disco-11111111111111111 | us-east-1 | true | {'RegionName': 'ap-south-1'},<br/>{'RegionName': 'eu-north-1'},<br/>{'RegionName': 'eu-west-3'},<br/>{'RegionName': 'eu-west-2'},<br/>{'RegionName': 'eu-west-1'},<br/>{'RegionName': 'ap-northeast-3'},<br/>{'RegionName': 'ap-northeast-2'},<br/>{'RegionName': 'ap-northeast-1'},<br/>{'RegionName': 'ca-central-1'},<br/>{'RegionName': 'sa-east-1'},<br/>{'RegionName': 'ap-southeast-1'},<br/>{'RegionName': 'ap-southeast-2'},<br/>{'RegionName': 'eu-central-1'},<br/>{'RegionName': 'us-east-1'},<br/>{'RegionName': 'us-east-2'},<br/>{'RegionName': 'us-west-1'},<br/>{'RegionName': 'us-west-2'} | 222222222222 | create-complete |  |


### aws-ec2-describe-ipam-resource-discovery-associations

***
Describes resource discovery association with an Amazon VPC IPAM. An associated resource discovery is a resource discovery that has been associated with an IPAM.

#### Base Command

`aws-ec2-describe-ipam-resource-discovery-associations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IpamResourceDiscoveryAssociationIds | A comma-separated list of the resource discovery association IDs. | Optional | 
| Filters | One or more filters separated by ';'. See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional | 
| MaxResults | The maximum number of results to return in a single call. Specify a value between 5 and 1000. | Optional | 
| NextToken | The token for the next set of results. | Optional | 
| AddressRegion | The Amazon Web Services region for the IP address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IpamResourceDiscoveryAssociations.IpamResourceDiscoveryAssociationId | String | The resource discovery association ID. | 
| AWS.EC2.IpamResourceDiscoveryAssociations.IpamResourceDiscoveryId | String | The resource discovery ID. | 
| AWS.EC2.IpamResourceDiscoveryAssociations.IpamRegion | String | The IPAM home region. | 
| AWS.EC2.IpamResourceDiscoveryAssociations.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command example
```!aws-ec2-describe-ipam-resource-discovery-associations```
#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "IpamResourceDiscoveryAssociations": {
                "IpamArn": "arn:aws:ec2::222222222222:ipam/ipam-11111111111111111",
                "IpamId": "ipam-11111111111111111",
                "IpamRegion": "us-east-1",
                "IpamResourceDiscoveryAssociationArn": "arn:aws:ec2::222222222222:ipam-resource-discovery-association/ipam-res-disco-assoc-11111111111111111",
                "IpamResourceDiscoveryAssociationId": "ipam-res-disco-assoc-11111111111111111",
                "IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
                "IsDefault": true,
                "OwnerId": "222222222222",
                "ResourceDiscoveryStatus": "active",
                "State": "associate-complete",
                "Tags": []
            }
        }
    }
}
```

#### Human Readable Output

>### Ipam Resource Discovery Associations
>|IpamArn|IpamId|IpamRegion|IpamResourceDiscoveryAssociationArn|IpamResourceDiscoveryAssociationId|IpamResourceDiscoveryId|IsDefault|OwnerId|ResourceDiscoveryStatus|State|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|
>| arn:aws:ec2::222222222222:ipam/ipam-11111111111111111 | ipam-11111111111111111 | us-east-1 | arn:aws:ec2::222222222222:ipam-resource-discovery-association/ipam-res-disco-assoc-11111111111111111 | ipam-res-disco-assoc-11111111111111111 | ipam-res-disco-11111111111111111 | true | 222222222222 | active | associate-complete |  |


### aws-ec2-get-ipam-discovered-public-addresses

***
Gets the public IP addresses that have been discovered by IPAM.

#### Base Command

`aws-ec2-get-ipam-discovered-public-addresses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IpamResourceDiscoveryId | An IPAM resource discovery ID. | Required | 
| AddressRegion | The Amazon Web Services Region for the IP address. | Required | 
| Filters | One or more filters separated by ';'. See AWS documentation for details &amp; filter options (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html). | Optional | 
| MaxResults | The maximum number of results to return in a single call. Specify a value between 5 and 1000. | Optional | 
| NextToken | The token for the next set of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.IpamDiscoveredPublicAddresses.Address | String | IPAM discovered public addresses. | 
| AWS.EC2.IpamDiscoveredPublicAddresses.AddressOwnerId | String | The ID of the owner of the resource the IP address is assigned to. | 
| AWS.EC2.IpamDiscoveredPublicAddresses.AddressType | String | The IP address type. | 
| AWS.EC2.IpamDiscoveredPublicAddresses.AssociationStatus | String | The association status. | 
| AWS.EC2.IpamDiscoveredPublicAddresses.InstanceId | String | The instance ID of the instance the assigned IP address is assigned to. | 
| AWS.EC2.IpamDiscoveredPublicAddresses.Tags | Unknown | Tags associated with the IP address. | 
| AWS.EC2.IpamDiscoveredPublicAddresses.AccountId | string | The ID of the AWS account with which the EC2 instance is associated. This key is only present when the parameter "AWS organization accounts" is provided. | 

#### Command example
```!aws-ec2-get-ipam-discovered-public-addresses IpamResourceDiscoveryId=ipam-res-disco-11111111111111111 AddressRegion=us-east-1 Filters=Name=address,Values=1.1.1.1```
#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "IpamDiscoveredPublicAddresses": {
                "Address": "1.1.1.1",
                "AddressAllocationId": "eipalloc-11111111111111111",
                "AddressOwnerId": "222222222222",
                "AddressRegion": "us-east-1",
                "AddressType": "amazon-owned-eip",
                "AssociationStatus": "associated",
                "InstanceId": "i-11111111111111111",
                "IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
                "NetworkBorderGroup": "us-east-1",
                "NetworkInterfaceDescription": "",
                "NetworkInterfaceId": "eni-11111111111111111",
                "PublicIpv4PoolId": "amazon",
                "SampleTime": "2023-11-26T02:00:45",
                "SecurityGroups": [
                    {
                        "GroupId": "sg-11111111111111111",
                        "GroupName": "example_sg"
                    }
                ],
                "SubnetId": "subnet-11111111111111111",
                "Tags": {
                    "EipTags": []
                },
                "VpcId": "vpc-11111111111111111"
            }
        }
    }
}
```

#### Human Readable Output

>### Ipam Discovered Public Addresses
>|Address|AddressAllocationId|AddressOwnerId|AddressRegion|AddressType|AssociationStatus|InstanceId|IpamResourceDiscoveryId|NetworkBorderGroup|NetworkInterfaceDescription|NetworkInterfaceId|PublicIpv4PoolId|SampleTime|SecurityGroups|SubnetId|Tags|VpcId|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1.1.1.1 | eipalloc-11111111111111111 | 222222222222 | us-east-1 | amazon-owned-eip | associated | i-11111111111111111 | ipam-res-disco-11111111111111111 | us-east-1 |  | eni-11111111111111111 | amazon | 2023-11-26T02:00:45 | {'GroupName': 'example_sg', 'GroupId': 'sg-11111111111111111'} | subnet-11111111111111111 | EipTags:  | vpc-11111111111111111 |

### aws-ec2-create-vpc-endpoint

***
Creates a VPC endpoint.

#### Base Command

`aws-ec2-create-vpc-endpoint`

#### Input

| **Argument Name**   | **Description** | **Required** |
|---------------------| --- | --- |
| vpcId               | The ID of the VPC in which the endpoint will be used. | Required | 
| serviceName         | The service name for the service that you want to create an endpoint. | Required | 
| endpointType        | The type of endpoint. | Optional | 
| subnetIds           | One or more subnet IDs in which to create the endpoint. | Optional | 
| securityGroupIds    | One or more security group IDs to associate with the endpoint. | Optional | 
| dryRun              | Checks whether you have the required permissions for the action, without actually making the request. Possible values are: true, false. | Optional | 
| vpcEndpointType     | The type of endpoint. Possible values are: Interface, Gateway, GatewayLoadBalancer. | Optional | 
| policyDocument      | A policy document to attach to the endpoint. A JSON policy document that controls access to the service from the endpoint. | Optional | 
| routeTableIds       | One or more route table IDs. | Optional | 
| clientToken         | Unique, case-sensitive identifier to ensure the idempotency of the request. | Optional | 
| privateDnsEnabled   | Indicates whether to associate a private hosted zone with the specified VPC. Possible values are: true, false. | Optional | 
| tagSpecifications   | One or more tags to associate with the endpoint. Should be Json string of key-value tags. | Optional |
| region              | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn             | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName     | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EC2.Vpcs.VpcEndpoint.VpcEndpointId | String | The ID of the endpoint. | 
| AWS.EC2.Vpcs.VpcEndpoint.State | String | The state of the VPC endpoint. | 
| AWS.EC2.Vpcs.VpcEndpoint.ServiceName | String | The service name of the VPC endpoint. | 
| AWS.EC2.Vpcs.VpcEndpoint.VpcId | String | The ID of the VPC to which the endpoint is associated. | 
| AWS.EC2.Vpcs.VpcEndpoint.EndpointType | String | The type of the VPC endpoint. | 

#### Command example
```!aws-ec2-create-vpc-endpoint service-name=test_service_name vpc-id=test_id```
#### Context Example
```json
{
    "AWS": {
        "EC2": {
            "Vpcs": {
                "VpcEndpoint":
                {
                    "ServiceName": "test_service_name",
                    "State": "PendingAcceptance",
                    "VpcEndpointId": "test_endpoint_id",
                    "VpcEndpointType": "Interface",
                    "VpcId": "test_id"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### VPC Endpoint
>|Service Name|State|Vpc Endpoint Id|Vpc Endpoint Type|Vpc Id|
>|---|---|---|---|---|
>| test_service_name | PendingAcceptance | test_endpoint_id | Interface | test_id |