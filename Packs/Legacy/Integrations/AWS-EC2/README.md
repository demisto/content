<!-- HTML_DOC -->
<h2 class="code-line" data-line-start="1" data-line-end="2">Configure AWS - EC2 on Demisto</h2>
<ol>
<li class="has-line-data" data-line-start="2" data-line-end="3">Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li class="has-line-data" data-line-start="3" data-line-end="4">Search for AWS - EC2.</li>
<li class="has-line-data" data-line-start="4" data-line-end="14">Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li class="has-line-data" data-line-start="5" data-line-end="6">
<strong>Name</strong>: a textual name for the integration instance.</li>
<li class="has-line-data" data-line-start="6" data-line-end="7"><strong>AWS Default Region</strong></li>
<li class="has-line-data" data-line-start="7" data-line-end="8"><strong>Role Arn</strong></li>
<li class="has-line-data" data-line-start="8" data-line-end="9"><strong>Role Session Name</strong></li>
<li class="has-line-data" data-line-start="9" data-line-end="10"><strong>Role Session Duration</strong></li>
<li class="has-line-data" data-line-start="10" data-line-end="11"><strong>Access Key</strong></li>
<li class="has-line-data" data-line-start="11" data-line-end="12"><strong>Secret Key</strong></li>
<li class="has-line-data" data-line-start="12" data-line-end="13"><strong>Use System Proxy</strong></li>
<li class="has-line-data" data-line-start="13" data-line-end="14"><strong>Trust any certificate (Not Secure)</strong></li>
</ul>
</li>
<li class="has-line-data" data-line-start="14" data-line-end="16">Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2 class="code-line" data-line-start="16" data-line-end="17">
<a id="Commands_16"></a>Commands</h2>
<p class="has-line-data" data-line-start="18" data-line-end="19">You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details. All command, argument, and output descriptions are taken from the AWS documentation.</p>
<ol>
<li><a href="#h_6b6a7eb9-9df5-4cbc-8527-25c66a4357d6" target="_self">Describe instances: aws-ec2-describe-instances</a></li>
<li><a href="#h_fa7ccddb-ec49-447e-b251-cd80ffdc702e" target="_self">Describe images: aws-ec2-describe-images</a></li>
<li><a href="#h_9d98a913-bcae-4833-bf6d-f276660d26f5" target="_self">Describe regions: aws-ec2-describe-regions</a></li>
<li><a href="#h_f5c6af47-13b8-4b9f-b0c3-edf076c90363" target="_self">Describe Elastic IP addresses: aws-ec2-describe-addresses</a></li>
<li><a href="#h_e4867b65-cc77-40f7-a4fa-5d4072ebc09d" target="_self">Describe available EBS snapshots: aws-ec2-describe-snapshots</a></li>
<li><a href="#h_33bb4eaf-a6ce-4c13-acb6-b50602f8f8f0" target="_self">Describe launch templates: aws-ec2-describe-launch-templates</a></li>
<li><a href="#h_a68db098-b6ff-483c-9aca-494c6c4403aa" target="_self">Describe key pairs: aws-ec2-describe-key-pairs</a></li>
<li><a href="#h_998cbf80-884e-4608-b64f-2c4def6627e6" target="_self">Describe EBS volumes: aws-ec2-describe-volumes</a></li>
<li><a href="#h_f88d00d2-7ee0-496b-9a03-00d252f06524" target="_self">Describe VPCs: aws-ec2-describe-vpcs</a></li>
<li><a href="#h_2cb8c926-8914-4b3b-8451-68bbc2a8aace" target="_self">Describes subnets: aws-ec2-describe-subnets</a></li>
<li><a href="#h_73f7f025-dbff-45fe-a046-2c2318ba939c" target="_self">Describe security groups: aws-ec2-describe-security-groups</a></li>
<li><a href="#h_8028d0b3-d5d6-4c41-bb33-cf33f484c8ef" target="_self">Allocate an Elastic IP address: aws-ec2-allocate-address</a></li>
<li><a href="#h_a8cfe195-40fc-46bf-a4f0-8da5da79771f" target="_self">Associate an Elastic IP address with an instance or network: aws-ec2-associate-address</a></li>
<li><a href="#h_19a16a93-3351-41d0-8cc3-420d5f094326" target="_self">Create a snapshot of an EBS volume: aws-ec2-create-snapshot</a></li>
<li><a href="#h_89ad79d4-48f5-483a-80ea-4457e48ff243" target="_self">Delete a snapshot: aws-ec2-delete-snapshot</a></li>
<li><a href="#h_b2688ea5-3b62-4cb3-86e1-a575209e76ad" target="_self">Create an Amazon EBS-backed AMI: aws-ec2-create-image</a></li>
<li><a href="#h_a94fc08c-5367-45cb-a0af-b0b2ae3902d1" target="_self">De-register an AMI: aws-ec2-deregister-image</a></li>
<li><a href="#h_a9290e85-9f9d-44fb-9b80-8a00624e4edb" target="_self">Modify a volume: aws-ec2-modify-volume</a></li>
<li><a href="#h_e7204c1c-3b45-4853-9955-beab510e79b1" target="_self">Add/Overwrite Amazon EC2 tags:aws-ec2-create-tags</a></li>
<li><a href="#h_2115882b-52bc-4788-9e1b-3a0f998f3bc3" target="_self">Disassociate an address: aws-ec2-disassociate-address</a></li>
<li><a href="#h_be722caf-bd4f-46f9-b441-0c74b48d156b" target="_self">Release an address: aws-ec2-release-address</a></li>
<li><a href="#h_3f201ac0-ada8-42d8-aee2-9d4a83471b0c" target="_self">Start an instance: aws-ec2-start-instances</a></li>
<li><a href="#h_b2d4252b-bad0-4189-9da8-7e938569da84" target="_self">Stop an instance: aws-ec2-stop-instances</a></li>
<li><a href="#h_ec872597-4749-4005-9079-968bda885d5d" target="_self">Terminate an instance: aws-ec2-terminate-instances</a></li>
<li><a href="#h_5d95c555-36d3-4a57-a501-0fec05b9b6f6" target="_self">Create an EBS volume: aws-ec2-create-volume</a></li>
<li><a href="#h_09ab8c37-4b74-4671-8707-7a5f3c0d458d" target="_self">Attach an EBS volume to an instance: aws-ec2-attach-volume</a></li>
<li><a href="#h_770c1b00-00b3-4f07-af43-2e1fc5424d9a" target="_self">Detach an EBS volume from an instance: aws-ec2-detach-volume</a></li>
<li><a href="#h_1c405d38-16a4-4f65-b93c-6e5caedfa894" target="_self">Delete an EBS volume: aws-ec2-delete-volume</a></li>
<li><a href="#h_3d06d1bd-308e-40f5-a500-177b04504740" target="_self">Launch instances using an AMI: aws-ec2-run-instances</a></li>
<li><a href="#h_9ac683ac-0db1-40b7-bc97-95ff3d4a57ce" target="_self">Waiter function - running: aws-ec2-waiter-instance-running</a></li>
<li><a href="#h_580aa99b-139d-404e-8c17-d19912e68637" target="_self">Waiter function - successful status: aws-ec2-waiter-instance-status-ok</a></li>
<li><a href="#h_dab6d1ab-0f93-4960-a25b-28b30d41e600" target="_self">Waiter function - stopped: aws-ec2-waiter-instance-stopped</a></li>
<li><a href="#h_093bb9c6-d48b-4477-821e-384b5c965ed9" target="_self">Waiter function - terminated: aws-ec2-waiter-instance-terminated</a></li>
<li><a href="#h_7b51d2f4-3f36-43f5-90f2-254739df1f52" target="_self">Waiter function - image: aws-ec20-waiter-image-available</a></li>
<li><a href="#h_d8dc108f-dda7-4c9f-a85e-d790d5bc1be3" target="_self">Waiter function - snapshot complete: aws-ec2-waiter-snapshot_completed</a></li>
<li><a href="#h_ec4c0cfd-8442-44e4-9976-5acefee5e66c" target="_self">Get the latest AMI: aws-ec2-get-latest-ami</a></li>
<li><a href="#h_47a604c2-2837-40ef-9e2f-b55c99b96e78" target="_self">Create a security group: aws-ec2-create-security-group</a></li>
<li><a href="#h_c69cba7b-87c3-4055-8bcd-db7f70256aab" target="_self">Delete a security group: aws-ec2-delete-security-group</a></li>
<li><a href="#h_0a05b1ae-c8b7-48eb-a15b-bd13c2ab4a98" target="_self">Add an ingress rule to a security group: aws-ec2-authorize-security-group-ingress-rule</a></li>
<li><a href="#h_45db8f57-c6a2-454c-ba78-57c9325a3298" target="_self">Remove an ingress rule to a security group: aws-ec2-revoke-security-group-ingress-rule</a></li>
<li><a href="#h_22e2dea1-aa5d-46f5-9a85-a49ccc01960a" target="_self">Copy an AMI into the current region: aws-ec2-copy-image</a></li>
<li><a href="#h_1e808591-6bb0-42c8-916b-93222287e431" target="_self">Save a snapshot to Amazon S3: aws-ec2-copy-snapshot</a></li>
<li><a href="#h_2c71e87b-e10f-4394-865c-687aeeadf48e" target="_self">Get the details of reserved instances: aws-ec2-describe-reserved-instances</a></li>
<li><a href="#h_3531fdba-0b40-420d-b77c-957db90d16be" target="_self">Monitor instances: aws-ec2-monitor-instances</a></li>
<li><a href="#h_289130de-2a2e-403a-a108-93b9d7a4d17c" target="_self">Disable instance monitoring: aws-ec2-unmonitor-instances</a></li>
<li><a href="#h_f6767e06-06e2-42d9-ac65-a985f86b0c65" target="_self">Reboot multiple instances: aws-ec2-reboot-instances</a></li>
<li><a href="#h_0b4efed1-6f64-4e62-bcdb-f00d18ac7309" target="_self">Get the administrator password: aws-ec2-get-password-data</a></li>
<li><a href="#h_9818b9bd-6fdf-49b4-a47e-cbab40082d0f" target="_self">Modify a network interface attribute: aws-ec2-modify-network-interface-attribute</a></li>
<li><a href="#h_537a6056-f26a-4d8c-bb6a-8e20a0a2f655" target="_self">Modify an attribute for an instance: aws-ec2-modify-instance-attribute</a></li>
<li><a href="#h_ad4f24a8-856b-4086-911c-cbef0fb5342b" target="_self">Create a network ACL in a VPC: aws-ec2-create-network-acl</a></li>
<li><a href="#h_73e1bc5c-5bff-41e5-90c2-cc676f64d814" target="_self">Create an entry in a network ACL: aws-ec2-create-network-acl-entry</a></li>
<li><a href="#h_9e7a1fb6-9f56-4a16-afba-c90a752c5c52" target="_self">Launch an EC2 fleet: aws-ec2-create-fleet</a></li>
<li><a href="#h_371493a2-3f6d-4754-98b5-f71136c1bdb6" target="_self">Delete an EC2 fleet: aws-ec2-delete-fleet</a></li>
<li><a href="#h_fee42e8b-17c9-4464-aefc-661b692c49f8" target="_self">Describe multiple EC2 fleets: aws-ec2-describe-fleets</a></li>
<li><a href="#h_1e2a78da-d345-4e4c-bcb1-19a97d1e51f8" target="_self">Describe running instances for an EC2 fleet: aws-ec2-describe-fleet-instances</a></li>
<li><a href="#h_2f581707-2545-4125-a31e-77dbeebe0989" target="_self">Modify an EC2 fleet: aws-ec2-modify-fleet</a></li>
<li><a href="#h_3a2af540-2be0-4432-b6ce-2b915b8afca3" target="_self">Create a launch template: aws-ec2-create-launch-template</a></li>
<li><a href="#h_1209deee-be0f-49f4-a123-1fb5cf9df2b2" target="_self">Delete a launch template: aws-ec2-delete-launch-template</a></li>
<li><a href="#h_392b6709-0b5c-4ef2-b35d-dcd8a7b86ccb" target="_self">Modify an attribute of an AMI: aws-ec2-modify-image-attribute</a></li>
</ol>
<h3 id="h_6b6a7eb9-9df5-4cbc-8527-25c66a4357d6" class="code-line" data-line-start="78" data-line-end="79">
<a id="1_awsec2describeinstances_78"></a>1. aws-ec2-describe-instances</h3>
<hr>
<p class="has-line-data" data-line-start="80" data-line-end="81">Describes one or more of your instances.</p>
<h5 class="code-line" data-line-start="81" data-line-end="82">
<a id="Base_Command_81"></a>Base Command</h5>
<p class="has-line-data" data-line-start="83" data-line-end="84"><code>aws-ec2-describe-instances</code></p>
<h5 class="code-line" data-line-start="84" data-line-end="85">
<a id="Input_84"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 762px;">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 541px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">filters</td>
<td style="width: 541px;">One or more filters.See documentation for details &amp; filter options.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">instanceIds</td>
<td style="width: 541px;">A CSV list of instance IDs.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">region</td>
<td style="width: 541px;">The AWS Region, if not specified the default region will be used</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">roleArn</td>
<td style="width: 541px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">roleSessionName</td>
<td style="width: 541px;">An identifier for the assumed role session.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">roleSessionDuration</td>
<td style="width: 541px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 72px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="96" data-line-end="97">
<a id="Context_Output_96"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 765px;">
<thead>
<tr>
<th style="width: 332.333px;"><strong>Path</strong></th>
<th style="width: 329.667px;"><strong>Type</strong></th>
<th style="width: 91px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.AmiLaunchIndex</td>
<td style="width: 329.667px;">number</td>
<td style="width: 91px;">The AMI launch index, which can be used to find this instance in the launch group.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ImageId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the AMI used to launch the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.InstanceId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.InstanceType</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The instance type.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.KernelId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The kernel associated with this instance, if applicable.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.KeyName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The name of the key pair, if this instance was launched with an associated key pair.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.LaunchTime</td>
<td style="width: 329.667px;">date</td>
<td style="width: 91px;">The time the instance was launched.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Monitoring.State</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Placement.AvailabilityZone</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The Availability Zone of the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Placement.Affinity</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The affinity setting for the instance on the Dedicated Host.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Placement.GroupName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The name of the placement group the instance is in (for cluster compute instances).</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Placement.HostId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">he ID of the Dedicated Host on which the instance resides.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Placement.Tenancy</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The tenancy of the instance (if the instance is running in a VPC).</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Platform</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The value is Windows for Windows instances; otherwise blank.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.PrivateDnsName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">(IPv4 only) The private DNS hostname name assigned to the instance. This DNS hostname can only be used inside the Amazon EC2 network. This name is not available until the instance enters the running state.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.PrivateIpAddress</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The private IPv4 address assigned to the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ProductCodes.ProductCodeId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The product code.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ProductCodes.ProductCodeType</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The type of product code.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.PublicDnsName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">(IPv4 only) The public DNS name assigned to the instance. This name is not available until the instance enters the running state.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.PublicIpAddress</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The public IPv4 address assigned to the instance, if applicable.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.RamdiskId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The RAM disk associated with this instance, if applicable.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.State.Code</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The low byte represents the state.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.State.Name</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The current state of the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.StateTransitionReason</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The reason for the most recent state transition. This might be an empty string.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.SubnetId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the subnet in which the instance is running.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.VpcId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the VPC in which the instance is running.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Architecture</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The architecture of the image.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.BlockDeviceMappings.DeviceName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The device name (for example, /dev/sdh or xvdh).</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.BlockDeviceMappings.Ebs.AttachTime</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.BlockDeviceMappings.Ebs.DeleteOnTermination</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">Indicates whether the volume is deleted on instance termination.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.BlockDeviceMappings.Ebs.Status</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The attachment state.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.BlockDeviceMappings.Ebs.VolumeId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the EBS volume.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ClientToken</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The idempotency token you provided when you launched the instance, if applicable.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.EbsOptimized</td>
<td style="width: 329.667px;">boolean</td>
<td style="width: 91px;">Indicates whether the instance is optimized for Amazon EBS I/O.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.EnaSupport</td>
<td style="width: 329.667px;">boolean</td>
<td style="width: 91px;">Specifies whether enhanced networking with ENA is enabled.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Hypervisor</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The hypervisor type of the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.IamInstanceProfile.Arn</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The Amazon Resource Name (ARN) of the instance profile.</td>
</tr>
<tr>
<td style="width: 332.333px;"><a href="http://aws.ec2.instances.iaminstanceprofile.id/">AWS.EC2.Instances.IamInstanceProfile.Id</a></td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the instance profile.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.InstanceLifecycle</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">Indicates whether this is a Spot Instance or a Scheduled Instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the Elastic GPU.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the association.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationState</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The state of the association between the instance and the Elastic GPU.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationTime</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The time the Elastic GPU was associated with the instance.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Association.IpOwnerId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the owner of the Elastic IP address.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Association.PublicDnsName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The public DNS name.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Association.PublicIp</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The public IP address or Elastic IP address bound to the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachTime</td>
<td style="width: 329.667px;">date</td>
<td style="width: 91px;">The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachmentId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the network interface attachment.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Attachment.DeleteOnTermination</td>
<td style="width: 329.667px;">boolean</td>
<td style="width: 91px;">Indicates whether the network interface is deleted when the instance is terminated.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Attachment.DeviceIndex</td>
<td style="width: 329.667px;">number</td>
<td style="width: 91px;">The index of the device on the instance for the network interface attachment.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Attachment.Status</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The attachment state.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Description</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The description.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Groups.GroupName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The name of the security group.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Groups.GroupId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the security group.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Ipv6Addresses.Ipv6Address</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The IPv6 addresses associated with the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.MacAddress</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The MAC address.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.OwnerId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the AWS account that created the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The private DNS name.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The IPv4 address of the network interface within the subnet.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.IpOwnerId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the owner of the Elastic IP address.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicDnsName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The public DNS name.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicIp</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The public IP address or Elastic IP address bound to the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Primary</td>
<td style="width: 329.667px;">boolean</td>
<td style="width: 91px;">Indicates whether this IPv4 address is the primary private IP address of the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateDnsName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The private IPv4 DNS name.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateIpAddress</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The private IPv4 address of the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck</td>
<td style="width: 329.667px;">boolean</td>
<td style="width: 91px;">Indicates whether to validate network traffic to or from this network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.Status</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The status of the network interface.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.SubnetId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the subnet.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.NetworkInterfaces.VpcId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the VPC.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.RootDeviceName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The device name of the root device volume (for example, /dev/sda1).</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.RootDeviceType</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The root device type used by the AMI. The AMI can use an EBS volume or an instance store volume.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.SecurityGroups.GroupName</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The name of the security group.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.SecurityGroups.GroupId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The ID of the security group.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.SourceDestCheck</td>
<td style="width: 329.667px;">boolean</td>
<td style="width: 91px;">Specifies whether to enable an instance launched in a VPC to perform NAT.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.SpotInstanceRequestId</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">If the request is a Spot Instance request, the ID of the request.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.SriovNetSupport</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.StateReason.Code</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The reason code for the state change.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.StateReason.Message</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The message for the state change.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Tags.Key</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The key of the tag.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.Tags.Value</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The value of the tag.</td>
</tr>
<tr>
<td style="width: 332.333px;">AWS.EC2.Instances.VirtualizationType</td>
<td style="width: 329.667px;">string</td>
<td style="width: 91px;">The virtualization type of the instance.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="184" data-line-end="185">
<a id="Command_Example_184"></a>Command Example</h5>
<p class="has-line-data" data-line-start="185" data-line-end="186">``</p>
<h5 class="code-line" data-line-start="187" data-line-end="188">
<a id="Context_Example_187"></a>Context Example</h5>
<pre><code class="has-line-data" data-line-start="189" data-line-end="191">
</code></pre>
<h5 class="code-line" data-line-start="192" data-line-end="193">
<a id="Human_Readable_Output_192"></a>Human Readable Output</h5>
<h3 id="h_fa7ccddb-ec49-447e-b251-cd80ffdc702e" class="code-line" data-line-start="195" data-line-end="196">
<a id="2_awsec2describeimages_195"></a>2. aws-ec2-describe-images</h3>
<hr>
<p class="has-line-data" data-line-start="197" data-line-end="198">Describes one or more of the images (AMIs, AKIs, and ARIs) available to you. Images available to you include public images, private images that you own, and private images owned by other AWS accounts but for which you have explicit launch permissions.</p>
<h5 class="code-line" data-line-start="198" data-line-end="199">
<a id="Base_Command_198"></a>Base Command</h5>
<p class="has-line-data" data-line-start="200" data-line-end="201"><code>aws-ec2-describe-images</code></p>
<h5 class="code-line" data-line-start="201" data-line-end="202">
<a id="Input_201"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters.</td>
<td>Optional</td>
</tr>
<tr>
<td>imageIds</td>
<td>One or more image IDs, Seperated by comma</td>
<td>Optional</td>
</tr>
<tr>
<td>owners</td>
<td>Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon | aws-marketplace | microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership.</td>
<td>Optional</td>
</tr>
<tr>
<td>executableUsers</td>
<td>Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs).</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="215" data-line-end="216">
<a id="Context_Output_215"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 445.667px;"><strong>Path</strong></th>
<th style="width: 71.3333px;"><strong>Type</strong></th>
<th style="width: 224px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Architecture</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The architecture of the image.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.CreationDate</td>
<td style="width: 71.3333px;">date</td>
<td style="width: 224px;">The date and time the image was created.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.ImageId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The ID of the AMI.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.ImageLocation</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The location of the AMI.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.ImageType</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The type of image.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Public</td>
<td style="width: 71.3333px;">boolean</td>
<td style="width: 224px;">Indicates whether the image has public launch permissions. The value is true if this image has public launch permissions or false if it has only implicit and explicit launch permissions.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.KernelId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The kernel associated with the image, if any. Only applicable for machine images.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.OwnerId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The AWS account ID of the image owner.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Platform</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The value is Windows for Windows AMIs; otherwise blank.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.ProductCodes.ProductCodeId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The product code.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.ProductCodes.ProductCodeType</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The type of product code.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.RamdiskId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The RAM disk associated with the image, if any. Only applicable for machine images.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.State</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The current state of the AMI. If the state is available , the image is successfully registered and can be used to launch an instance.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.DeviceName</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The device name (for example, /dev/sdh or xvdh).</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.VirtualName</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The virtual device name (ephemeral N).</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.Encrypted</td>
<td style="width: 71.3333px;">boolean</td>
<td style="width: 224px;">Indicates whether the EBS volume is encrypted.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.DeleteOnTermination</td>
<td style="width: 71.3333px;">boolean</td>
<td style="width: 224px;">Indicates whether the EBS volume is deleted on instance termination.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.Iops</td>
<td style="width: 71.3333px;">number</td>
<td style="width: 224px;">The number of I/O operations per second (IOPS) that the volume supports.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.KmsKeyId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.SnapshotId</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The ID of the snapshot.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeSize</td>
<td style="width: 71.3333px;">number</td>
<td style="width: 224px;">The size of the volume, in GiB.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeType</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The volume type.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.BlockDeviceMappings.NoDevice</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">Suppresses the specified device included in the block device mapping of the AMI.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Description</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The description of the AMI that was provided during image creation.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.EnaSupport</td>
<td style="width: 71.3333px;">boolean</td>
<td style="width: 224px;">Specifies whether enhanced networking with ENA is enabled.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Hypervisor</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The hypervisor type of the image.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.ImageOwnerAlias</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The AWS account alias (for example, amazon , self ) or the AWS account ID of the AMI owner.</td>
</tr>
<tr>
<td style="width: 445.667px;"><a href="http://aws.ec2.images.name/">AWS.EC2.Images.Name</a></td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The name of the AMI that was provided during image creation.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.RootDeviceName</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The device name of the root device volume (for example, /dev/sda1).</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.RootDeviceType</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The type of root device used by the AMI. The AMI can use an EBS volume or an instance store volume.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.SriovNetSupport</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.StateReason.Code</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The reason code for the state change.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.StateReason.Message</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The message for the state change.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Tags.Key</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The key of the tag.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.Tags.Value</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The value of the tag.</td>
</tr>
<tr>
<td style="width: 445.667px;">AWS.EC2.Images.VirtualizationType</td>
<td style="width: 71.3333px;">string</td>
<td style="width: 224px;">The type of virtualization of the AMI.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="265" data-line-end="266"> </h5>
<h3 id="h_9d98a913-bcae-4833-bf6d-f276660d26f5" class="code-line" data-line-start="268" data-line-end="269">
<a id="3_awsec2describeregions_268"></a>3. aws-ec2-describe-regions</h3>
<hr>
<p class="has-line-data" data-line-start="270" data-line-end="271">Describes one or more regions that are currently available to you.</p>
<h5 class="code-line" data-line-start="271" data-line-end="272">
<a id="Base_Command_271"></a>Base Command</h5>
<p class="has-line-data" data-line-start="273" data-line-end="274"><code>aws-ec2-describe-regions</code></p>
<h5 class="code-line" data-line-start="274" data-line-end="275">
<a id="Input_274"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>regionNames</td>
<td>The name of the region (for example, us-east-1 ).</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="285" data-line-end="286">
<a id="Context_Output_285"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 314.333px;"><strong>Path</strong></th>
<th style="width: 78.6667px;"><strong>Type</strong></th>
<th style="width: 347px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 314.333px;">AWS.Regions.Endpoint</td>
<td style="width: 78.6667px;">string</td>
<td style="width: 347px;">The region service endpoint.</td>
</tr>
<tr>
<td style="width: 314.333px;">AWS.Regions.RegionName</td>
<td style="width: 78.6667px;">string</td>
<td style="width: 347px;">The name of the region.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="301" data-line-end="302"> </h5>
<h3 id="h_f5c6af47-13b8-4b9f-b0c3-edf076c90363" class="code-line" data-line-start="304" data-line-end="305">
<a id="4_awsec2describeaddresses_304"></a>4. aws-ec2-describe-addresses</h3>
<hr>
<p class="has-line-data" data-line-start="306" data-line-end="307">Describes one or more of your Elastic IP addresses.</p>
<h5 class="code-line" data-line-start="307" data-line-end="308">
<a id="Base_Command_307"></a>Base Command</h5>
<p class="has-line-data" data-line-start="309" data-line-end="310"><code>aws-ec2-describe-addresses</code></p>
<h5 class="code-line" data-line-start="310" data-line-end="311">
<a id="Input_310"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>publicIps</td>
<td>One or more Elastic IP addresses.</td>
<td>Optional</td>
</tr>
<tr>
<td>allocationIds</td>
<td>One or more allocation IDs.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="323" data-line-end="324">
<a id="Context_Output_323"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.ElasticIPs.InstanceId</td>
<td>string</td>
<td>The ID of the instance that the address is associated with (if any).</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.PublicIp</td>
<td>string</td>
<td>The Elastic IP address.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.AllocationId</td>
<td>string</td>
<td>The ID representing the allocation of the address for use with EC2-VPC.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.AssociationId</td>
<td>string</td>
<td>The ID representing the association of the address with an instance in a VPC.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.Domain</td>
<td>string</td>
<td>dicates whether this Elastic IP address is for use with instances in EC2-Classic (standard) or instances in a VPC.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.NetworkInterfaceId</td>
<td>string</td>
<td>The ID of the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.NetworkInterfaceOwnerId</td>
<td>string</td>
<td>The ID of the AWS account that owns the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.PrivateIpAddress</td>
<td>string</td>
<td>The private IP address associated with the Elastic IP address.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.Region</td>
<td>string</td>
<td>The aws region were the elastic ip is located.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_e4867b65-cc77-40f7-a4fa-5d4072ebc09d" class="code-line" data-line-start="351" data-line-end="352">
<a id="5_awsec2describesnapshots_351"></a>5. aws-ec2-describe-snapshots</h3>
<hr>
<p class="has-line-data" data-line-start="353" data-line-end="354">Describes one or more of the EBS snapshots available to you.</p>
<h5 class="code-line" data-line-start="354" data-line-end="355">
<a id="Base_Command_354"></a>Base Command</h5>
<p class="has-line-data" data-line-start="356" data-line-end="357"><code>aws-ec2-describe-snapshots</code></p>
<h5 class="code-line" data-line-start="357" data-line-end="358">
<a id="Input_357"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>ownerIds</td>
<td>Returns the snapshots owned by the specified owner. Multiple owners can be specified.</td>
<td>Optional</td>
</tr>
<tr>
<td>snapshotIds</td>
<td>One or more snapshot IDs. Seperated by commas</td>
<td>Optional</td>
</tr>
<tr>
<td>restorableByUserIds</td>
<td>One or more AWS accounts IDs that can create volumes from the snapshot.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="371" data-line-end="372">
<a id="Context_Output_371"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Snapshots.DataEncryptionKeyId</td>
<td>string</td>
<td>The data encryption key identifier for the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Description</td>
<td>string</td>
<td>The description for the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Encrypted</td>
<td>boolean</td>
<td>Indicates whether the snapshot is encrypted.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.KmsKeyId</td>
<td>string</td>
<td>The full ARN of the AWS Key Management Service (AWS KMS) customer master key (CMK) that was used to protect the volume encryption key for the parent volume.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.OwnerId</td>
<td>string</td>
<td>The AWS account ID of the EBS snapshot owner.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Progress</td>
<td>string</td>
<td>The progress of the snapshot, as a percentage.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.SnapshotId</td>
<td>string</td>
<td>The ID of the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.StartTime</td>
<td>string</td>
<td>The time stamp when the snapshot was initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.State</td>
<td>string</td>
<td>The snapshot state.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.StateMessage</td>
<td>string</td>
<td>this field displays error state details to help you diagnose why the error occurred.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.VolumeId</td>
<td>string</td>
<td>The ID of the volume that was used to create the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.VolumeSize</td>
<td>number</td>
<td>The size of the volume, in GiB.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.OwnerAlias</td>
<td>string</td>
<td>Value from an Amazon-maintained list of snapshot owners.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Region</td>
<td>string</td>
<td>The aws region were the snapshot is located</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_33bb4eaf-a6ce-4c13-acb6-b50602f8f8f0" class="code-line" data-line-start="404" data-line-end="405">
<a id="6_awsec2describelaunchtemplates_404"></a>6. aws-ec2-describe-launch-templates</h3>
<hr>
<p class="has-line-data" data-line-start="406" data-line-end="407">Describes one or more launch templates.</p>
<h5 class="code-line" data-line-start="407" data-line-end="408">
<a id="Base_Command_407"></a>Base Command</h5>
<p class="has-line-data" data-line-start="409" data-line-end="410"><code>aws-ec2-describe-launch-templates</code></p>
<h5 class="code-line" data-line-start="410" data-line-end="411">
<a id="Input_410"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Filters</td>
<td>One or more filters.See documentation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchTemplateNames</td>
<td>One or more launch template names. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchTemplateIds</td>
<td>One or more launch template IDs. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="423" data-line-end="424">
<a id="Context_Output_423"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplateId</td>
<td>string</td>
<td>The ID of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplateName</td>
<td>string</td>
<td>The name of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.CreateTime</td>
<td>date</td>
<td>The time launch template was created.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.CreatedBy</td>
<td>string</td>
<td>The principal that created the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.DefaultVersionNumber</td>
<td>number</td>
<td>The version number of the default version of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LatestVersionNumber</td>
<td>number</td>
<td>The version number of the latest version of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.Region</td>
<td>string</td>
<td>The aws region where the template is located</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a68db098-b6ff-483c-9aca-494c6c4403aa" class="code-line" data-line-start="449" data-line-end="450">
<a id="7_awsec2describekeypairs_449"></a>7. aws-ec2-describe-key-pairs</h3>
<hr>
<p class="has-line-data" data-line-start="451" data-line-end="452">Describes one or more of your key pairs.</p>
<h5 class="code-line" data-line-start="452" data-line-end="453">
<a id="Base_Command_452"></a>Base Command</h5>
<p class="has-line-data" data-line-start="454" data-line-end="455"><code>aws-ec2-describe-key-pairs</code></p>
<h5 class="code-line" data-line-start="455" data-line-end="456">
<a id="Input_455"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>keyNames</td>
<td>One or more key pair names. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="467" data-line-end="468">
<a id="Context_Output_467"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.KeyPairs.KeyFingerprint</td>
<td>Unknown</td>
<td>If you used CreateKeyPair to create the key pair, this is the SHA-1 digest of the DER encoded private key. If you used ImportKeyPair to provide AWS the public key, this is the MD5 public key fingerprint as specified in section 4 of RFC4716.</td>
</tr>
<tr>
<td>AWS.EC2.KeyPairs.KeyName</td>
<td>Unknown</td>
<td>The name of the key pair.</td>
</tr>
<tr>
<td>AWS.EC2.KeyPairs.Region</td>
<td>Unknown</td>
<td>The aws region where the key pair is located</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_998cbf80-884e-4608-b64f-2c4def6627e6" class="code-line" data-line-start="487" data-line-end="488">
<a id="8_awsec2describevolumes_487"></a>8. aws-ec2-describe-volumes</h3>
<hr>
<p class="has-line-data" data-line-start="489" data-line-end="490">Describes the specified EBS volumes.</p>
<h5 class="code-line" data-line-start="490" data-line-end="491">
<a id="Base_Command_490"></a>Base Command</h5>
<p class="has-line-data" data-line-start="492" data-line-end="493"><code>aws-ec2-describe-volumes</code></p>
<h5 class="code-line" data-line-start="493" data-line-end="494">
<a id="Input_493"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 699px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">filters</td>
<td style="width: 468px;">One or more filters. See documentation for filters list.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">volumeIds</td>
<td style="width: 468px;">One or more volume IDs. Sepereted by comma.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">region</td>
<td style="width: 468px;">The AWS Region, if not specified the default region will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">roleArn</td>
<td style="width: 468px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">roleSessionName</td>
<td style="width: 468px;">An identifier for the assumed role session.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">roleSessionDuration</td>
<td style="width: 468px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="505" data-line-end="506">
<a id="Context_Output_505"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 699px;">
<thead>
<tr>
<th style="width: 374px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 257px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.AvailabilityZone</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The Availability Zone for the volume.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.CreateTime</td>
<td style="width: 59px;">date</td>
<td style="width: 257px;">The time stamp when volume creation was initiated.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Encrypted</td>
<td style="width: 59px;">boolean</td>
<td style="width: 257px;">Indicates whether the volume will be encrypted.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.KmsKeyId</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The full ARN of the AWS Key Management Service customer master key that was used to protect the volume encryption key for the volume.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Size</td>
<td style="width: 59px;">number</td>
<td style="width: 257px;">The snapshot from which the volume was created, if applicable.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.State</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The volume state.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.VolumeId</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The ID of the volume.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Iops</td>
<td style="width: 59px;">number</td>
<td style="width: 257px;">The number of I/O operations per second (IOPS) that the volume supports.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.VolumeType</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The volume type. This can be gp2 for General Purpose SSD, io1 for Provisioned IOPS SSD, st1 for Throughput Optimized HDD, sc1 for Cold HDD, or standard for Magnetic volumes.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Tags.Key</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The key of the tag.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Tags.Value</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The value of the tag.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Attachments.AttachTime</td>
<td style="width: 59px;">date</td>
<td style="width: 257px;">The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Attachments.Device</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The device name.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Attachments.InstanceId</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The ID of the instance.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Attachments.State</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The attachment state of the volume.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Attachments.VolumeId</td>
<td style="width: 59px;">string</td>
<td style="width: 257px;">The ID of the volume.</td>
</tr>
<tr>
<td style="width: 374px;">AWS.EC2.Volumes.Attachments.DeleteOnTermination</td>
<td style="width: 59px;">boolean</td>
<td style="width: 257px;">Indicates whether the EBS volume is deleted on instance termination.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_f88d00d2-7ee0-496b-9a03-00d252f06524" class="code-line" data-line-start="539" data-line-end="540">
<a id="9_awsec2describevpcs_539"></a>9. aws-ec2-describe-vpcs</h3>
<hr>
<p class="has-line-data" data-line-start="541" data-line-end="542">Describes one or more of your VPCs.</p>
<h5 class="code-line" data-line-start="542" data-line-end="543">
<a id="Base_Command_542"></a>Base Command</h5>
<p class="has-line-data" data-line-start="544" data-line-end="545"><code>aws-ec2-describe-vpcs</code></p>
<h5 class="code-line" data-line-start="545" data-line-end="546">
<a id="Input_545"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>vpcIds</td>
<td>One or more VPC IDs. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="557" data-line-end="558">
<a id="Context_Output_557"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Vpcs.CidrBlock</td>
<td>string</td>
<td>The primary IPv4 CIDR block for the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.DhcpOptionsId</td>
<td>string</td>
<td>The ID of the set of DHCP options you have associated with the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.State</td>
<td>string</td>
<td>The current state of the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.VpcId</td>
<td>string</td>
<td>The ID of the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.InstanceTenancy</td>
<td>string</td>
<td>The allowed tenancy of instances launched into the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.IsDefault</td>
<td>string</td>
<td>Indicates whether the VPC is the default VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.AssociationId</td>
<td>string</td>
<td>The association ID for the IPv6 CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlock</td>
<td>string</td>
<td>The IPv6 CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.State</td>
<td>string</td>
<td>The state of the CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.StatusMessage</td>
<td>string</td>
<td>A message about the status of the CIDR block, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.AssociationId</td>
<td>string</td>
<td>The association ID for the IPv4 CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlock</td>
<td>string</td>
<td>The IPv4 CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlockState.State</td>
<td>string</td>
<td>The state of the CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Vpcs.Tags.CidrBlockAssociationSet.CidrBlockState.StatusMessage</td>
<td>string</td>
<td>A message about the status of the CIDR block, if applicable.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2cb8c926-8914-4b3b-8451-68bbc2a8aace" class="code-line" data-line-start="590" data-line-end="591">
<a id="10_awsec2describesubnets_590"></a>10. aws-ec2-describe-subnets</h3>
<hr>
<p class="has-line-data" data-line-start="592" data-line-end="593">Describes one or more of your subnets.</p>
<h5 class="code-line" data-line-start="593" data-line-end="594">
<a id="Base_Command_593"></a>Base Command</h5>
<p class="has-line-data" data-line-start="595" data-line-end="596"><code>aws-ec2-describe-subnets</code></p>
<h5 class="code-line" data-line-start="596" data-line-end="597">
<a id="Input_596"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documetation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>subnetIds</td>
<td>One or more subnet IDs. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="608" data-line-end="609">
<a id="Context_Output_608"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Subnets.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone of the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.AvailableIpAddressCount</td>
<td>number</td>
<td>The number of unused private IPv4 addresses in the subnet. Note that the IPv4 addresses for any stopped instances are considered unavailable.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.CidrBlock</td>
<td>string</td>
<td>The IPv4 CIDR block assigned to the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.DefaultForAz</td>
<td>boolean</td>
<td>Indicates whether this is the default subnet for the Availability Zone.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.MapPublicIpOnLaunch</td>
<td>boolean</td>
<td>Indicates whether instances launched in this subnet receive a public IPv4 address.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.State</td>
<td>string</td>
<td>The current state of the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.SubnetId</td>
<td>string</td>
<td>The ID of the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.VpcId</td>
<td>string</td>
<td>The ID of the VPC the subnet is in.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.AssignIpv6AddressOnCreation</td>
<td>boolean</td>
<td>Indicates whether a network interface created in this subnet (including a network interface created by RunInstances) receives an IPv6 address.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.AssociationId</td>
<td>string</td>
<td>The association ID for the CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlock</td>
<td>string</td>
<td>The IPv6 CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.State</td>
<td>string</td>
<td>The state of a CIDR block.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.Ipv6CidrBlockAssociationSet.Ipv6CidrBlockState.StatusMessage</td>
<td>string</td>
<td>A message about the status of the CIDR block, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Subnets.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<h5 class="code-line" data-line-start="637" data-line-end="638"> </h5>
<h3 id="h_73f7f025-dbff-45fe-a046-2c2318ba939c" class="code-line" data-line-start="640" data-line-end="641">
<a id="11_awsec2describesecuritygroups_640"></a>11. aws-ec2-describe-security-groups</h3>
<hr>
<p class="has-line-data" data-line-start="642" data-line-end="643">Describes one or more of your security groups.</p>
<h5 class="code-line" data-line-start="643" data-line-end="644">
<a id="Base_Command_643"></a>Base Command</h5>
<p class="has-line-data" data-line-start="645" data-line-end="646"><code>aws-ec2-describe-security-groups</code></p>
<h5 class="code-line" data-line-start="646" data-line-end="647">
<a id="Input_646"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documetation for filters list.</td>
<td>Optional</td>
</tr>
<tr>
<td>groupIds</td>
<td>One or more security group IDs. Required for security groups in a nondefault VPC. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>groupNames</td>
<td>One or more security group names. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="659" data-line-end="660">
<a id="Context_Output_659"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.SecurityGroups.Description</td>
<td>string</td>
<td>A description of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.GroupName</td>
<td>string</td>
<td>The name of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.FromPort</td>
<td>number</td>
<td>The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.IpProtocol</td>
<td>string</td>
<td>The IP protocol name (tcp , udp , icmp ) or number.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.IpRanges.CidrIp</td>
<td>string</td>
<td>The IPv4 CIDR range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.IpRanges.Description</td>
<td>string</td>
<td>A description for the security group rule that references this IPv4 address range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.Ipv6Ranges.CidrIpv6</td>
<td>string</td>
<td>The IPv6 CIDR range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.Ipv6Ranges.Description</td>
<td>string</td>
<td>A description for the security group rule that references this IPv6 address range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.PrefixListIds.Description</td>
<td>string</td>
<td>A description for the security group rule that references this prefix list ID.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.PrefixListIds.PrefixListId</td>
<td>string</td>
<td>The ID of the prefix.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.ToPort</td>
<td>number</td>
<td>The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.Description</td>
<td>string</td>
<td>A description for the security group rule that references this user ID group pair.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.GroupId</td>
<td>string</td>
<td>The ID of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.GroupName</td>
<td>string</td>
<td>The name of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.PeeringStatus</td>
<td>string</td>
<td>The status of a VPC peering connection, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.UserId</td>
<td>string</td>
<td>The ID of an AWS account.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.VpcId</td>
<td>string</td>
<td>The ID of the VPC for the referenced security group, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissions.UserIdGroupPairs.VpcPeeringConnectionId</td>
<td>string</td>
<td>The ID of the VPC peering connection, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.OwnerId</td>
<td>string</td>
<td>The AWS account ID of the owner of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.GroupId</td>
<td>string</td>
<td>The ID of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.FromPort</td>
<td>number</td>
<td>The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.IpProtocol</td>
<td>string</td>
<td>The IP protocol name (tcp , udp , icmp) or number.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.IpRanges.CidrIp</td>
<td>string</td>
<td>The IPv4 CIDR range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.IpRanges.Description</td>
<td>string</td>
<td>A description for the security group rule that references this IPv4 address range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.Ipv6Ranges.CidrIpv6</td>
<td>string</td>
<td>The IPv6 CIDR range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.Ipv6Ranges.Description</td>
<td>string</td>
<td>A description for the security group rule that references this IPv6 address range.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.PrefixListIds.Description</td>
<td>string</td>
<td>A description for the security group rule that references this prefix list ID.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.PrefixListIds.PrefixListId</td>
<td>string</td>
<td>The ID of the prefix.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.ToPort</td>
<td>string</td>
<td>The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.Description</td>
<td>string</td>
<td>A description for the security group rule that references this user ID group pair.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.GroupId</td>
<td>string</td>
<td>The ID of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.GroupName</td>
<td>string</td>
<td>The name of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.PeeringStatus</td>
<td>string</td>
<td>The status of a VPC peering connection, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.UserId</td>
<td>string</td>
<td>The ID of an AWS account.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.VpcId</td>
<td>string</td>
<td>The ID of the VPC for the referenced security group, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.IpPermissionsEgress.UserIdGroupPairs.VpcPeeringConnectionId</td>
<td>string</td>
<td>The ID of the VPC peering connection, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.VpcId</td>
<td>string</td>
<td>The ID of the VPC for the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_8028d0b3-d5d6-4c41-bb33-cf33f484c8ef" class="code-line" data-line-start="715" data-line-end="716">
<a id="12_awsec2allocateaddress_715"></a>12. aws-ec2-allocate-address</h3>
<hr>
<p class="has-line-data" data-line-start="717" data-line-end="718">Allocates an Elastic IP address.</p>
<h5 class="code-line" data-line-start="718" data-line-end="719">
<a id="Base_Command_718"></a>Base Command</h5>
<p class="has-line-data" data-line-start="720" data-line-end="721"><code>aws-ec2-allocate-address</code></p>
<h5 class="code-line" data-line-start="721" data-line-end="722">
<a id="Input_721"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="731" data-line-end="732">
<a id="Context_Output_731"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.ElasticIPs.PublicIp</td>
<td>Unknown</td>
<td>The Elastic IP address.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.AllocationId</td>
<td>string</td>
<td>The ID that AWS assigns to represent the allocation of the Elastic IP address for use with instances in a VPC.</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.Domain</td>
<td>string</td>
<td>Indicates whether this Elastic IP address is for use with instances in EC2-Classic (standard ) or instances in a VPC (vpc).</td>
</tr>
<tr>
<td>AWS.EC2.ElasticIPs.Region</td>
<td>Unknown</td>
<td>The aws region where the elastic IP is located.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a8cfe195-40fc-46bf-a4f0-8da5da79771f" class="code-line" data-line-start="752" data-line-end="753">
<a id="13_awsec2associateaddress_752"></a>13. aws-ec2-associate-address</h3>
<hr>
<p class="has-line-data" data-line-start="754" data-line-end="755">Associates an Elastic IP address with an instance or a network interface.</p>
<h5 class="code-line" data-line-start="755" data-line-end="756">
<a id="Base_Command_755"></a>Base Command</h5>
<p class="has-line-data" data-line-start="757" data-line-end="758"><code>aws-ec2-associate-address</code></p>
<h5 class="code-line" data-line-start="758" data-line-end="759">
<a id="Input_758"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>allocationId</td>
<td>The allocation ID.</td>
<td>Required</td>
</tr>
<tr>
<td>instanceId</td>
<td>The ID of the instance. For EC2-VPC, you can specify either the instance ID or the network interface ID, but not both. The operation fails if you specify an instance ID unless exactly one network interface is attached.</td>
<td>Optional</td>
</tr>
<tr>
<td>allowReassociation</td>
<td>For a VPC in an EC2-Classic account, specify true to allow an Elastic IP address that is already associated with an instance or network interface to be reassociated with the specified instance or network interface. Otherwise, the operation fails. In a VPC in an EC2-VPC-only account, reassociation is automatic, therefore you can specify false to ensure the operation fails if the Elastic IP address is already associated with another resource.</td>
<td>Optional</td>
</tr>
<tr>
<td>networkInterfaceId</td>
<td>The ID of the network interface. If the instance has more than one network interface, you must specify a network interface ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>privateIpAddress</td>
<td>The primary or secondary private IP address to associate with the Elastic IP address. If no private IP address is specified, the Elastic IP address is associated with the primary private IP address.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="773" data-line-end="774">
<a id="Context_Output_773"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.ElasticIPs.AssociationId</td>
<td>string</td>
<td>The ID that represents the association of the Elastic IP address with an instance.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_19a16a93-3351-41d0-8cc3-420d5f094326" class="code-line" data-line-start="791" data-line-end="792">
<a id="14_awsec2createsnapshot_791"></a>14. aws-ec2-create-snapshot</h3>
<hr>
<p class="has-line-data" data-line-start="793" data-line-end="794">Creates a snapshot of an EBS volume and stores it in Amazon S3. You can use snapshots for backups, to make copies of EBS volumes, and to save data before shutting down an instance.</p>
<h5 class="code-line" data-line-start="794" data-line-end="795">
<a id="Base_Command_794"></a>Base Command</h5>
<p class="has-line-data" data-line-start="796" data-line-end="797"><code>aws-ec2-create-snapshot</code></p>
<h5 class="code-line" data-line-start="797" data-line-end="798">
<a id="Input_797"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>volumeId</td>
<td>The ID of the EBS volume.</td>
<td>Required</td>
</tr>
<tr>
<td>description</td>
<td>A description for the snapshot.</td>
<td>Optional</td>
</tr>
<tr>
<td>tags</td>
<td>The tags to apply to the snapshot during creation.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="810" data-line-end="811">
<a id="Context_Output_810"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Snapshots.DataEncryptionKeyId</td>
<td>string</td>
<td>The data encryption key identifier for the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Description</td>
<td>string</td>
<td>The description for the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Encrypted</td>
<td>number</td>
<td>Indicates whether the snapshot is encrypted.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.KmsKeyId</td>
<td>string</td>
<td>The full ARN of the AWS Key Management Service (AWS KMS) customer master key (CMK) that was used to protect the volume encryption key for the parent volume.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.OwnerId</td>
<td>string</td>
<td>The AWS account ID of the EBS snapshot owner.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Progress</td>
<td>string</td>
<td>The progress of the snapshot, as a percentage.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.SnapshotId</td>
<td>string</td>
<td>The ID of the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.StartTime</td>
<td>date</td>
<td>The time stamp when the snapshot was initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.State</td>
<td>string</td>
<td>The snapshot state.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.StateMessage</td>
<td>string</td>
<td>this field displays error state details to help you diagnose why the error occurred.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.VolumeId</td>
<td>string</td>
<td>The ID of the volume that was used to create the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.VolumeSize</td>
<td>number</td>
<td>The size of the volume, in GiB.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.OwnerAlias</td>
<td>string</td>
<td>Value from an Amazon-maintained list of snapshot owners.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_89ad79d4-48f5-483a-80ea-4457e48ff243" class="code-line" data-line-start="842" data-line-end="843">
<a id="15_awsec2deletesnapshot_842"></a>15. aws-ec2-delete-snapshot</h3>
<hr>
<p class="has-line-data" data-line-start="844" data-line-end="845">Deletes the specified snapshot.</p>
<h5 class="code-line" data-line-start="845" data-line-end="846">
<a id="Base_Command_845"></a>Base Command</h5>
<p class="has-line-data" data-line-start="847" data-line-end="848"><code>aws-ec2-delete-snapshot</code></p>
<h5 class="code-line" data-line-start="848" data-line-end="849">
<a id="Input_848"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>snapshotId</td>
<td>The ID of the EBS snapshot.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="859" data-line-end="860">
<a id="Context_Output_859"></a>Context Output</h5>
<p class="has-line-data" data-line-start="861" data-line-end="862">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="871" data-line-end="872"> </h5>
<h3 id="h_b2688ea5-3b62-4cb3-86e1-a575209e76ad" class="code-line" data-line-start="874" data-line-end="875">
<a id="16_awsec2createimage_874"></a>16. aws-ec2-create-image</h3>
<hr>
<p class="has-line-data" data-line-start="876" data-line-end="877">Creates an Amazon EBS-backed AMI from an Amazon EBS-backed instance that is either running or stopped.</p>
<h5 class="code-line" data-line-start="877" data-line-end="878">
<a id="Base_Command_877"></a>Base Command</h5>
<p class="has-line-data" data-line-start="879" data-line-end="880"><code>aws-ec2-create-image</code></p>
<h5 class="code-line" data-line-start="880" data-line-end="881">
<a id="Input_880"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>name</td>
<td>A name for the new image.</td>
<td>Required</td>
</tr>
<tr>
<td>instanceId</td>
<td>The ID of the instance.</td>
<td>Required</td>
</tr>
<tr>
<td>description</td>
<td>A description for the new image.</td>
<td>Optional</td>
</tr>
<tr>
<td>noReboot</td>
<td>By default, Amazon EC2 attempts to shut down and reboot the instance before creating the image. If the noReboot option is set, Amazon EC2 wont shut down the instance before creating the image. When this option is used, file system integrity on the created image cant be guaranteed.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="894" data-line-end="895">
<a id="Context_Output_894"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Images.ImageId</td>
<td>string</td>
<td>The ID of the new AMI.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Name</td>
<td>string</td>
<td>The name of the new AMI.</td>
</tr>
<tr>
<td>AWS.EC2.Images.InstanceId</td>
<td>string</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Region</td>
<td>string</td>
<td>The aws region where the image is located</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a94fc08c-5367-45cb-a0af-b0b2ae3902d1" class="code-line" data-line-start="915" data-line-end="916">
<a id="17_awsec2deregisterimage_915"></a>17. aws-ec2-deregister-image</h3>
<hr>
<p class="has-line-data" data-line-start="917" data-line-end="918">Deregisters the specified AMI.</p>
<h5 class="code-line" data-line-start="918" data-line-end="919">
<a id="Base_Command_918"></a>Base Command</h5>
<p class="has-line-data" data-line-start="920" data-line-end="921"><code>aws-ec2-deregister-image</code></p>
<h5 class="code-line" data-line-start="921" data-line-end="922">
<a id="Input_921"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>imageId</td>
<td>The ID of the AMI.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="932" data-line-end="933">
<a id="Context_Output_932"></a>Context Output</h5>
<p class="has-line-data" data-line-start="934" data-line-end="935">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="944" data-line-end="945"> </h5>
<h3 id="h_a9290e85-9f9d-44fb-9b80-8a00624e4edb" class="code-line" data-line-start="947" data-line-end="948">
<a id="18_awsec2modifyvolume_947"></a>18. aws-ec2-modify-volume</h3>
<hr>
<p class="has-line-data" data-line-start="949" data-line-end="950">You can modify several parameters of an existing EBS volume, including volume size, volume type, and IOPS capacity.</p>
<h5 class="code-line" data-line-start="950" data-line-end="951">
<a id="Base_Command_950"></a>Base Command</h5>
<p class="has-line-data" data-line-start="952" data-line-end="953"><code>aws-ec2-modify-volume</code></p>
<h5 class="code-line" data-line-start="953" data-line-end="954">
<a id="Input_953"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>volumeId</td>
<td>The ID of the volume.</td>
<td>Required</td>
</tr>
<tr>
<td>size</td>
<td>Target size in GiB of the volume to be modified.</td>
<td>Optional</td>
</tr>
<tr>
<td>volumeType</td>
<td>Target EBS volume type of the volume to be modified The API does not support modifications for volume type standard . You also cannot change the type of a volume to standard .</td>
<td>Optional</td>
</tr>
<tr>
<td>iops</td>
<td>Target IOPS rate of the volume to be modified.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="967" data-line-end="968">
<a id="Context_Output_967"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Volumes.Modification.VolumeId</td>
<td>string</td>
<td>ID of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.ModificationState</td>
<td>string</td>
<td>Current state of modification. Modification state is null for unmodified. volumes.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.StatusMessage</td>
<td>string</td>
<td>Generic status message on modification progress or failure.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.TargetSize</td>
<td>number</td>
<td>Target size of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.TargetIops</td>
<td>number</td>
<td>Target IOPS rate of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.TargetVolumeType</td>
<td>string</td>
<td>Target EBS volume type of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.OriginalSize</td>
<td>number</td>
<td>Original size of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.OriginalIops</td>
<td>number</td>
<td>Original IOPS rate of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.OriginalVolumeType</td>
<td>string</td>
<td>Original EBS volume type of the volume being modified.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.Progress</td>
<td>string</td>
<td>Modification progress from 0 to 100%.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.StartTime</td>
<td>date</td>
<td>Modification start time.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Modification.EndTime</td>
<td>date</td>
<td>Modification completion or failure time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_e7204c1c-3b45-4853-9955-beab510e79b1" class="code-line" data-line-start="996" data-line-end="997">
<a id="19_awsec2createtags_996"></a>19. aws-ec2-create-tags</h3>
<hr>
<p class="has-line-data" data-line-start="998" data-line-end="999">Adds or overwrites one or more tags for the specified Amazon EC2 resource or resources.</p>
<h5 class="code-line" data-line-start="999" data-line-end="1000">
<a id="Base_Command_999"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1001" data-line-end="1002"><code>aws-ec2-create-tags</code></p>
<h5 class="code-line" data-line-start="1002" data-line-end="1003">
<a id="Input_1002"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>resources</td>
<td>The IDs of one or more resources to tag. For example, ami-1a2b3c4d.</td>
<td>Optional</td>
</tr>
<tr>
<td>tags</td>
<td>One or more tags.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1014" data-line-end="1015">
<a id="Context_Output_1014"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1016" data-line-end="1017">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1026" data-line-end="1027"> </h5>
<h3 id="h_2115882b-52bc-4788-9e1b-3a0f998f3bc3" class="code-line" data-line-start="1029" data-line-end="1030">
<a id="20_awsec2disassociateaddress_1029"></a>20. aws-ec2-disassociate-address</h3>
<hr>
<p class="has-line-data" data-line-start="1031" data-line-end="1032">Disassociates an Elastic IP address from the instance or network interface its associated with.</p>
<h5 class="code-line" data-line-start="1032" data-line-end="1033">
<a id="Base_Command_1032"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1034" data-line-end="1035"><code>aws-ec2-disassociate-address</code></p>
<h5 class="code-line" data-line-start="1035" data-line-end="1036">
<a id="Input_1035"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>associationId</td>
<td>The association ID.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1046" data-line-end="1047">
<a id="Context_Output_1046"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1048" data-line-end="1049">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1058" data-line-end="1059"> </h5>
<h3 id="h_be722caf-bd4f-46f9-b441-0c74b48d156b" class="code-line" data-line-start="1061" data-line-end="1062">
<a id="21_awsec2releaseaddress_1061"></a>21. aws-ec2-release-address</h3>
<hr>
<p class="has-line-data" data-line-start="1063" data-line-end="1064">Releases the specified Elastic IP address.</p>
<h5 class="code-line" data-line-start="1064" data-line-end="1065">
<a id="Base_Command_1064"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1066" data-line-end="1067"><code>aws-ec2-release-address</code></p>
<h5 class="code-line" data-line-start="1067" data-line-end="1068">
<a id="Input_1067"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>allocationId</td>
<td>The allocation ID.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1078" data-line-end="1079">
<a id="Context_Output_1078"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1080" data-line-end="1081">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1090" data-line-end="1091"> </h5>
<h3 id="h_3f201ac0-ada8-42d8-aee2-9d4a83471b0c" class="code-line" data-line-start="1093" data-line-end="1094">
<a id="22_awsec2startinstances_1093"></a>22. aws-ec2-start-instances</h3>
<hr>
<p class="has-line-data" data-line-start="1095" data-line-end="1096">Starts an Amazon EBS-backed instance that you have previously stopped.</p>
<h5 class="code-line" data-line-start="1096" data-line-end="1097">
<a id="Base_Command_1096"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1098" data-line-end="1099"><code>aws-ec2-start-instances</code></p>
<h5 class="code-line" data-line-start="1099" data-line-end="1100">
<a id="Input_1099"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs. Sepereted by comma.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1110" data-line-end="1111">
<a id="Context_Output_1110"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1112" data-line-end="1113">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1122" data-line-end="1123"> </h5>
<h3 id="h_b2d4252b-bad0-4189-9da8-7e938569da84" class="code-line" data-line-start="1125" data-line-end="1126">
<a id="23_awsec2stopinstances_1125"></a>23. aws-ec2-stop-instances</h3>
<hr>
<p class="has-line-data" data-line-start="1127" data-line-end="1128">Stops an Amazon EBS-backed instance.</p>
<h5 class="code-line" data-line-start="1128" data-line-end="1129">
<a id="Base_Command_1128"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1130" data-line-end="1131"><code>aws-ec2-stop-instances</code></p>
<h5 class="code-line" data-line-start="1131" data-line-end="1132">
<a id="Input_1131"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1142" data-line-end="1143">
<a id="Context_Output_1142"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1144" data-line-end="1145">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1154" data-line-end="1155"> </h5>
<h3 id="h_ec872597-4749-4005-9079-968bda885d5d" class="code-line" data-line-start="1157" data-line-end="1158">
<a id="24_awsec2terminateinstances_1157"></a>24. aws-ec2-terminate-instances</h3>
<hr>
<p class="has-line-data" data-line-start="1159" data-line-end="1160">Shuts down one or more instances. This operation is idempotent; if you terminate an instance more than once, each call succeeds.</p>
<h5 class="code-line" data-line-start="1160" data-line-end="1161">
<a id="Base_Command_1160"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1162" data-line-end="1163"><code>aws-ec2-terminate-instances</code></p>
<h5 class="code-line" data-line-start="1163" data-line-end="1164">
<a id="Input_1163"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1174" data-line-end="1175">
<a id="Context_Output_1174"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1176" data-line-end="1177">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1186" data-line-end="1187"> </h5>
<h3 id="h_5d95c555-36d3-4a57-a501-0fec05b9b6f6" class="code-line" data-line-start="1189" data-line-end="1190">
<a id="25_awsec2createvolume_1189"></a>25. aws-ec2-create-volume</h3>
<hr>
<p class="has-line-data" data-line-start="1191" data-line-end="1192">Creates an EBS volume that can be attached to an instance in the same Availability Zone.</p>
<h5 class="code-line" data-line-start="1192" data-line-end="1193">
<a id="Base_Command_1192"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1194" data-line-end="1195"><code>aws-ec2-create-volume</code></p>
<h5 class="code-line" data-line-start="1195" data-line-end="1196">
<a id="Input_1195"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>availabilityZone</td>
<td>The Availability Zone in which to create the volume. Use DescribeAvailabilityZones to list the Availability Zones that are currently available to you.</td>
<td>Required</td>
</tr>
<tr>
<td>encrypted</td>
<td>Specifies whether the volume should be encrypted.</td>
<td>Optional</td>
</tr>
<tr>
<td>iops</td>
<td>The number of I/O operations per second (IOPS) to provision for the volume, with a maximum ratio of 50 IOPS/GiB. Range is 100 to 32000 IOPS for volumes in most regions.</td>
<td>Optional</td>
</tr>
<tr>
<td>kmsKeyId</td>
<td>An identifier for the AWS Key Management Service (AWS KMS) customer master key (CMK) to use when creating the encrypted volume. This parameter is only required if you want to use a non-default CMK; if this parameter is not specified, the default CMK for EBS is used. If a KmsKeyId is specified, the Encrypted flag must also be set.</td>
<td>Optional</td>
</tr>
<tr>
<td>size</td>
<td>The size of the volume, in GiBs.</td>
<td>Optional</td>
</tr>
<tr>
<td>snapshotId</td>
<td>The snapshot from which to create the volume.</td>
<td>Optional</td>
</tr>
<tr>
<td>volumeType</td>
<td>The volume type.</td>
<td>Optional</td>
</tr>
<tr>
<td>tags</td>
<td>One or more tags.Example key=Name,value=test;key=Owner,value=Bob</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1213" data-line-end="1214">
<a id="Context_Output_1213"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Volumes.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone for the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.CreateTime</td>
<td>date</td>
<td>The time stamp when volume creation was initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Encrypted</td>
<td>boolean</td>
<td>Indicates whether the volume will be encrypted.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.KmsKeyId</td>
<td>string</td>
<td>The full ARN of the AWS Key Management Service (AWS KMS) customer master key (CMK) that was used to protect the volume encryption key for the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Size</td>
<td>number</td>
<td>The size of the volume, in GiBs.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.SnapshotId</td>
<td>string</td>
<td>The snapshot from which the volume was created, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.State</td>
<td>string</td>
<td>The volume state.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.VolumeId</td>
<td>string</td>
<td>The ID of the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Iops</td>
<td>number</td>
<td>The number of I/O operations per second (IOPS) that the volume supports.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.VolumeType</td>
<td>string</td>
<td>The volume type. This can be gp2 for General Purpose SSD, io1 for Provisioned IOPS SSD, st1 for Throughput Optimized HDD, sc1 for Cold HDD, or standard for Magnetic volumes.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1239" data-line-end="1240"> </h5>
<h3 id="h_09ab8c37-4b74-4671-8707-7a5f3c0d458d" class="code-line" data-line-start="1242" data-line-end="1243">
<a id="26_awsec2attachvolume_1242"></a>26. aws-ec2-attach-volume</h3>
<hr>
<p class="has-line-data" data-line-start="1244" data-line-end="1245">Attaches an EBS volume to a running or stopped instance and exposes it to the instance with the specified device name.</p>
<h5 class="code-line" data-line-start="1245" data-line-end="1246">
<a id="Base_Command_1245"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1247" data-line-end="1248"><code>aws-ec2-attach-volume</code></p>
<h5 class="code-line" data-line-start="1248" data-line-end="1249">
<a id="Input_1248"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>device</td>
<td>The device name (for example, /dev/sdh or xvdh).</td>
<td>Required</td>
</tr>
<tr>
<td>instanceId</td>
<td>The ID of the instance.</td>
<td>Required</td>
</tr>
<tr>
<td>volumeId</td>
<td>The ID of the EBS volume. The volume and instance must be within the same Availability Zone.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1261" data-line-end="1262">
<a id="Context_Output_1261"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Volumes.Attachments.AttachTime</td>
<td>date</td>
<td>The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.Device</td>
<td>string</td>
<td>The device name.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.InstanceId</td>
<td>string</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.State</td>
<td>string</td>
<td>The attachment state of the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.VolumeId</td>
<td>string</td>
<td>The ID of the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.DeleteOnTermination</td>
<td>boolean</td>
<td>Indicates whether the EBS volume is deleted on instance termination.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1281" data-line-end="1282"> </h5>
<h3 id="h_770c1b00-00b3-4f07-af43-2e1fc5424d9a" class="code-line" data-line-start="1284" data-line-end="1285">
<a id="27_awsec2detachvolume_1284"></a>27. aws-ec2-detach-volume</h3>
<hr>
<p class="has-line-data" data-line-start="1286" data-line-end="1287">Detaches an EBS volume from an instance.</p>
<h5 class="code-line" data-line-start="1287" data-line-end="1288">
<a id="Base_Command_1287"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1289" data-line-end="1290"><code>aws-ec2-detach-volume</code></p>
<h5 class="code-line" data-line-start="1290" data-line-end="1291">
<a id="Input_1290"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>volumeId</td>
<td>The ID of the volume.</td>
<td>Required</td>
</tr>
<tr>
<td>force</td>
<td>Forces detachment if the previous detachment attempt did not occur cleanly. This option can lead to data loss or a corrupted file system. Use this option only as a last resort to detach a volume from a failed instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>device</td>
<td>The device name (for example, /dev/sdh or xvdh).</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceId</td>
<td>The ID of the instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1304" data-line-end="1305">
<a id="Context_Output_1304"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Volumes.Attachments.AttachTime</td>
<td>date</td>
<td>The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.Device</td>
<td>string</td>
<td>The device name.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.InstanceId</td>
<td>string</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.State</td>
<td>string</td>
<td>The attachment state of the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.VolumeId</td>
<td>string</td>
<td>The ID of the volume.</td>
</tr>
<tr>
<td>AWS.EC2.Volumes.Attachments.DeleteOnTermination</td>
<td>boolean</td>
<td>Indicates whether the EBS volume is deleted on instance termination.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1c405d38-16a4-4f65-b93c-6e5caedfa894" class="code-line" data-line-start="1327" data-line-end="1328">
<a id="28_awsec2deletevolume_1327"></a>28. aws-ec2-delete-volume</h3>
<hr>
<p class="has-line-data" data-line-start="1329" data-line-end="1330">Deletes the specified EBS volume. The volume must be in the available state (not attached to an instance).</p>
<h5 class="code-line" data-line-start="1330" data-line-end="1331">
<a id="Base_Command_1330"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1332" data-line-end="1333"><code>aws-ec2-delete-volume</code></p>
<h5 class="code-line" data-line-start="1333" data-line-end="1334">
<a id="Input_1333"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>volumeId</td>
<td>The ID of the volume.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1344" data-line-end="1345">
<a id="Context_Output_1344"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1346" data-line-end="1347">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1356" data-line-end="1357"> </h5>
<h3 id="h_3d06d1bd-308e-40f5-a500-177b04504740" class="code-line" data-line-start="1359" data-line-end="1360">
<a id="29_awsec2runinstances_1359"></a>29. aws-ec2-run-instances</h3>
<hr>
<p class="has-line-data" data-line-start="1361" data-line-end="1362">Launches the specified number of instances using an AMI for which you have permissions. You can create a launch template , which is a resource that contains the parameters to launch an instance. When you launch an instance using RunInstances , you can specify the launch template instead of specifying the launch parameters. An instance is ready for you to use when its in the running state. You can check the state of your instance using DescribeInstances.</p>
<h5 class="code-line" data-line-start="1362" data-line-end="1363">
<a id="Base_Command_1362"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1364" data-line-end="1365"><code>aws-ec2-run-instances</code></p>
<h5 class="code-line" data-line-start="1365" data-line-end="1366">
<a id="Input_1365"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>count</td>
<td>The number of instances to launch. must be grater then 0.</td>
<td>Required</td>
</tr>
<tr>
<td>imageId</td>
<td>The ID of the AMI, which you can get by calling DescribeImages . An AMI is required to launch an instance and must be specified here or in a launch template.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceType</td>
<td>The instance type. for example: t2.large</td>
<td>Optional</td>
</tr>
<tr>
<td>securityGroupIds</td>
<td>One or more security group IDs. Sepereted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>securityGroups</td>
<td>One or more security group names. For a nondefault VPC, you must use security group IDs instead.</td>
<td>Optional</td>
</tr>
<tr>
<td>subnetId</td>
<td>The ID of the subnet to launch the instance into.</td>
<td>Optional</td>
</tr>
<tr>
<td>userData</td>
<td>The user data to make available to the instance.This value will be base64 encoded automatically. Do not base64 encode this value prior to performing the operation.</td>
<td>Optional</td>
</tr>
<tr>
<td>disableApiTermination</td>
<td>If you set this parameter to true , you cant terminate the instance using the Amazon EC2 console, CLI, or API.</td>
<td>Optional</td>
</tr>
<tr>
<td>iamInstanceProfileArn</td>
<td>The Amazon Resource Name (ARN) of the instance profile. Both iamInstanceProfileArn and iamInstanceProfile are required if you would like to associate an instance profile.</td>
<td>Optional</td>
</tr>
<tr>
<td>iamInstanceProfileName</td>
<td>The name of the instance profile. Both iamInstanceProfileArn and iamInstanceProfile are required if you would like to associate an instance profile.</td>
<td>Optional</td>
</tr>
<tr>
<td>keyName</td>
<td>The name of the key pair. Warning - If you do not specify a key pair, you cant connect to the instance unless you choose an AMI that is configured to allow users another way to log in.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsOptimized</td>
<td>Indicates whether the instance is optimized for Amazon EBS I/O.</td>
<td>Optional</td>
</tr>
<tr>
<td>deviceName</td>
<td>The device name (for example, /dev/sdh or xvdh).</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsVolumeSize</td>
<td>The size of the volume, in GiB.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsVolumeType</td>
<td>The volume type.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsIops</td>
<td>The number of I/O operations per second (IOPS) that the volume supports.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsDeleteOnTermination</td>
<td>Indicates whether the EBS volume is deleted on instance termination.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsKmsKeyId</td>
<td>Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsSnapshotId</td>
<td>The ID of the snapshot.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsEncrypted</td>
<td>Indicates whether the EBS volume is encrypted.</td>
<td>Optional</td>
</tr>
<tr>
<td>launchTemplateId</td>
<td>The ID of the launch template. The launch template to use to launch the instances. Any parameters that you specify in RunInstances override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both.</td>
<td>Optional</td>
</tr>
<tr>
<td>launchTemplateName</td>
<td>The name of the launch template. The launch template to use to launch the instances. Any parameters that you specify in RunInstances override the same parameters in the launch template. You can specify either the name or ID of a launch template, but not both.</td>
<td>Optional</td>
</tr>
<tr>
<td>launchTemplateVersion</td>
<td>The version number of the launch template.</td>
<td>Optional</td>
</tr>
<tr>
<td>tags</td>
<td>The tags to apply to the instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1399" data-line-end="1400">
<a id="Context_Output_1399"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Instances.AmiLaunchIndex</td>
<td>number</td>
<td>The AMI launch index, which can be used to find this instance in the launch group.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ImageId</td>
<td>string</td>
<td>The ID of the AMI used to launch the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.InstanceId</td>
<td>string</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.InstanceType</td>
<td>string</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.KernelId</td>
<td>string</td>
<td>The kernel associated with this instance, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.KeyName</td>
<td>string</td>
<td>The name of the key pair, if this instance was launched with an associated key pair.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.LaunchTime</td>
<td>date</td>
<td>The time the instance was launched.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Monitoring.State</td>
<td>string</td>
<td>Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Placement.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Placement.Affinity</td>
<td>string</td>
<td>The affinity setting for the instance on the Dedicated Host.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Placement.GroupName</td>
<td>string</td>
<td>The name of the placement group the instance is in (for cluster compute instances).</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Placement.HostId</td>
<td>string</td>
<td>he ID of the Dedicated Host on which the instance resides.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Placement.Tenancy</td>
<td>string</td>
<td>The tenancy of the instance (if the instance is running in a VPC).</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Platform</td>
<td>string</td>
<td>The value is Windows for Windows instances; otherwise blank.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.PrivateDnsName</td>
<td>string</td>
<td>(IPv4 only) The private DNS hostname name assigned to the instance. This DNS hostname can only be used inside the Amazon EC2 network. This name is not available until the instance enters the running state.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.PrivateIpAddress</td>
<td>string</td>
<td>The private IPv4 address assigned to the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ProductCodes.ProductCodeId</td>
<td>string</td>
<td>The product code.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ProductCodes.ProductCodeType</td>
<td>string</td>
<td>The type of product code.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.PublicDnsName</td>
<td>string</td>
<td>(IPv4 only) The public DNS name assigned to the instance. This name is not available until the instance enters the running state.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.PublicIpAddress</td>
<td>string</td>
<td>The public IPv4 address assigned to the instance, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.RamdiskId</td>
<td>string</td>
<td>The RAM disk associated with this instance, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.State.Code</td>
<td>string</td>
<td>The low byte represents the state.</td>
</tr>
<tr>
<td><a href="http://aws.ec2.instances.state.name/">AWS.EC2.Instances.State.Name</a></td>
<td>string</td>
<td>The current state of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.StateTransitionReason</td>
<td>string</td>
<td>The reason for the most recent state transition. This might be an empty string.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.SubnetId</td>
<td>string</td>
<td>The ID of the subnet in which the instance is running.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.VpcId</td>
<td>string</td>
<td>The ID of the VPC in which the instance is running.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Architecture</td>
<td>string</td>
<td>The architecture of the image.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.BlockDeviceMappings.DeviceName</td>
<td>string</td>
<td>The device name (for example, /dev/sdh or xvdh).</td>
</tr>
<tr>
<td>AWS.EC2.Instances.BlockDeviceMappings.Ebs.AttachTime</td>
<td>string</td>
<td>The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.BlockDeviceMappings.Ebs.DeleteOnTermination</td>
<td>string</td>
<td>Indicates whether the volume is deleted on instance termination.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.BlockDeviceMappings.Ebs.Status</td>
<td>string</td>
<td>The attachment state.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.BlockDeviceMappings.Ebs.VolumeId</td>
<td>string</td>
<td>The ID of the EBS volume.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ClientToken</td>
<td>string</td>
<td>The idempotency token you provided when you launched the instance, if applicable.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.EbsOptimized</td>
<td>boolean</td>
<td>Indicates whether the instance is optimized for Amazon EBS I/O.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.EnaSupport</td>
<td>boolean</td>
<td>Specifies whether enhanced networking with ENA is enabled.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Hypervisor</td>
<td>string</td>
<td>The hypervisor type of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.IamInstanceProfile.Arn</td>
<td>string</td>
<td>The Amazon Resource Name (ARN) of the instance profile.</td>
</tr>
<tr>
<td><a href="http://aws.ec2.instances.iaminstanceprofile.id/">AWS.EC2.Instances.IamInstanceProfile.Id</a></td>
<td>string</td>
<td>The ID of the instance profile.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.InstanceLifecycle</td>
<td>string</td>
<td>Indicates whether this is a Spot Instance or a Scheduled Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuId</td>
<td>string</td>
<td>The ID of the Elastic GPU.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationId</td>
<td>string</td>
<td>The ID of the association.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationState</td>
<td>string</td>
<td>The state of the association between the instance and the Elastic GPU.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.ElasticGpuAssociations.ElasticGpuAssociationTime</td>
<td>string</td>
<td>The time the Elastic GPU was associated with the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Association.IpOwnerId</td>
<td>string</td>
<td>The ID of the owner of the Elastic IP address.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Association.PublicDnsName</td>
<td>string</td>
<td>The public DNS name.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Association.PublicIp</td>
<td>string</td>
<td>The public IP address or Elastic IP address bound to the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachTime</td>
<td>date</td>
<td>The time stamp when the attachment initiated.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Attachment.AttachmentId</td>
<td>string</td>
<td>The ID of the network interface attachment.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Attachment.DeleteOnTermination</td>
<td>boolean</td>
<td>Indicates whether the network interface is deleted when the instance is terminated.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Attachment.DeviceIndex</td>
<td>number</td>
<td>The index of the device on the instance for the network interface attachment.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Attachment.Status</td>
<td>string</td>
<td>The attachment state.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Description</td>
<td>string</td>
<td>The description.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Groups.GroupName</td>
<td>string</td>
<td>The name of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Groups.GroupId</td>
<td>string</td>
<td>The ID of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Ipv6Addresses.Ipv6Address</td>
<td>string</td>
<td>The IPv6 addresses associated with the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.MacAddress</td>
<td>string</td>
<td>The MAC address.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.NetworkInterfaceId</td>
<td>string</td>
<td>The ID of the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.OwnerId</td>
<td>string</td>
<td>The ID of the AWS account that created the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateDnsName</td>
<td>string</td>
<td>The private DNS name.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddress</td>
<td>string</td>
<td>The IPv4 address of the network interface within the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.IpOwnerId</td>
<td>string</td>
<td>The ID of the owner of the Elastic IP address.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicDnsName</td>
<td>string</td>
<td>The public DNS name.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Association.PublicIp</td>
<td>string</td>
<td>The public IP address or Elastic IP address bound to the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.Primary</td>
<td>boolean</td>
<td>Indicates whether this IPv4 address is the primary private IP address of the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateDnsName</td>
<td>string</td>
<td>The private IPv4 DNS name.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.PrivateIpAddresses.PrivateIpAddress</td>
<td>string</td>
<td>The private IPv4 address of the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.SourceDestCheck</td>
<td>boolean</td>
<td>Indicates whether to validate network traffic to or from this network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.Status</td>
<td>string</td>
<td>The status of the network interface.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.SubnetId</td>
<td>string</td>
<td>The ID of the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.NetworkInterfaces.VpcId</td>
<td>string</td>
<td>The ID of the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.RootDeviceName</td>
<td>string</td>
<td>The device name of the root device volume (for example, /dev/sda1).</td>
</tr>
<tr>
<td>AWS.EC2.Instances.RootDeviceType</td>
<td>string</td>
<td>The root device type used by the AMI. The AMI can use an EBS volume or an instance store volume.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.SecurityGroups.GroupName</td>
<td>string</td>
<td>The name of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.SecurityGroups.GroupId</td>
<td>string</td>
<td>The ID of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.SourceDestCheck</td>
<td>boolean</td>
<td>Specifies whether to enable an instance launched in a VPC to perform NAT.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.SpotInstanceRequestId</td>
<td>string</td>
<td>If the request is a Spot Instance request, the ID of the request.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.SriovNetSupport</td>
<td>string</td>
<td>Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.StateReason.Code</td>
<td>string</td>
<td>The reason code for the state change.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.StateReason.Message</td>
<td>string</td>
<td>The message for the state change.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.VirtualizationType</td>
<td>string</td>
<td>The virtualization type of the instance.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1495" data-line-end="1496"> </h5>
<h3 id="h_9ac683ac-0db1-40b7-bc97-95ff3d4a57ce" class="code-line" data-line-start="1498" data-line-end="1499">
<a id="30_awsec2waiterinstancerunning_1498"></a>30. aws-ec2-waiter-instance-running</h3>
<hr>
<p class="has-line-data" data-line-start="1500" data-line-end="1501">A waiter function that runs every 15 seconds until a successful state is reached.</p>
<h5 class="code-line" data-line-start="1501" data-line-end="1502">
<a id="Base_Command_1501"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1503" data-line-end="1504"><code>aws-ec2-waiter-instance-running</code></p>
<h5 class="code-line" data-line-start="1504" data-line-end="1505">
<a id="Input_1504"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filter</td>
<td>One or more filters. See documentation for details &amp; filter options.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs. Sepreted by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterDelay</td>
<td>The amount of time in seconds to wait between attempts. Default 15</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterMaxAttempts</td>
<td>The maximum number of attempts to be made. Default 40</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1518" data-line-end="1519">
<a id="Context_Output_1518"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1520" data-line-end="1521">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1530" data-line-end="1531"> </h5>
<h3 id="h_580aa99b-139d-404e-8c17-d19912e68637" class="code-line" data-line-start="1533" data-line-end="1534">
<a id="31_awsec2waiterinstancestatusok_1533"></a>31. aws-ec2-waiter-instance-status-ok</h3>
<hr>
<p class="has-line-data" data-line-start="1535" data-line-end="1536">A waiter function that runs every 15 seconds until a successful state is reached</p>
<h5 class="code-line" data-line-start="1536" data-line-end="1537">
<a id="Base_Command_1536"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1538" data-line-end="1539"><code>aws-ec2-waiter-instance-status-ok</code></p>
<h5 class="code-line" data-line-start="1539" data-line-end="1540">
<a id="Input_1539"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filter</td>
<td>One or more filters. See documentation for details &amp; filter options.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs. Seprated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterDelay</td>
<td>The amount of time in seconds to wait between attempts. Default 15</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterMaxAttempts</td>
<td>The maximum number of attempts to be made. Default 40.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1553" data-line-end="1554">
<a id="Context_Output_1553"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1555" data-line-end="1556">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1565" data-line-end="1566"> </h5>
<h3 id="h_dab6d1ab-0f93-4960-a25b-28b30d41e600" class="code-line" data-line-start="1568" data-line-end="1569">
<a id="32_awsec2waiterinstancestopped_1568"></a>32. aws-ec2-waiter-instance-stopped</h3>
<hr>
<p class="has-line-data" data-line-start="1570" data-line-end="1571">A waiter function that runs every 15 seconds until a successful state is reached</p>
<h5 class="code-line" data-line-start="1571" data-line-end="1572">
<a id="Base_Command_1571"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1573" data-line-end="1574"><code>aws-ec2-waiter-instance-stopped</code></p>
<h5 class="code-line" data-line-start="1574" data-line-end="1575">
<a id="Input_1574"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filter</td>
<td>One or more filters. See documentation for details &amp; filter options.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs. Seprated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterDelay</td>
<td>The amount of time in seconds to wait between attempts. Default 15</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterMaxAttempts</td>
<td>The maximum number of attempts to be made. Default 40</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1588" data-line-end="1589">
<a id="Context_Output_1588"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1590" data-line-end="1591">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1600" data-line-end="1601"> </h5>
<h3 id="h_093bb9c6-d48b-4477-821e-384b5c965ed9" class="code-line" data-line-start="1603" data-line-end="1604">
<a id="33_awsec2waiterinstanceterminated_1603"></a>33. aws-ec2-waiter-instance-terminated</h3>
<hr>
<p class="has-line-data" data-line-start="1605" data-line-end="1606">A waiter function that runs every 15 seconds until a successful state is reached</p>
<h5 class="code-line" data-line-start="1606" data-line-end="1607">
<a id="Base_Command_1606"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1608" data-line-end="1609"><code>aws-ec2-waiter-instance-terminated</code></p>
<h5 class="code-line" data-line-start="1609" data-line-end="1610">
<a id="Input_1609"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filter</td>
<td>One or more filters. See documentation for details &amp; filter options.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs. Seprated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterDelay</td>
<td>The amount of time in seconds to wait between attempts. Default 15</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterMaxAttempts</td>
<td>The maximum number of attempts to be made. Default 40</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1623" data-line-end="1624">
<a id="Context_Output_1623"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1625" data-line-end="1626">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1635" data-line-end="1636"> </h5>
<h3 id="h_7b51d2f4-3f36-43f5-90f2-254739df1f52" class="code-line" data-line-start="1638" data-line-end="1639">
<a id="34_awsec2waiterimageavailable_1638"></a>34. aws-ec2-waiter-image-available</h3>
<hr>
<p class="has-line-data" data-line-start="1640" data-line-end="1641">A waiter function that waits until image is avilable</p>
<h5 class="code-line" data-line-start="1641" data-line-end="1642">
<a id="Base_Command_1641"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1643" data-line-end="1644"><code>aws-ec2-waiter-image-available</code></p>
<h5 class="code-line" data-line-start="1644" data-line-end="1645">
<a id="Input_1644"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for available filters.</td>
<td>Optional</td>
</tr>
<tr>
<td>imageIds</td>
<td>One or more image IDs. Sperated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>owners</td>
<td>Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon | aws-marketplace | microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership.</td>
<td>Optional</td>
</tr>
<tr>
<td>executableUsers</td>
<td>Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs).</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterDelay</td>
<td>The amount of time in seconds to wait between attempts. Default 15</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterMaxAttempts</td>
<td>The maximum number of attempts to be made. Default 40</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1660" data-line-end="1661">
<a id="Context_Output_1660"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1662" data-line-end="1663">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1672" data-line-end="1673"> </h5>
<h3 id="h_d8dc108f-dda7-4c9f-a85e-d790d5bc1be3" class="code-line" data-line-start="1675" data-line-end="1676">
<a id="35_awsec2waitersnapshot_completed_1675"></a>35. aws-ec2-waiter-snapshot_completed</h3>
<hr>
<p class="has-line-data" data-line-start="1677" data-line-end="1678">A waiter function that waits until the snapshot is complate</p>
<h5 class="code-line" data-line-start="1678" data-line-end="1679">
<a id="Base_Command_1678"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1680" data-line-end="1681"><code>aws-ec2-waiter-snapshot_completed</code></p>
<h5 class="code-line" data-line-start="1681" data-line-end="1682">
<a id="Input_1681"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for available filters.</td>
<td>Optional</td>
</tr>
<tr>
<td>ownerIds</td>
<td>Returns the snapshots owned by the specified owner. Multiple owners can be specified. Sperated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>snapshotIds</td>
<td>One or more snapshot IDs. Sperated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>restorableByUserIds</td>
<td>One or more AWS accounts IDs that can create volumes from the snapshot.</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterDelay</td>
<td>The amount of time in seconds to wait between attempts. Default 15</td>
<td>Optional</td>
</tr>
<tr>
<td>waiterMaxAttempts</td>
<td>The maximum number of attempts to be made. Default 40</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1697" data-line-end="1698">
<a id="Context_Output_1697"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1699" data-line-end="1700">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1709" data-line-end="1710"> </h5>
<h3 id="h_ec4c0cfd-8442-44e4-9976-5acefee5e66c" class="code-line" data-line-start="1712" data-line-end="1713">
<a id="36_awsec2getlatestami_1712"></a>36. aws-ec2-get-latest-ami</h3>
<hr>
<p class="has-line-data" data-line-start="1714" data-line-end="1715">Get The latest AMI</p>
<h5 class="code-line" data-line-start="1715" data-line-end="1716">
<a id="Base_Command_1715"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1717" data-line-end="1718"><code>aws-ec2-get-latest-ami</code></p>
<h5 class="code-line" data-line-start="1718" data-line-end="1719">
<a id="Input_1718"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>One or more filters. See documentation for available filters.</td>
<td>Optional</td>
</tr>
<tr>
<td>owners</td>
<td>Filters the images by the owner. Specify an AWS account ID, self (owner is the sender of the request), or an AWS owner alias (valid values are amazon | aws-marketplace | microsoft ). Omitting this option returns all images for which you have launch permissions, regardless of ownership.</td>
<td>Optional</td>
</tr>
<tr>
<td>executableUsers</td>
<td>Scopes the images by users with explicit launch permissions. Specify an AWS account ID, self (the sender of the request), or all (public AMIs).</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1731" data-line-end="1732">
<a id="Context_Output_1731"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Images.Architecture</td>
<td>string</td>
<td>The architecture of the image.</td>
</tr>
<tr>
<td>AWS.EC2.Images.CreationDate</td>
<td>date</td>
<td>The date and time the image was created.</td>
</tr>
<tr>
<td>AWS.EC2.Images.ImageId</td>
<td>string</td>
<td>The ID of the AMI.</td>
</tr>
<tr>
<td>AWS.EC2.Images.ImageLocation</td>
<td>string</td>
<td>The location of the AMI.</td>
</tr>
<tr>
<td>AWS.EC2.Images.ImageType</td>
<td>string</td>
<td>The type of image.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Public</td>
<td>boolean</td>
<td>Indicates whether the image has public launch permissions. The value is true if this image has public launch permissions or false if it has only implicit and explicit launch permissions.</td>
</tr>
<tr>
<td>AWS.EC2.Images.KernelId</td>
<td>string</td>
<td>The kernel associated with the image, if any. Only applicable for machine images.</td>
</tr>
<tr>
<td>AWS.EC2.Images.OwnerId</td>
<td>string</td>
<td>The AWS account ID of the image owner.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Platform</td>
<td>string</td>
<td>The value is Windows for Windows AMIs; otherwise blank.</td>
</tr>
<tr>
<td>AWS.EC2.Images.ProductCodes.ProductCodeId</td>
<td>string</td>
<td>The product code.</td>
</tr>
<tr>
<td>AWS.EC2.Images.ProductCodes.ProductCodeType</td>
<td>string</td>
<td>The type of product code.</td>
</tr>
<tr>
<td>AWS.EC2.Images.RamdiskId</td>
<td>string</td>
<td>The RAM disk associated with the image, if any. Only applicable for machine images.</td>
</tr>
<tr>
<td>AWS.EC2.Images.State</td>
<td>string</td>
<td>The current state of the AMI. If the state is available , the image is successfully registered and can be used to launch an instance.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.DeviceName</td>
<td>string</td>
<td>The device name (for example, /dev/sdh or xvdh ).</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.VirtualName</td>
<td>string</td>
<td>The virtual device name (ephemeral N).</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.Encrypted</td>
<td>boolean</td>
<td>Indicates whether the EBS volume is encrypted.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.DeleteOnTermination</td>
<td>boolean</td>
<td>Indicates whether the EBS volume is deleted on instance termination.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.Iops</td>
<td>number</td>
<td>The number of I/O operations per second (IOPS) that the volume supports.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.KmsKeyId</td>
<td>string</td>
<td>Identifier (key ID, key alias, ID ARN, or alias ARN) for a user-managed CMK under which the EBS volume is encrypted.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.SnapshotId</td>
<td>string</td>
<td>The ID of the snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeSize</td>
<td>number</td>
<td>The size of the volume, in GiB.</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.Ebs.VolumeType</td>
<td>string</td>
<td>The volume type</td>
</tr>
<tr>
<td>AWS.EC2.Images.BlockDeviceMappings.NoDevice</td>
<td>string</td>
<td>Suppresses the specified device included in the block device mapping of the AMI.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Description</td>
<td>string</td>
<td>The description of the AMI that was provided during image creation.</td>
</tr>
<tr>
<td>AWS.EC2.Images.EnaSupport</td>
<td>boolean</td>
<td>Specifies whether enhanced networking with ENA is enabled.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Hypervisor</td>
<td>string</td>
<td>The hypervisor type of the image.</td>
</tr>
<tr>
<td>AWS.EC2.Images.ImageOwnerAlias</td>
<td>string</td>
<td>The AWS account alias (for example, amazon , self ) or the AWS account ID of the AMI owner.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Name</td>
<td>string</td>
<td>The name of the AMI that was provided during image creation.</td>
</tr>
<tr>
<td>AWS.EC2.Images.RootDeviceName</td>
<td>string</td>
<td>The device name of the root device volume (for example, /dev/sda1).</td>
</tr>
<tr>
<td>AWS.EC2.Images.RootDeviceType</td>
<td>string</td>
<td>The type of root device used by the AMI. The AMI can use an EBS volume or an instance store volume.</td>
</tr>
<tr>
<td>AWS.EC2.Images.SriovNetSupport</td>
<td>string</td>
<td>Specifies whether enhanced networking with the Intel 82599 Virtual Function interface is enabled.</td>
</tr>
<tr>
<td>AWS.EC2.Images.StateReason.Code</td>
<td>string</td>
<td>The reason code for the state change.</td>
</tr>
<tr>
<td>AWS.EC2.Images.StateReason.Message</td>
<td>string</td>
<td>The message for the state change.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Images.VirtualizationType</td>
<td>string</td>
<td>The type of virtualization of the AMI.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1781" data-line-end="1782"> </h5>
<h3 id="h_47a604c2-2837-40ef-9e2f-b55c99b96e78" class="code-line" data-line-start="1784" data-line-end="1785">
<a id="37_awsec2createsecuritygroup_1784"></a>37. aws-ec2-create-security-group</h3>
<hr>
<p class="has-line-data" data-line-start="1786" data-line-end="1787">Creates a security group.</p>
<h5 class="code-line" data-line-start="1787" data-line-end="1788">
<a id="Base_Command_1787"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1789" data-line-end="1790"><code>aws-ec2-create-security-group</code></p>
<h5 class="code-line" data-line-start="1790" data-line-end="1791">
<a id="Input_1790"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>groupName</td>
<td>The name of the security group.</td>
<td>Required</td>
</tr>
<tr>
<td>description</td>
<td>A description for the security group.</td>
<td>Required</td>
</tr>
<tr>
<td>vpcId</td>
<td>The ID of the VPC.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1803" data-line-end="1804">
<a id="Context_Output_1803"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.SecurityGroups.GroupName</td>
<td>string</td>
<td>The name of the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.Description</td>
<td>string</td>
<td>A description for the security group.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.VpcId</td>
<td>string</td>
<td>The ID of the VPC.</td>
</tr>
<tr>
<td>AWS.EC2.SecurityGroups.GroupId</td>
<td>string</td>
<td>The ID of the security group.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1821" data-line-end="1822"> </h5>
<h3 id="h_c69cba7b-87c3-4055-8bcd-db7f70256aab" class="code-line" data-line-start="1824" data-line-end="1825">
<a id="38_awsec2deletesecuritygroup_1824"></a>38. aws-ec2-delete-security-group</h3>
<hr>
<p class="has-line-data" data-line-start="1826" data-line-end="1827">Deletes a security group.</p>
<h5 class="code-line" data-line-start="1827" data-line-end="1828">
<a id="Base_Command_1827"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1829" data-line-end="1830"><code>aws-ec2-delete-security-group</code></p>
<h5 class="code-line" data-line-start="1830" data-line-end="1831">
<a id="Input_1830"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>groupId</td>
<td>The ID of the security group. Required for a nondefault VPC.</td>
<td>Optional</td>
</tr>
<tr>
<td>groupName</td>
<td>default VPC only. The name of the security group. You can specify either the security group name or the security group ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1842" data-line-end="1843">
<a id="Context_Output_1842"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1844" data-line-end="1845">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1854" data-line-end="1855"> </h5>
<h3 id="h_0a05b1ae-c8b7-48eb-a15b-bd13c2ab4a98" class="code-line" data-line-start="1857" data-line-end="1858">
<a id="39_awsec2authorizesecuritygroupingressrule_1857"></a>39. aws-ec2-authorize-security-group-ingress-rule</h3>
<hr>
<p class="has-line-data" data-line-start="1859" data-line-end="1860">Adds ingress rule to a security group.</p>
<h5 class="code-line" data-line-start="1860" data-line-end="1861">
<a id="Base_Command_1860"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1862" data-line-end="1863"><code>aws-ec2-authorize-security-group-ingress-rule</code></p>
<h5 class="code-line" data-line-start="1863" data-line-end="1864">
<a id="Input_1863"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>groupId</td>
<td>The ID of the security group. You must specify either the security group ID or the security group name in the request. For security groups in a nondefault VPC, you must specify the security group ID.</td>
<td>Required</td>
</tr>
<tr>
<td>fromPort</td>
<td>The start of port range for the TCP and UDP protocols.</td>
<td>Optional</td>
</tr>
<tr>
<td>toPort</td>
<td>The end of port range for the TCP and UDP protocols.</td>
<td>Optional</td>
</tr>
<tr>
<td>cidrIp</td>
<td>The CIDR IPv4 address range.</td>
<td>Optional</td>
</tr>
<tr>
<td>ipProtocol</td>
<td>The IP protocol name (tcp , udp , icmp) or number. Use -1 to specify all protocols.</td>
<td>Optional</td>
</tr>
<tr>
<td>sourceSecurityGroupName</td>
<td>The name of the source security group. The source security group must be in the same VPC.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td><span>IpPermissionsfromPort</span></td>
<td><span>The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes.</span></td>
<td>Optional</td>
</tr>
<tr>
<td><span>IpPermissionsIpProtocol</span></td>
<td><span>The IP protocol name (tcp, udp, icmp, icmpv6) or number.</span></td>
<td>Optional</td>
</tr>
<tr>
<td><span>IpPermissionsToPort</span></td>
<td><span>The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes.</span></td>
<td>Optional</td>
</tr>
<tr>
<td><span>IpRangesCidrIp</span></td>
<td><span>The IPv4 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv4 address, use the /32 prefix length.</span></td>
<td>Optional</td>
</tr>
<tr>
<td><span>IpRangesDesc</span></td>
<td>
<p><span>A description for the security group rule that references this IPv4 address range.</span></p>
<p> </p>
<p><span>Limitations: Maximum of 255 characters. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$*</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>Ipv6RangesCidrIp</span></td>
<td>
<p><span>The IPv6 CIDR range. You can either specify a CIDR range or a source security group, not both. To specify a single IPv6 address, use the /128 prefix length.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>Ipv6RangesDesc</span></td>
<td>
<p><span>A description for the security group rule that references this IPv6 address range.</span></p>
<p><span>Limitations: Maximum of 255 characters. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$*</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>PrefixListId</span></td>
<td>
<p><span>The ID of the prefix.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>PrefixListIdDesc</span></td>
<td>
<p><span>A description for the security group rule that references this prefix list ID.</span></p>
<p><span>Limitations: Maximum of 255 characters. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$*</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsDescription</span></td>
<td>
<p><span>A description for the security group rule that references this user ID group pair.</span></p>
<p><span>Limitations: Maximum of 255 characters. Allowed characters are a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=;{}!$*</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsGroupId</span></td>
<td>
<p><span>The ID of the security group.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsGroupName</span></td>
<td>
<p><span>The name of the security group. In a request, use this parameter for a security group in EC2-Classic or a default VPC only. For a security group in a nondefault VPC, use the security group ID.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsPeeringStatus</span></td>
<td>
<p><span>The status of a VPC peering connection, if applicable.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsUserId</span></td>
<td>
<p><span>The ID of an AWS account.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsVpcId</span></td>
<td>
<p><span>The ID of the VPC for the referenced security group, if applicable.</span></p>
</td>
<td>Optional</td>
</tr>
<tr>
<td><span>UserIdGroupPairsVpcPeeringConnectionId</span></td>
<td>
<p><span>The ID of the VPC peering connection, if applicable.</span></p>
</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1879" data-line-end="1880">
<a id="Context_Output_1879"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1881" data-line-end="1882">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1891" data-line-end="1892"> </h5>
<h3 id="h_45db8f57-c6a2-454c-ba78-57c9325a3298" class="code-line" data-line-start="1894" data-line-end="1895">
<a id="40_awsec2revokesecuritygroupingressrule_1894"></a>40. aws-ec2-revoke-security-group-ingress-rule</h3>
<hr>
<p class="has-line-data" data-line-start="1896" data-line-end="1897">Removes egress rule from a security group. To remove a rule, the values that you specify (for example, ports) must match the existing rule’s values exactly.</p>
<h5 class="code-line" data-line-start="1897" data-line-end="1898">
<a id="Base_Command_1897"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1899" data-line-end="1900"><code>aws-ec2-revoke-security-group-ingress-rule</code></p>
<h5 class="code-line" data-line-start="1900" data-line-end="1901">
<a id="Input_1900"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>groupId</td>
<td>The ID of the security group.</td>
<td>Required</td>
</tr>
<tr>
<td>fromPort</td>
<td>The start of port range for the TCP and UDP protocols.</td>
<td>Optional</td>
</tr>
<tr>
<td>toPort</td>
<td>The end of port range for the TCP and UDP protocols.</td>
<td>Optional</td>
</tr>
<tr>
<td>cidrIp</td>
<td>The CIDR IPv4 address range.</td>
<td>Optional</td>
</tr>
<tr>
<td>ipProtocol</td>
<td>The IP protocol name (tcp , udp , icmp) or number. Use -1 to specify all protocols.</td>
<td>Optional</td>
</tr>
<tr>
<td>sourceSecurityGroupName</td>
<td>The name of the source security group. The source security group must be in the same VPC.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1916" data-line-end="1917">
<a id="Context_Output_1916"></a>Context Output</h5>
<p class="has-line-data" data-line-start="1918" data-line-end="1919">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1928" data-line-end="1929"> </h5>
<h3 id="h_22e2dea1-aa5d-46f5-9a85-a49ccc01960a" class="code-line" data-line-start="1931" data-line-end="1932">
<a id="41_awsec2copyimage_1931"></a>41. aws-ec2-copy-image</h3>
<hr>
<p class="has-line-data" data-line-start="1933" data-line-end="1934">Initiates the copy of an AMI from the specified source region to the current region.</p>
<h5 class="code-line" data-line-start="1934" data-line-end="1935">
<a id="Base_Command_1934"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1936" data-line-end="1937"><code>aws-ec2-copy-image</code></p>
<h5 class="code-line" data-line-start="1937" data-line-end="1938">
<a id="Input_1937"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>name</td>
<td>The name of the new AMI in the destination region.</td>
<td>Required</td>
</tr>
<tr>
<td>sourceImageId</td>
<td>The ID of the AMI to copy.</td>
<td>Required</td>
</tr>
<tr>
<td>sourceRegion</td>
<td>The name of the region that contains the AMI to copy.</td>
<td>Required</td>
</tr>
<tr>
<td>description</td>
<td>A description for the new AMI in the destination region.</td>
<td>Optional</td>
</tr>
<tr>
<td>encrypted</td>
<td>Specifies whether the destination snapshots of the copied image should be encrypted. The default CMK for EBS is used unless a non-default AWS Key Management Service (AWS KMS) CMK is specified with KmsKeyId .</td>
<td>Optional</td>
</tr>
<tr>
<td>kmsKeyId</td>
<td>An identifier for the AWS Key Management Service (AWS KMS) customer master key (CMK) to use when creating the encrypted volume. This parameter is only required if you want to use a non-default CMK; if this parameter is not specified, the default CMK for EBS is used. If a KmsKeyId is specified, the Encrypted flag must also be set.</td>
<td>Optional</td>
</tr>
<tr>
<td>clientToken</td>
<td>nique, case-sensitive identifier you provide to ensure idempotency of the request.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1954" data-line-end="1955">
<a id="Context_Output_1954"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Images.ImageId</td>
<td>string</td>
<td>The ID of the new AMI.</td>
</tr>
<tr>
<td>AWS.EC2.Images.Region</td>
<td>string</td>
<td>The Region where the image is located.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1970" data-line-end="1971"> </h5>
<h3 id="h_1e808591-6bb0-42c8-916b-93222287e431" class="code-line" data-line-start="1973" data-line-end="1974">
<a id="42_awsec2copysnapshot_1973"></a>42. aws-ec2-copy-snapshot</h3>
<hr>
<p class="has-line-data" data-line-start="1975" data-line-end="1976">Copies a point-in-time snapshot of an EBS volume and stores it in Amazon S3. You can copy the snapshot within the same region or from one region to another.</p>
<h5 class="code-line" data-line-start="1976" data-line-end="1977">
<a id="Base_Command_1976"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1978" data-line-end="1979"><code>aws-ec2-copy-snapshot</code></p>
<h5 class="code-line" data-line-start="1979" data-line-end="1980">
<a id="Input_1979"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>sourceSnapshotId</td>
<td>The ID of the EBS snapshot to copy.</td>
<td>Required</td>
</tr>
<tr>
<td>sourceRegion</td>
<td>The ID of the region that contains the snapshot to be copied.</td>
<td>Required</td>
</tr>
<tr>
<td>description</td>
<td>A description for the EBS snapshot.</td>
<td>Optional</td>
</tr>
<tr>
<td>encrypted</td>
<td>Specifies whether the destination snapshot should be encrypted. You can encrypt a copy of an unencrypted snapshot using this flag, but you cannot use it to create an unencrypted copy from an encrypted snapshot. Your default CMK for EBS is used unless a non-default AWS Key Management Service (AWS KMS) CMK is specified with KmsKeyId .</td>
<td>Optional</td>
</tr>
<tr>
<td>kmsKeyId</td>
<td>An identifier for the AWS Key Management Service (AWS KMS) customer master key (CMK) to use when creating the encrypted volume. This parameter is only required if you want to use a non-default CMK; if this parameter is not specified, the default CMK for EBS is used. If a KmsKeyId is specified, the Encrypted flag must also be set.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1994" data-line-end="1995">
<a id="Context_Output_1994"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Snapshots.SnapshotId</td>
<td>string</td>
<td>The ID of the new snapshot.</td>
</tr>
<tr>
<td>AWS.EC2.Snapshots.Region</td>
<td>string</td>
<td>The Region where the snapshot is located.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2010" data-line-end="2011"> </h5>
<h3 id="h_2c71e87b-e10f-4394-865c-687aeeadf48e" class="code-line" data-line-start="2013" data-line-end="2014">
<a id="43_awsec2describereservedinstances_2013"></a>43. aws-ec2-describe-reserved-instances</h3>
<hr>
<p class="has-line-data" data-line-start="2015" data-line-end="2016">Describes one or more of the Reserved Instances that you purchased.</p>
<h5 class="code-line" data-line-start="2016" data-line-end="2017">
<a id="Base_Command_2016"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2018" data-line-end="2019"><code>aws-ec2-describe-reserved-instances</code></p>
<h5 class="code-line" data-line-start="2019" data-line-end="2020">
<a id="Input_2019"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>filters</td>
<td>ne or more filters.</td>
<td>Optional</td>
</tr>
<tr>
<td>reservedInstancesIds</td>
<td>One or more Reserved Instance IDs. Separated by comma.</td>
<td>Optional</td>
</tr>
<tr>
<td>offeringClass</td>
<td>Describes whether the Reserved Instance is Standard or Convertible.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2032" data-line-end="2033">
<a id="Context_Output_2032"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.ReservedInstances.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone in which the Reserved Instance can be used.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.Duration</td>
<td>number</td>
<td>The duration of the Reserved Instance, in seconds.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.End</td>
<td>date</td>
<td>The time when the Reserved Instance expires.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.FixedPrice</td>
<td>number</td>
<td>The purchase price of the Reserved Instance.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.InstanceCount</td>
<td>number</td>
<td>The number of reservations purchased.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.InstanceType</td>
<td>string</td>
<td>The instance type on which the Reserved Instance can be used.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.ProductDescription</td>
<td>string</td>
<td>The Reserved Instance product platform description.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.ReservedInstancesId</td>
<td>string</td>
<td>The ID of the Reserved Instance.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.Start</td>
<td>date</td>
<td>The date and time the Reserved Instance started.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.State</td>
<td>string</td>
<td>The state of the Reserved Instance purchase.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.UsagePrice</td>
<td>number</td>
<td>The usage price of the Reserved Instance, per hour.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.CurrencyCode</td>
<td>string</td>
<td>The currency of the Reserved Instance. It’s specified using ISO 4217 standard currency codes. At this time, the only supported currency is USD .</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.InstanceTenancy</td>
<td>string</td>
<td>The tenancy of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.OfferingClass</td>
<td>string</td>
<td>The offering class of the Reserved Instance.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.OfferingType</td>
<td>string</td>
<td>The Reserved Instance offering type.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.RecurringCharges.Amount</td>
<td>number</td>
<td>The amount of the recurring charge.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.RecurringCharges.Frequency</td>
<td>string</td>
<td>he frequency of the recurring charge.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.Scope</td>
<td>string</td>
<td>The scope of the Reserved Instance.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.ReservedInstances.Region</td>
<td>string</td>
<td>The AWS region where the reserved instance is located.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2067" data-line-end="2068"> </h5>
<h3 id="h_3531fdba-0b40-420d-b77c-957db90d16be" class="code-line" data-line-start="2070" data-line-end="2071">
<a id="44_awsec2monitorinstances_2070"></a>44. aws-ec2-monitor-instances</h3>
<hr>
<p class="has-line-data" data-line-start="2072" data-line-end="2073">Enables detailed monitoring for a running instance.</p>
<h5 class="code-line" data-line-start="2073" data-line-end="2074">
<a id="Base_Command_2073"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2075" data-line-end="2076"><code>aws-ec2-monitor-instances</code></p>
<h5 class="code-line" data-line-start="2076" data-line-end="2077">
<a id="Input_2076"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instancesIds</td>
<td>One or more instance IDs. Separated by comma.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2087" data-line-end="2088">
<a id="Context_Output_2087"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Instances.InstanceId</td>
<td>string</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Monitoring.State</td>
<td>string</td>
<td>Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2103" data-line-end="2104"> </h5>
<h3 id="h_289130de-2a2e-403a-a108-93b9d7a4d17c" class="code-line" data-line-start="2106" data-line-end="2107">
<a id="45_awsec2unmonitorinstances_2106"></a>45. aws-ec2-unmonitor-instances</h3>
<hr>
<p class="has-line-data" data-line-start="2108" data-line-end="2109">Disables detailed monitoring for a running instance.</p>
<h5 class="code-line" data-line-start="2109" data-line-end="2110">
<a id="Base_Command_2109"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2111" data-line-end="2112"><code>aws-ec2-unmonitor-instances</code></p>
<h5 class="code-line" data-line-start="2112" data-line-end="2113">
<a id="Input_2112"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instancesIds</td>
<td>One or more instance IDs. Separated by comma.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2123" data-line-end="2124">
<a id="Context_Output_2123"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Instances.InstanceId</td>
<td>Unknown</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.Monitoring.State</td>
<td>Unknown</td>
<td>Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2139" data-line-end="2140"> </h5>
<h3 id="h_f6767e06-06e2-42d9-ac65-a985f86b0c65" class="code-line" data-line-start="2142" data-line-end="2143">
<a id="46_awsec2rebootinstances_2142"></a>46. aws-ec2-reboot-instances</h3>
<hr>
<p class="has-line-data" data-line-start="2144" data-line-end="2145">Requests a reboot of one or more instances. This operation is asynchronous; it only queues a request to reboot the specified instances. The operation succeeds if the instances are valid and belong to you. Requests to reboot terminated instances are ignored. If an instance does not cleanly shut down within four minutes, Amazon EC2 performs a hard reboot.</p>
<h5 class="code-line" data-line-start="2145" data-line-end="2146">
<a id="Base_Command_2145"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2147" data-line-end="2148"><code>aws-ec2-reboot-instances</code></p>
<h5 class="code-line" data-line-start="2148" data-line-end="2149">
<a id="Input_2148"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instanceIds</td>
<td>One or more instance IDs. Separated by comma.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2159" data-line-end="2160">
<a id="Context_Output_2159"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2161" data-line-end="2162">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2171" data-line-end="2172"> </h5>
<h3 id="h_0b4efed1-6f64-4e62-bcdb-f00d18ac7309" class="code-line" data-line-start="2174" data-line-end="2175">
<a id="47_awsec2getpassworddata_2174"></a>47. aws-ec2-get-password-data</h3>
<hr>
<p class="has-line-data" data-line-start="2176" data-line-end="2177">Retrieves the encrypted administrator password for a running Windows instance.</p>
<h5 class="code-line" data-line-start="2177" data-line-end="2178">
<a id="Base_Command_2177"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2179" data-line-end="2180"><code>aws-ec2-get-password-data</code></p>
<h5 class="code-line" data-line-start="2180" data-line-end="2181">
<a id="Input_2180"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instanceId</td>
<td>The ID of the Windows instance.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2191" data-line-end="2192">
<a id="Context_Output_2191"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Instances.PasswordData.PasswordData</td>
<td>string</td>
<td>The password of the instance. Returns an empty string if the password is not available.</td>
</tr>
<tr>
<td>AWS.EC2.Instances.PasswordData.Timestamp</td>
<td>date</td>
<td>The time the data was last updated.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_9818b9bd-6fdf-49b4-a47e-cbab40082d0f" class="code-line" data-line-start="2210" data-line-end="2211">
<a id="48_awsec2modifynetworkinterfaceattribute_2210"></a>48. aws-ec2-modify-network-interface-attribute</h3>
<hr>
<p class="has-line-data" data-line-start="2212" data-line-end="2213">Modifies the specified network interface attribute. You can specify only one attribute at a time.</p>
<h5 class="code-line" data-line-start="2213" data-line-end="2214">
<a id="Base_Command_2213"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2215" data-line-end="2216"><code>aws-ec2-modify-network-interface-attribute</code></p>
<h5 class="code-line" data-line-start="2216" data-line-end="2217">
<a id="Input_2216"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>networkInterfaceId</td>
<td>The ID of the network interface.</td>
<td>Required</td>
</tr>
<tr>
<td>groups</td>
<td>Changes the security groups for the network interface. The new set of groups you specify replaces the current set. You must specify at least one group, even if it’s just the default security group in the VPC. You must specify the ID of the security group, not the name.</td>
<td>Optional</td>
</tr>
<tr>
<td>sourceDestCheck</td>
<td>Indicates whether source/destination checking is enabled. A value of true means checking is enabled, and false means checking is disabled. This value must be false for a NAT instance to perform NAT.</td>
<td>Optional</td>
</tr>
<tr>
<td>description</td>
<td>A description for the network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>attachmentId</td>
<td>The ID of the network interface attachment. Information about the interface attachment. If modifying the ‘delete on termination’ attribute, you must specify the ID of the interface attachment.</td>
<td>Optional</td>
</tr>
<tr>
<td>deleteOnTermination</td>
<td>Indicates whether the network interface is deleted when the instance is terminated. Information about the interface attachment. If modifying the ‘delete on termination’ attribute, you must specify the ID of the interface attachment.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2232" data-line-end="2233">
<a id="Context_Output_2232"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2234" data-line-end="2235">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2244" data-line-end="2245"> </h5>
<h3 id="h_537a6056-f26a-4d8c-bb6a-8e20a0a2f655" class="code-line" data-line-start="2247" data-line-end="2248">
<a id="49_awsec2modifyinstanceattribute_2247"></a>49. aws-ec2-modify-instance-attribute</h3>
<hr>
<p class="has-line-data" data-line-start="2249" data-line-end="2250">Modifies the specified attribute of the specified instance. You can specify only one attribute at a time. Using this action to change the security groups associated with an elastic network interface (ENI) attached to an instance in a VPC can result in an error if the instance has more than one ENI. To change the security groups associated with an ENI attached to an instance that has multiple ENIs, we recommend that you use the ModifyNetworkInterfaceAttribute action.</p>
<h5 class="code-line" data-line-start="2250" data-line-end="2251">
<a id="Base_Command_2250"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2252" data-line-end="2253"><code>aws-ec2-modify-instance-attribute</code></p>
<h5 class="code-line" data-line-start="2253" data-line-end="2254">
<a id="Input_2253"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>instanceId</td>
<td>The ID of the instance.</td>
<td>Required</td>
</tr>
<tr>
<td>sourceDestCheck</td>
<td>Specifies whether source/destination checking is enabled. A value of true means that checking is enabled, and false means that checking is disabled. This value must be false for a NAT instance to perform NAT.</td>
<td>Optional</td>
</tr>
<tr>
<td>disableApiTermination</td>
<td>If the value is true , you can’t terminate the instance using the Amazon EC2 console, CLI, or API; otherwise, you can. You cannot use this parameter for Spot Instances.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsOptimized</td>
<td>Specifies whether the instance is optimized for Amazon EBS I/O. This optimization provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal EBS I/O performance. This optimization isn’t available with all instance types. Additional usage charges apply when using an EBS Optimized instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>enaSupport</td>
<td>Set to true to enable enhanced networking with ENA for the instance. This option is supported only for HVM instances. Specifying this option with a PV instance can make it unreachable.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceType</td>
<td>Changes the instance type to the specified value.</td>
<td>Optional</td>
</tr>
<tr>
<td>instanceInitiatedShutdownBehavior</td>
<td>Specifies whether an instance stops or terminates when you initiate shutdown from the instance (using the operating system command for system shutdown)</td>
<td>Optional</td>
</tr>
<tr>
<td>groups</td>
<td>[EC2-VPC] Changes the security groups of the instance. You must specify at least one security group, even if it’s just the default security group for the VPC. You must specify the security group ID, not the security group name.</td>
<td>Optional</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2271" data-line-end="2272">
<a id="Context_Output_2271"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2273" data-line-end="2274">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2283" data-line-end="2284"> </h5>
<h3 id="h_ad4f24a8-856b-4086-911c-cbef0fb5342b" class="code-line" data-line-start="2286" data-line-end="2287">
<a id="50_awsec2createnetworkacl_2286"></a>50. aws-ec2-create-network-acl</h3>
<hr>
<p class="has-line-data" data-line-start="2288" data-line-end="2289">Creates a network ACL in a VPC. Network ACLs provide an optional layer of security (in addition to security groups) for the instances in your VPC.</p>
<h5 class="code-line" data-line-start="2289" data-line-end="2290">
<a id="Base_Command_2289"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2291" data-line-end="2292"><code>aws-ec2-create-network-acl</code></p>
<h5 class="code-line" data-line-start="2292" data-line-end="2293">
<a id="Input_2292"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>DryRun</td>
<td>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response.</td>
<td>Optional</td>
</tr>
<tr>
<td>VpcId</td>
<td>The ID of the VPC.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2304" data-line-end="2305">
<a id="Context_Output_2304"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Associations.NetworkAclAssociationId</td>
<td>String</td>
<td>The ID of the association between a network ACL and a subnet.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Associations.NetworkAclId</td>
<td>String</td>
<td>The ID of the network ACL.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Associations.SubnetId</td>
<td>String</td>
<td>The ID of the subnet.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.CidrBlock</td>
<td>String</td>
<td>The IPv4 network range to allow or deny, in CIDR notation.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.Egress</td>
<td>Boolean</td>
<td>Indicates whether the rule is an egress rule (applied to traffic leaving the subnet).</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.IcmpTypeCode.Code</td>
<td>Number</td>
<td>The ICMP code. A value of -1 means all codes for the specified ICMP type.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.IcmpTypeCode.Type</td>
<td>Number</td>
<td>The ICMP type. A value of -1 means all types.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.Ipv6CidrBlock</td>
<td>String</td>
<td>The IPv6 network range to allow or deny, in CIDR notation.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.PortRange.From</td>
<td>Number</td>
<td>The first port in the range.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.PortRange.To</td>
<td>Number</td>
<td>The last port in the range.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.Protocol</td>
<td>String</td>
<td>The protocol number. A value of “-1” means all protocols.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.RuleAction</td>
<td>String</td>
<td>Indicates whether to allow or deny the traffic that matches the rule.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Entries.RuleNumber</td>
<td>Number</td>
<td>The rule number for the entry. ACL entries are processed in ascending order by rule number.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.NetworkAclId</td>
<td>String</td>
<td>The ID of the network ACL.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Tags.Key</td>
<td>String</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.Tags.Value</td>
<td>String</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.VpcId</td>
<td>String</td>
<td>The ID of the VPC for the network ACL.</td>
</tr>
<tr>
<td>AWS.EC2.VpcId.NetworkAcl.OwnerId</td>
<td>String</td>
<td>The ID of the AWS account that owns the network ACL.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2336" data-line-end="2337"> </h5>
<h3 id="h_73e1bc5c-5bff-41e5-90c2-cc676f64d814" class="code-line" data-line-start="2339" data-line-end="2340">
<a id="51_awsec2createnetworkaclentry_2339"></a>51. aws-ec2-create-network-acl-entry</h3>
<hr>
<p class="has-line-data" data-line-start="2341" data-line-end="2342">Creates an entry (a rule) in a network ACL with the specified rule number.</p>
<h5 class="code-line" data-line-start="2342" data-line-end="2343">
<a id="Base_Command_2342"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2344" data-line-end="2345"><code>aws-ec2-create-network-acl-entry</code></p>
<h5 class="code-line" data-line-start="2345" data-line-end="2346">
<a id="Input_2345"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>CidrBlock</td>
<td>The IPv4 network range to allow or deny, in CIDR notation (for example 172.16.0.0/24 ).</td>
<td>Optional</td>
</tr>
<tr>
<td>DryRun</td>
<td>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response.</td>
<td>Optional</td>
</tr>
<tr>
<td>Egress</td>
<td>Indicates whether this is an egress rule (rule is applied to traffic leaving the subnet).</td>
<td>Required</td>
</tr>
<tr>
<td>Code</td>
<td>The ICMP code. A value of -1 means all codes for the specified ICMP type.</td>
<td>Optional</td>
</tr>
<tr>
<td>Type</td>
<td>The ICMP type. A value of -1 means all types.</td>
<td>Optional</td>
</tr>
<tr>
<td>Ipv6CidrBlock</td>
<td>The IPv6 network range to allow or deny, in CIDR notation (for example 2001:db8:1234:1a00::/64 ).</td>
<td>Optional</td>
</tr>
<tr>
<td>NetworkAclId</td>
<td>The ID of the network ACL.</td>
<td>Required</td>
</tr>
<tr>
<td>From</td>
<td>The first port in the range.</td>
<td>Optional</td>
</tr>
<tr>
<td>To</td>
<td>The last port in the range.</td>
<td>Optional</td>
</tr>
<tr>
<td>Protocol</td>
<td>The protocol number. A value of “-1” means all protocols. If you specify “-1” or a protocol number other than “6” (TCP), “17” (UDP), or “1” (ICMP), traffic on all ports is allowed, regardless of any ports or ICMP types or codes that you specify. If you specify protocol “58” (ICMPv6) and specify an IPv4 CIDR block, traffic for all ICMP types and codes allowed, regardless of any that you specify. If you specify protocol “58” (ICMPv6) and specify an IPv6 CIDR block, you must specify an ICMP type and code.</td>
<td>Required</td>
</tr>
<tr>
<td>RuleAction</td>
<td>Indicates whether to allow or deny the traffic that matches the rule.</td>
<td>Required</td>
</tr>
<tr>
<td>RuleNumber</td>
<td>The rule number for the entry (for example, 100). ACL entries are processed in ascending order by rule number.</td>
<td>Required</td>
</tr>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2367" data-line-end="2368">
<a id="Context_Output_2367"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2369" data-line-end="2370">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2379" data-line-end="2380"> </h5>
<h3 id="h_9e7a1fb6-9f56-4a16-afba-c90a752c5c52" class="code-line" data-line-start="2382" data-line-end="2383">
<a id="52_awsec2createfleet_2382"></a>52. aws-ec2-create-fleet</h3>
<hr>
<p class="has-line-data" data-line-start="2384" data-line-end="2385">Launches an EC2 Fleet.</p>
<h5 class="code-line" data-line-start="2385" data-line-end="2386">
<a id="Base_Command_2385"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2387" data-line-end="2388"><code>aws-ec2-create-fleet</code></p>
<h5 class="code-line" data-line-start="2388" data-line-end="2389">
<a id="Input_2388"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>DryRun</td>
<td>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response.</td>
<td>Optional</td>
</tr>
<tr>
<td>ClientToken</td>
<td>Unique, case-sensitive identifier you provide to ensure the idempotency of the request.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotAllocationStrategy</td>
<td>Indicates how to allocate the target capacity across the Spot pools specified by the Spot Fleet request.</td>
<td>Optional</td>
</tr>
<tr>
<td>InstanceInterruptionBehavior</td>
<td>The behavior when a Spot Instance is interrupted.</td>
<td>Optional</td>
</tr>
<tr>
<td>InstancePoolsToUseCount</td>
<td>The number of Spot pools across which to allocate your target Spot capacity.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotSingleInstanceType</td>
<td>Indicates that the fleet uses a single instance type to launch all Spot Instances in the fleet.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotSingleInstanceType</td>
<td>Indicates that the fleet launches all Spot Instances into a single Availability Zone.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotMinTargetCapacity</td>
<td>The minimum target capacity for Spot Instances in the fleet. If the minimum target capacity is not reached, the fleet launches no instances.</td>
<td>Optional</td>
</tr>
<tr>
<td>OnDemandAllocationStrategy</td>
<td>The order of the launch template overrides to use in fulfilling On-Demand capacity.</td>
<td>Optional</td>
</tr>
<tr>
<td>OnDemandSingleInstanceType</td>
<td>Indicates that the fleet uses a single instance type to launch all On-Demand Instances in the fleet.</td>
<td>Optional</td>
</tr>
<tr>
<td>OnDemandSingleAvailabilityZone</td>
<td>Indicates that the fleet launches all On-Demand Instances into a single Availability Zone.</td>
<td>Optional</td>
</tr>
<tr>
<td>OnDemandMinTargetCapacity</td>
<td>The minimum target capacity for On-Demand Instances in the fleet. If the minimum target capacity is not reached, the fleet launches no instances.</td>
<td>Optional</td>
</tr>
<tr>
<td>ExcessCapacityTerminationPolicy</td>
<td>Indicates whether running instances should be terminated if the total target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchTemplateId</td>
<td>The ID of the launch template.</td>
<td>Required</td>
</tr>
<tr>
<td>LaunchTemplateName</td>
<td>The name of the launch template.</td>
<td>Required</td>
</tr>
<tr>
<td>Version</td>
<td>The version number of the launch template.</td>
<td>Required</td>
</tr>
<tr>
<td>OverrideInstanceType</td>
<td>The instance type.</td>
<td>Optional</td>
</tr>
<tr>
<td>OverrideMaxPrice</td>
<td>The maximum price per unit hour that you are willing to pay for a Spot Instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>OverrideSubnetId</td>
<td>The ID of the subnet in which to launch the instances.</td>
<td>Optional</td>
</tr>
<tr>
<td>OverrideAvailabilityZone</td>
<td>The Availability Zone in which to launch the instances.</td>
<td>Optional</td>
</tr>
<tr>
<td>OverrideWeightedCapacity</td>
<td>The number of units provided by the specified instance type.</td>
<td>Optional</td>
</tr>
<tr>
<td>OverridePriority</td>
<td>The priority for the launch template override.</td>
<td>Optional</td>
</tr>
<tr>
<td>TotalTargetCapacity</td>
<td>The number of units to request, filled using DefaultTargetCapacityType .</td>
<td>Required</td>
</tr>
<tr>
<td>OnDemandTargetCapacity</td>
<td>The number of On-Demand units to request.</td>
<td>Required</td>
</tr>
<tr>
<td>SpotTargetCapacity</td>
<td>The number of Spot units to request.</td>
<td>Required</td>
</tr>
<tr>
<td>DefaultTargetCapacityType</td>
<td>The default TotalTargetCapacity, which is either Spot or On-Demand .</td>
<td>Required</td>
</tr>
<tr>
<td>Type</td>
<td>The type of the request.</td>
<td>Optional</td>
</tr>
<tr>
<td>ValidFrom</td>
<td>The start date and time of the request, in UTC format (for example, YYYY -MM -DD T<em>HH</em>:MM :SS Z).</td>
<td>Optional</td>
</tr>
<tr>
<td>ValidUntil</td>
<td>The end date and time of the request, in UTC format (for example, YYYY -MM -DD T<em>HH</em><span> </span>:MM :SS Z).</td>
<td>Optional</td>
</tr>
<tr>
<td>ReplaceUnhealthyInstances</td>
<td>Indicates whether EC2 Fleet should replace unhealthy instances.</td>
<td>Optional</td>
</tr>
<tr>
<td>Tags</td>
<td>The tags to apply to the resource.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2429" data-line-end="2430">
<a id="Context_Output_2429"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Fleet.FleetId</td>
<td>String</td>
<td>The ID of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Errors</td>
<td>String</td>
<td>Information about the instances that could not be launched by the fleet. Valid only when Type is set to instant.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId</td>
<td>String</td>
<td>The ID of the launch template. You must specify either a template ID or a template name.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName</td>
<td>String</td>
<td>The name of the launch template. You must specify either a template name or a template ID.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version</td>
<td>String</td>
<td>The version number of the launch template. You must specify a version number.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.InstanceType</td>
<td>String</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.MaxPrice</td>
<td>String</td>
<td>The maximum price per unit hour that you are willing to pay for a Spot Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.SubnetId</td>
<td>String</td>
<td>The ID of the subnet in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.AvailabilityZone</td>
<td>String</td>
<td>The Availability Zone in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.WeightedCapacity</td>
<td>String</td>
<td>The number of units provided by the specified instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.Priority</td>
<td>String</td>
<td>The priority for the launch template override.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Overrides.Placement.GroupName</td>
<td>String</td>
<td>The name of the placement group the instance is in.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.Lifecycle</td>
<td>String</td>
<td>Indicates if the instance that could not be launched was a Spot Instance or On-Demand Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.ErrorCode</td>
<td>String</td>
<td>The error code that indicates why the instance could not be launched.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.LaunchTemplateAndOverrides.ErrorMessage</td>
<td>String</td>
<td>The error message that describes why the instance could not be launched.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId</td>
<td>String</td>
<td>The ID of the launch template. You must specify either a template ID or a template name.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName</td>
<td>String</td>
<td>The name of the launch template. You must specify either a template name or a template ID.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version</td>
<td>String</td>
<td>The version number of the launch template. You must specify a version number.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.InstanceType</td>
<td>String</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.MaxPrice</td>
<td>String</td>
<td>The maximum price per unit hour that you are willing to pay for a Spot Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.SubnetId</td>
<td>String</td>
<td>The ID of the subnet in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.AvailabilityZone</td>
<td>String</td>
<td>The Availability Zone in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.WeightedCapacity</td>
<td>Number</td>
<td>The number of units provided by the specified instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Priority</td>
<td>Number</td>
<td>The priority for the launch template override.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Placement.GroupName</td>
<td>String</td>
<td>The name of the placement group the instance is in.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Lifecycle</td>
<td>String</td>
<td>Indicates if the instance that was launched is a Spot Instance or On-Demand Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.InstanceIds</td>
<td>String</td>
<td>The IDs of the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.InstanceType</td>
<td>String</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Instances.LaunchTemplateAndOverrides.Overrides.Platform</td>
<td>String</td>
<td>The value is Windows for Windows instances; otherwise blank.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2472" data-line-end="2473"> </h5>
<h3 id="h_371493a2-3f6d-4754-98b5-f71136c1bdb6" class="code-line" data-line-start="2475" data-line-end="2476">
<a id="53_awsec2deletefleet_2475"></a>53. aws-ec2-delete-fleet</h3>
<hr>
<p class="has-line-data" data-line-start="2477" data-line-end="2478">Deletes the specified EC2 Fleet.</p>
<h5 class="code-line" data-line-start="2478" data-line-end="2479">
<a id="Base_Command_2478"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2480" data-line-end="2481"><code>aws-ec2-delete-fleet</code></p>
<h5 class="code-line" data-line-start="2481" data-line-end="2482">
<a id="Input_2481"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>DryRun</td>
<td>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response.</td>
<td>Optional</td>
</tr>
<tr>
<td>FleetIds</td>
<td>The IDs of the EC2 Fleets.</td>
<td>Required</td>
</tr>
<tr>
<td>TerminateInstances</td>
<td>Indicates whether to terminate instances for an EC2 Fleet if it is deleted successfully.</td>
<td>Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2494" data-line-end="2495">
<a id="Context_Output_2494"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.CurrentFleetState</td>
<td>String</td>
<td>The current state of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.PreviousFleetState</td>
<td>String</td>
<td>The previous state of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedFleets.SuccessfulFleetDeletions.FleetId</td>
<td>String</td>
<td>The ID of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.Error.Code</td>
<td>String</td>
<td>The error code.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.Error.Message</td>
<td>String</td>
<td>The description for the error code.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedFleets.UnsuccessfulFleetDeletions.FleetId</td>
<td>String</td>
<td>The ID of the EC2 Fleet.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2514" data-line-end="2515"> </h5>
<h3 id="h_fee42e8b-17c9-4464-aefc-661b692c49f8" class="code-line" data-line-start="2517" data-line-end="2518">
<a id="54_awsec2describefleets_2517"></a>54. aws-ec2-describe-fleets</h3>
<hr>
<p class="has-line-data" data-line-start="2519" data-line-end="2520">Describes one or more of your EC2 Fleets.</p>
<h5 class="code-line" data-line-start="2520" data-line-end="2521">
<a id="Base_Command_2520"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2522" data-line-end="2523"><code>aws-ec2-describe-fleets</code></p>
<h5 class="code-line" data-line-start="2523" data-line-end="2524">
<a id="Input_2523"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>filters</td>
<td>One or more filters.</td>
<td>Optional</td>
</tr>
<tr>
<td>FleetIds</td>
<td>The ID of the EC2 Fleets.</td>
<td>Optional</td>
</tr>
<tr>
<td>MaxResults</td>
<td>The maximum number of results to return in a single call. Specify a value between 1 and 1000.</td>
<td>Optional</td>
</tr>
<tr>
<td>NextToken</td>
<td>The token for the next set of results.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2537" data-line-end="2538">
<a id="Context_Output_2537"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Fleet.NextToken</td>
<td>string</td>
<td>The token for the next set of results.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.ActivityStatus</td>
<td>string</td>
<td>The progress of the EC2 Fleet. If there is an error, the status is error .</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.CreateTime</td>
<td>date</td>
<td>The creation date and time of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.FleetId</td>
<td>string</td>
<td>The ID of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.FleetState</td>
<td>string</td>
<td>The state of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.ClientToken</td>
<td>string</td>
<td>Unique, case-sensitive identifier you provide to ensure the idempotency of the request.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.ExcessCapacityTerminationPolicy</td>
<td>string</td>
<td>Indicates whether running instances should be terminated if the target capacity of the EC2 Fleet is decreased below the current size of the EC2 Fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.FulfilledCapacity</td>
<td>number</td>
<td>The number of units fulfilled by this request compared to the set target capacity.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.FulfilledOnDemandCapacity</td>
<td>number</td>
<td>The number of units fulfilled by this request compared to the set target On-Demand capacity.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.LaunchTemplateId</td>
<td>string</td>
<td>The ID of the launch template. You must specify either a template ID or a template name.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.LaunchTemplateName</td>
<td>string</td>
<td>The name of the launch template. You must specify either a template name or a template ID.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Version</td>
<td>string</td>
<td>The version number of the launch template. You must specify a version number.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.InstanceType</td>
<td>string</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.MaxPrice</td>
<td>string</td>
<td>The maximum price per unit hour that you are willing to pay for a Spot Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.SubnetId</td>
<td>string</td>
<td>The ID of the subnet in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.WeightedCapacity</td>
<td>number</td>
<td>The number of units provided by the specified instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.Priority</td>
<td>number</td>
<td>The priority for the launch template override.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.LaunchTemplateConfigs.LaunchTemplateSpecification.Overrides.Placement.GroupName</td>
<td>string</td>
<td>The name of the placement group the instance is in.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.TotalTargetCapacity</td>
<td>number</td>
<td>The number of units to request, filled using DefaultTargetCapacityType .</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.OnDemandTargetCapacity</td>
<td>number</td>
<td>The number of On-Demand units to request.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.SpotTargetCapacity</td>
<td>number</td>
<td>The maximum number of Spot units to launch.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.TargetCapacitySpecification.DefaultTargetCapacityType</td>
<td>string</td>
<td>The default TotalTargetCapacity , which is either Spot or On-Demand.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.TerminateInstancesWithExpiration</td>
<td>boolean</td>
<td>Indicates whether running instances should be terminated when the EC2 Fleet expires.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Type</td>
<td>string</td>
<td>The type of request. Indicates whether the EC2 Fleet only requests the target capacity, or also attempts to maintain it.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.ValidFrom</td>
<td>date</td>
<td>The start date and time of the request, in UTC format (for example, YYYY -MM -DD T<em>HH</em><span> </span>:MM :SS Z).</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.ValidUntil</td>
<td>date</td>
<td>The end date and time of the request, in UTC format (for example, YYYY -MM -DD T<em>HH</em><span> </span>:MM :SS Z).</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.ReplaceUnhealthyInstances</td>
<td>boolean</td>
<td>Indicates whether EC2 Fleet should replace unhealthy instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.SpotOptions.AllocationStrategy</td>
<td>string</td>
<td>Indicates how to allocate the target capacity across the Spot pools specified by the Spot Fleet request.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.SpotOptions.InstanceInterruptionBehavior</td>
<td>string</td>
<td>The behavior when a Spot Instance is interrupted. The default is terminate.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.SpotOptions.InstancePoolsToUseCount</td>
<td>number</td>
<td>The number of Spot pools across which to allocate your target Spot capacity.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.SpotOptions.SingleInstanceType</td>
<td>boolean</td>
<td>Indicates that the fleet uses a single instance type to launch all Spot Instances in the fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.SpotOptions.SingleAvailabilityZone</td>
<td>boolean</td>
<td>Indicates that the fleet launches all Spot Instances into a single Availability Zone.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.SpotOptions.MinTargetCapacity</td>
<td>number</td>
<td>The minimum target capacity for Spot Instances in the fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.OnDemandOptions.AllocationStrategy</td>
<td>string</td>
<td>The order of the launch template overrides to use in fulfilling On-Demand capacity.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.OnDemandOptions.SingleInstanceType</td>
<td>boolean</td>
<td>Indicates that the fleet uses a single instance type to launch all On-Demand Instances in the fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.OnDemandOptions.SingleAvailabilityZone</td>
<td>boolean</td>
<td>Indicates that the fleet launches all On-Demand Instances into a single Availability Zone.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.OnDemandOptions.MinTargetCapacity</td>
<td>number</td>
<td>The minimum target capacity for On-Demand Instances in the fleet.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Tags.Key</td>
<td>string</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Tags.Value</td>
<td>string</td>
<td>The value of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId</td>
<td>string</td>
<td>The ID of the launch template. You must specify either a template ID or a template name.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName</td>
<td>string</td>
<td>The name of the launch template. You must specify either a template name or a template ID.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version</td>
<td>string</td>
<td>The version number of the launch template. You must specify a version number.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.InstanceType</td>
<td>string</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.MaxPrice</td>
<td>string</td>
<td>The maximum price per unit hour that you are willing to pay for a Spot Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.SubnetId</td>
<td>string</td>
<td>The ID of the subnet in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.WeightedCapacity</td>
<td>number</td>
<td>The number of units provided by the specified instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.Priority</td>
<td>number</td>
<td>The priority for the launch template override.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Overrides.Placement.GroupName</td>
<td>string</td>
<td>The name of the placement group the instance is in.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.Lifecycle</td>
<td>string</td>
<td>Indicates if the instance that could not be launched was a Spot Instance or On-Demand Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.ErrorCode</td>
<td>string</td>
<td>The error code that indicates why the instance could not be launched.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Errors.ErrorMessage</td>
<td>string</td>
<td>The error message that describes why the instance could not be launched.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateId</td>
<td>string</td>
<td>The ID of the launch template. You must specify either a template ID or a template name.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.LaunchTemplateName</td>
<td>string</td>
<td>The name of the launch template. You must specify either a template name or a template ID.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.LaunchTemplateSpecification.Version</td>
<td>string</td>
<td>The version number of the launch template. You must specify a version number.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.InstanceType</td>
<td>string</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.MaxPrice</td>
<td>string</td>
<td>The maximum price per unit hour that you are willing to pay for a Spot Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.SubnetId</td>
<td>string</td>
<td>The ID of the subnet in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.AvailabilityZone</td>
<td>string</td>
<td>The Availability Zone in which to launch the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.WeightedCapacity</td>
<td>number</td>
<td>The number of units provided by the specified instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.Priority</td>
<td>number</td>
<td>The priority for the launch template override.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.LaunchTemplateAndOverrides.Overrides.Placement.GroupName</td>
<td>string</td>
<td>The name of the placement group the instance is in.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.Lifecycle</td>
<td>string</td>
<td>Indicates if the instance that was launched is a Spot Instance or On-Demand Instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.InstanceIds</td>
<td>string</td>
<td>The IDs of the instances.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.InstanceType</td>
<td>string</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.Fleets.Instances.Platform</td>
<td>string</td>
<td>The value is Windows for Windows instances; otherwise blank.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2618" data-line-end="2619"> </h5>
<h3 id="h_1e2a78da-d345-4e4c-bcb1-19a97d1e51f8" class="code-line" data-line-start="2621" data-line-end="2622">
<a id="55_awsec2describefleetinstances_2621"></a>55. aws-ec2-describe-fleet-instances</h3>
<hr>
<p class="has-line-data" data-line-start="2623" data-line-end="2624">Describes the running instances for the specified EC2 Fleet.</p>
<h5 class="code-line" data-line-start="2624" data-line-end="2625">
<a id="Base_Command_2624"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2626" data-line-end="2627"><code>aws-ec2-describe-fleet-instances</code></p>
<h5 class="code-line" data-line-start="2627" data-line-end="2628">
<a id="Input_2627"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>filters</td>
<td>A filter name and value pair that is used to return a more specific list of results from a describe operation.</td>
<td>Optional</td>
</tr>
<tr>
<td>FleetId</td>
<td>The ID of the EC2 Fleet.</td>
<td>Required</td>
</tr>
<tr>
<td>MaxResults</td>
<td>The maximum number of results to return in a single call. Specify a value between 1 and 1000.</td>
<td>Optional</td>
</tr>
<tr>
<td>NextToken</td>
<td>The token for the next set of results.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2641" data-line-end="2642">
<a id="Context_Output_2641"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.Fleet.ActiveInstances.InstanceId</td>
<td>String</td>
<td>The ID of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.ActiveInstances.InstanceType</td>
<td>String</td>
<td>The instance type.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.ActiveInstances.SpotInstanceRequestId</td>
<td>String</td>
<td>The ID of the Spot Instance request.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.ActiveInstances.InstanceHealth</td>
<td>String</td>
<td>The health status of the instance.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.NextToken</td>
<td>String</td>
<td>The token for the next set of results.</td>
</tr>
<tr>
<td>AWS.EC2.Fleet.FleetId</td>
<td>String</td>
<td>The ID of the EC2 Fleet.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2661" data-line-end="2662"> </h5>
<h3 id="h_2f581707-2545-4125-a31e-77dbeebe0989" class="code-line" data-line-start="2664" data-line-end="2665">
<a id="56_awsec2modifyfleet_2664"></a>56. aws-ec2-modify-fleet</h3>
<hr>
<p class="has-line-data" data-line-start="2666" data-line-end="2667">Modifies the specified EC2 Fleet.</p>
<h5 class="code-line" data-line-start="2667" data-line-end="2668">
<a id="Base_Command_2667"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2669" data-line-end="2670"><code>aws-ec2-modify-fleet</code></p>
<h5 class="code-line" data-line-start="2670" data-line-end="2671">
<a id="Input_2670"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>FleetId</td>
<td>The ID of the EC2 Fleet.</td>
<td>Required</td>
</tr>
<tr>
<td>TotalTargetCapacity</td>
<td>The number of units to request, filled using DefaultTargetCapacityType.</td>
<td>Required</td>
</tr>
<tr>
<td>OnDemandTargetCapacity</td>
<td>The number of On-Demand units to request.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotTargetCapacity</td>
<td>The number of Spot units to request.</td>
<td>Optional</td>
</tr>
<tr>
<td>DefaultTargetCapacityType</td>
<td>The default TotalTargetCapacity, which is either Spot or On-Demand.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2685" data-line-end="2686">
<a id="Context_Output_2685"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2687" data-line-end="2688">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2697" data-line-end="2698"> </h5>
<h3 id="h_3a2af540-2be0-4432-b6ce-2b915b8afca3" class="code-line" data-line-start="2700" data-line-end="2701">
<a id="57_awsec2createlaunchtemplate_2700"></a>57. aws-ec2-create-launch-template</h3>
<hr>
<p class="has-line-data" data-line-start="2702" data-line-end="2703">Creates a launch template. A launch template contains the parameters to launch an instance.</p>
<h5 class="code-line" data-line-start="2703" data-line-end="2704">
<a id="Base_Command_2703"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2705" data-line-end="2706"><code>aws-ec2-create-launch-template</code></p>
<h5 class="code-line" data-line-start="2706" data-line-end="2707">
<a id="Input_2706"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>ClientToken</td>
<td>Unique, case-sensitive identifier you provide to ensure the idempotency of the request.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchTemplateName</td>
<td>A name for the launch template.</td>
<td>Required</td>
</tr>
<tr>
<td>VersionDescription</td>
<td>A description for the first version of the launch template.</td>
<td>Optional</td>
</tr>
<tr>
<td>KernelId</td>
<td>The ID of the kernel.</td>
<td>Optional</td>
</tr>
<tr>
<td>EbsOptimized</td>
<td>Indicates whether the instance is optimized for Amazon EBS I/O.</td>
<td>Optional</td>
</tr>
<tr>
<td>iamInstanceProfileArn</td>
<td>The Amazon Resource Name (ARN) of the instance profile.</td>
<td>Optional</td>
</tr>
<tr>
<td>iamInstanceProfileName</td>
<td>The name of the instance profile.</td>
<td>Optional</td>
</tr>
<tr>
<td>deviceName</td>
<td>The device name (for example, /dev/sdh or xvdh).</td>
<td>Optional</td>
</tr>
<tr>
<td>VirtualName</td>
<td>The virtual device name (ephemeralN). Instance store volumes are numbered starting from 0.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsEncrypted</td>
<td>Indicates whether the EBS volume is encrypted.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsDeleteOnTermination</td>
<td>Indicates whether the EBS volume is deleted on instance termination.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsIops</td>
<td>The number of I/O operations per second (IOPS) that the volume supports.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsKmsKeyId</td>
<td>The ARN of the AWS Key Management Service (AWS KMS) CMK used for encryption.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsSnapshotId</td>
<td>The ID of the snapshot.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsVolumeSize</td>
<td>The size of the volume, in GiB.</td>
<td>Optional</td>
</tr>
<tr>
<td>ebsVolumeType</td>
<td>The volume type.</td>
<td>Optional</td>
</tr>
<tr>
<td>NoDevice</td>
<td>Suppresses the specified device included in the block device mapping of the AMI.</td>
<td>Optional</td>
</tr>
<tr>
<td>AssociatePublicIpAddress</td>
<td>Associates a public IPv4 address with eth0 for a new network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>NetworkInterfacesDeleteOnTermination</td>
<td>Indicates whether the network interface is deleted when the instance is terminated.</td>
<td>Optional</td>
</tr>
<tr>
<td>NetworkInterfacesDescription</td>
<td>A description for the network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>NetworkInterfacesDeviceIndex</td>
<td>The device index for the network interface attachment.</td>
<td>Optional</td>
</tr>
<tr>
<td>NetworkInterfaceGroups</td>
<td>The IDs of one or more security groups.</td>
<td>Optional</td>
</tr>
<tr>
<td>Ipv6AddressCount</td>
<td>The number of IPv6 addresses to assign to a network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>Ipv6Addresses</td>
<td>One or more specific IPv6 addresses from the IPv6 CIDR block range of your subnet.</td>
<td>Optional</td>
</tr>
<tr>
<td>NetworkInterfaceId</td>
<td>The ID of the network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>PrivateIpAddress</td>
<td>The primary private IPv4 address of the network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>SubnetId</td>
<td>The ID of the subnet for the network interface.</td>
<td>Optional</td>
</tr>
<tr>
<td>ImageId</td>
<td>The ID of the AMI, which you can get by using DescribeImages.</td>
<td>Optional</td>
</tr>
<tr>
<td>InstanceType</td>
<td>The instance type.</td>
<td>Optional</td>
</tr>
<tr>
<td>KeyName</td>
<td>The name of the key pair.</td>
<td>Optional</td>
</tr>
<tr>
<td>Monitoring</td>
<td>Specify true to enable detailed monitoring. Otherwise, basic monitoring is enabled.</td>
<td>Optional</td>
</tr>
<tr>
<td>AvailabilityZone</td>
<td>The Availability Zone for the instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>PlacementAffinity</td>
<td>The affinity setting for an instance on a Dedicated Host.</td>
<td>Optional</td>
</tr>
<tr>
<td>AvailabilityZoneGroupName</td>
<td>The name of the placement group for the instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>PlacementHostId</td>
<td>The ID of the Dedicated Host for the instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>PlacementTenancy</td>
<td>The tenancy of the instance (if the instance is running in a VPC).</td>
<td>Optional</td>
</tr>
<tr>
<td>PlacementSpreadDomain</td>
<td>Reserved for future use.</td>
<td>Optional</td>
</tr>
<tr>
<td>RamDiskId</td>
<td>The ID of the RAM disk.</td>
<td>Optional</td>
</tr>
<tr>
<td>DisableApiTermination</td>
<td>If set to true , you can’t terminate the instance using the Amazon EC2 console, CLI, or API.</td>
<td>Optional</td>
</tr>
<tr>
<td>InstanceInitiatedShutdownBehavior</td>
<td>Indicates whether an instance stops or terminates when you initiate shutdown from the instance (using the operating system command for system shutdown).</td>
<td>Optional</td>
</tr>
<tr>
<td>UserData</td>
<td>The Base64-encoded user data to make available to the instance.</td>
<td>Optional</td>
</tr>
<tr>
<td>Tags</td>
<td>The tags to apply to the resource.</td>
<td>Optional</td>
</tr>
<tr>
<td>ElasticGpuSpecificationsType</td>
<td>The type of Elastic Graphics accelerator.</td>
<td>Optional</td>
</tr>
<tr>
<td>ElasticInferenceAcceleratorsType</td>
<td>The type of elastic inference accelerator. The possible values are eia1.medium, eia1.large, and eia1.xlarge.</td>
<td>Optional</td>
</tr>
<tr>
<td>securityGroupIds</td>
<td>One or more security group IDs.</td>
<td>Optional</td>
</tr>
<tr>
<td>securityGroups</td>
<td>One or more security group names.</td>
<td>Optional</td>
</tr>
<tr>
<td>MarketType</td>
<td>The market type.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotInstanceType</td>
<td>The Spot Instance request type.</td>
<td>Optional</td>
</tr>
<tr>
<td>BlockDurationMinutes</td>
<td>The required duration for the Spot Instances (also known as Spot blocks), in minutes. This value must be a multiple of 60 (60, 120, 180, 240, 300, or 360).</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotValidUntil</td>
<td>The end date of the request.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotInstanceInterruptionBehavior</td>
<td>The behavior when a Spot Instance is interrupted. The default is terminate.</td>
<td>Optional</td>
</tr>
<tr>
<td>SpotMaxPrice</td>
<td>The maximum hourly price you’re willing to pay for the Spot Instances.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2768" data-line-end="2769">
<a id="Context_Output_2768"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.LaunchTemplateId</td>
<td>String</td>
<td>The ID of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.LaunchTemplateName</td>
<td>String</td>
<td>The name of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.CreateTime</td>
<td>Date</td>
<td>The time launch template was created.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.CreatedBy</td>
<td>String</td>
<td>The principal that created the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.DefaultVersionNumber</td>
<td>Number</td>
<td>The version number of the default version of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.LatestVersionNumber</td>
<td>Number</td>
<td>The version number of the latest version of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.Tags.Key</td>
<td>String</td>
<td>The key of the tag.</td>
</tr>
<tr>
<td>AWS.EC2.LaunchTemplates.LaunchTemplate.Tags.Value</td>
<td>String</td>
<td>The value of the tag.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2790" data-line-end="2791"> </h5>
<h3 id="h_1209deee-be0f-49f4-a123-1fb5cf9df2b2" class="code-line" data-line-start="2793" data-line-end="2794">
<a id="58_awsec2deletelaunchtemplate_2793"></a>58. aws-ec2-delete-launch-template</h3>
<hr>
<p class="has-line-data" data-line-start="2795" data-line-end="2796">Deletes a launch template. Deleting a launch template deletes all of its versions.</p>
<h5 class="code-line" data-line-start="2796" data-line-end="2797">
<a id="Base_Command_2796"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2798" data-line-end="2799"><code>aws-ec2-delete-launch-template</code></p>
<h5 class="code-line" data-line-start="2799" data-line-end="2800">
<a id="Input_2799"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchTemplateId</td>
<td>The ID of the launch template.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchTemplateName</td>
<td>The name of the launch template.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2811" data-line-end="2812">
<a id="Context_Output_2811"></a>Context Output</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AWS.EC2.DeletedLaunchTemplates.LaunchTemplate.LaunchTemplateId</td>
<td>String</td>
<td>The ID of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedLaunchTemplates.LaunchTemplate.LaunchTemplateName</td>
<td>String</td>
<td>The name of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedLaunchTemplates.LaunchTemplate.CreateTime</td>
<td>Date</td>
<td>The time launch template was created.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedLaunchTemplates.LaunchTemplate.CreatedBy</td>
<td>String</td>
<td>The principal that created the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedLaunchTemplates.LaunchTemplate.DefaultVersionNumber</td>
<td>Number</td>
<td>The version number of the default version of the launch template.</td>
</tr>
<tr>
<td>AWS.EC2.DeletedLaunchTemplates.LaunchTemplate.LatestVersionNumber</td>
<td>Number</td>
<td>The version number of the latest version of the launch template.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2831" data-line-end="2832"> </h5>
<h3 id="h_392b6709-0b5c-4ef2-b35d-dcd8a7b86ccb" class="code-line" data-line-start="2834" data-line-end="2835">
<a id="59_awsec2modifyimageattribute_2834"></a>59. aws-ec2-modify-image-attribute</h3>
<hr>
<p class="has-line-data" data-line-start="2836" data-line-end="2837">Modifies the specified attribute of the specified AMI.</p>
<h5 class="code-line" data-line-start="2837" data-line-end="2838">
<a id="Base_Command_2837"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2839" data-line-end="2840"><code>aws-ec2-modify-image-attribute</code></p>
<h5 class="code-line" data-line-start="2840" data-line-end="2841">
<a id="Input_2840"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>region</td>
<td>The AWS Region, if not specified the default region will be used.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleArn</td>
<td>The Amazon Resource Name (ARN) of the role to assume.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionName</td>
<td>An identifier for the assumed role session.</td>
<td>Optional</td>
</tr>
<tr>
<td>roleSessionDuration</td>
<td>The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td>Optional</td>
</tr>
<tr>
<td>Attribute</td>
<td>The name of the attribute to modify. The valid values are description, launchPermission, and productCodes.</td>
<td>Optional</td>
</tr>
<tr>
<td>Description</td>
<td>A new description for the AMI.</td>
<td>Optional</td>
</tr>
<tr>
<td>ImageId</td>
<td>The ID of the AMI.</td>
<td>Required</td>
</tr>
<tr>
<td>LaunchPermission-Add-Group</td>
<td>The name of the group.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchPermission-Add-UserId</td>
<td>The AWS account ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchPermission-Remove-Group</td>
<td>The name of the group.</td>
<td>Optional</td>
</tr>
<tr>
<td>LaunchPermission-Remove-UserId</td>
<td>The AWS account ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>OperationType</td>
<td>The operation type.</td>
<td>Optional</td>
</tr>
<tr>
<td>ProductCodes</td>
<td>One or more DevPay product codes. After you add a product code to an AMI, it can’t be removed.</td>
<td>Optional</td>
</tr>
<tr>
<td>UserGroups</td>
<td>One or more user groups. This parameter can be used only when the Attribute parameter is launchPermission.</td>
<td>Optional</td>
</tr>
<tr>
<td>UserIds</td>
<td>One or more AWS account IDs. This parameter can be used only when the Attribute parameter is launchPermission.</td>
<td>Optional</td>
</tr>
<tr>
<td>Value</td>
<td>The value of the attribute being modified. This parameter can be used only when the Attribute parameter is description or productCodes.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2862" data-line-end="2863">
<a id="Context_Output_2862"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2864" data-line-end="2865">There is no context output for this command.</p>