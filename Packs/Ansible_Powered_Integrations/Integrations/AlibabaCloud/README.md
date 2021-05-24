This integration enables the management of Alibaba Cloud Elastic Compute Service.

To use this integration, configure an instance of this integration. This will associate a credential to be used to manage a Alibaba tenancy. Create separate instances for each region being managed.

# Authorize Cortex XSOAR for AliCloud
To use this integration you must generate an Access/Secret token for your Aliyun tenancy.
1. Navigate to the [Resource Access Management](https://ram.console.aliyun.com/users)
2. Create a service account dedicated for XSOAR with Programmatic Access enabled
3. Record the Access and Secret tokens
4. Navigate to [Permmions > Grants](https://ram.console.aliyun.com/permissions)
4. Grant the service account principal either `AliyunECSFullAccess` or `AliyunECSReadOnlyAccess` permissions. 
## Configure AlibabaCloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AlibabaCloud.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Access Key | Aliyun Cloud access key | True |
    | Access Secret Key | Aliyun Cloud secret key | True |
    | Region | Aliyun Cloud region | True |
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ali-instance
***
Create, Start, Stop, Restart or Terminate an Instance in ECS. Add or Remove Instance to/from a Security Group.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ali_instance_module.html


#### Base Command

`ali-instance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | The state of the instance after operating. Possible values are: present, running, stopped, restarted, absent. Default is present. | Optional | 
| availability_zone | Aliyun availability zone ID in which to launch the instance. If it is not specified, it will be allocated by system automatically. | Optional | 
| image_id | Image ID used to launch instances. Required when `state=present` and creating new ECS instances. | Optional | 
| instance_type | Instance type used to launch instances. Required when `state=present` and creating new ECS instances. | Optional | 
| security_groups | A list of security group IDs. | Optional | 
| vswitch_id | The subnet ID in which to launch the instances (VPC). | Optional | 
| instance_name | The name of ECS instance, which is a string of 2 to 128 Chinese or English characters. It must begin with an uppercase/lowercase letter or a Chinese character and can contain numerals, ".", "_" or "-". It cannot begin with http:// or https://. | Optional | 
| description | The description of ECS instance, which is a string of 2 to 256 characters. It cannot begin with http:// or https://. | Optional | 
| internet_charge_type | Internet charge type of ECS instance. Possible values are: PayByBandwidth, PayByTraffic. Default is PayByBandwidth. | Optional | 
| max_bandwidth_in | Maximum incoming bandwidth from the public network, measured in Mbps (Megabits per second). Default is 200. | Optional | 
| max_bandwidth_out | Maximum outgoing bandwidth to the public network, measured in Mbps (Megabits per second). Default is 0. | Optional | 
| host_name | Instance host name. | Optional | 
| password | The password to login instance. After rebooting instances, modified password will take effect. | Optional | 
| system_disk_category | Category of the system disk. Possible values are: cloud_efficiency, cloud_ssd. Default is cloud_efficiency. | Optional | 
| system_disk_size | Size of the system disk, in GB. The valid values are 40~500. Default is 40. | Optional | 
| system_disk_name | Name of the system disk. | Optional | 
| system_disk_description | Description of the system disk. | Optional | 
| count | The number of the new instance. An integer value which indicates how many instances that match `count_tag` should be running. Instances are either created or terminated based on this value. Default is 1. | Optional | 
| count_tag | `count` determines how many instances based on a specific tag criteria should be present. This can be expressed in multiple ways and is shown in the EXAMPLES section. The specified count_tag must already exist or be passed in as the `instance_tags` option. If it is not specified, it will be replaced by `instance_name`. | Optional | 
| allocate_public_ip | Whether allocate a public ip for the new instance. Default is False. | Optional | 
| instance_charge_type | The charge type of the instance. Possible values are: PrePaid, PostPaid. Default is PostPaid. | Optional | 
| period | The charge duration of the instance, in month. Required when `instance_charge_type=PrePaid`.<br/>The valid value are [1-9, 12, 24, 36]. Default is 1. | Optional | 
| auto_renew | Whether automate renew the charge of the instance. Default is False. | Optional | 
| auto_renew_period | The duration of the automatic renew the charge of the instance. Required when `auto_renew=True`. Possible values are: 1, 2, 3, 6, 12. | Optional | 
| instance_ids | A list of instance ids. It is required when need to operate existing instances. If it is specified, `count` will lose efficacy. | Optional | 
| force | Whether the current operation needs to be execute forcibly. Default is False. | Optional | 
| instance_tags | A hash/dictionaries of instance tags, to add to the new instance or for starting/stopping instance by tag. `{"key":"value"}`. | Optional | 
| key_name | The name of key pair which is used to access ECS instance in SSH. | Optional | 
| user_data | User-defined data to customize the startup behaviors of an ECS instance and to pass data into an ECS instance. It only will take effect when launching the new ECS instances. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlibabaCloud.ali_instance.instances | unknown | List of ECS instances | 
| AlibabaCloud.ali_instance.ids | unknown | List of ECS instance IDs | 


#### Command Example
```!ali-instance image_id=ubuntu_20_04_x64_20G_alibase_20210420.vhd instance_type=ecs.n4.small vswitch_id=vsw-bp1aclhyjkdy98ujfzspt host_name=testserver security_groups=sg-bp1fy1o431n7m0hta5tt ```

#### Context Example
```json
{
    "alibabacloud": {
        "ali_instance": [
            {
                "changed": true,
                "host": "localhost",
                "instances": [],
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
># Instances #


### ali-instance-info
***
Gather information on instances of Alibaba Cloud ECS.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/ali_instance_info_module.html


#### Base Command

`ali-instance-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| availability_zone | Aliyun availability zone ID in which to launch the instance. | Optional | 
| instance_names | A list of ECS instance names. | Optional | 
| instance_ids | A list of ECS instance ids. | Optional | 
| instance_tags | A hash/dictionaries of instance tags. `{"key":"value"}`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlibabaCloud.ali_instance_info.instances | unknown | List of ECS instances | 
| AlibabaCloud.ali_instance_info.ids | unknown | List of ECS instance IDs | 


#### Command Example
```!ali-instance-info ```

#### Context Example
```json
{
    "alibabacloud": {
        "ali_instance_info": [
            {
                "changed": false,
                "host": "localhost",
                "ids": [
                    "i-bp1io1ygqvbuwxj73izt"
                ],
                "instances": [
                    {
                        "auto_release_time": "",
                        "availability_zone": "cn-hangzhou-b",
                        "block_device_mappings": [
                            {
                                "attach_time": "2021-05-24T10:24:40Z",
                                "delete_on_termination": true,
                                "device_name": "/dev/xvda",
                                "status": "in_use",
                                "volume_id": "d-bp1clt44axl1smfropli"
                            }
                        ],
                        "cpu": 1,
                        "cpu_options": {
                            "core_count": 1,
                            "numa": "",
                            "threads_per_core": 1
                        },
                        "creation_time": "2021-05-24T10:24Z",
                        "credit_specification": "",
                        "dedicated_instance_attribute": {
                            "affinity": "",
                            "tenancy": ""
                        },
                        "deletion_protection": false,
                        "deployment_set_id": "",
                        "description": "",
                        "ecs_capacity_reservation_attr": {
                            "capacity_reservation_id": "",
                            "capacity_reservation_preference": ""
                        },
                        "eip": {
                            "allocation_id": "",
                            "internet_charge_type": "",
                            "ip_address": ""
                        },
                        "expired_time": "2099-12-31T15:59Z",
                        "gpu": {
                            "amount": 0,
                            "spec": "",
                            "specification": ""
                        },
                        "hibernation_options": {
                            "configured": false
                        },
                        "host_name": "testserver",
                        "id": "i-bp1io1ygqvbuwxj73izt",
                        "image_id": "ubuntu_20_04_x64_20G_alibase_20210420.vhd",
                        "inner_ip_address": "",
                        "instance_charge_type": "PostPaid",
                        "instance_id": "i-bp1io1ygqvbuwxj73izt",
                        "instance_name": "testserver",
                        "instance_type": "ecs.n4.small",
                        "instance_type_family": "ecs.n4",
                        "internet_charge_type": "PayByBandwidth",
                        "internet_max_bandwidth_in": -1,
                        "internet_max_bandwidth_out": 0,
                        "io_optimized": true,
                        "memory": 2048,
                        "metadata_options": {
                            "http_endpoint": "",
                            "http_tokens": ""
                        },
                        "network_interfaces": [
                            {
                                "mac_address": "00:16:3e:01:24:c5",
                                "network_interface_id": "eni-bp1brh4zldkxuugjumeg",
                                "primary_ip_address": "172.16.0.57",
                                "private_ip_sets": {
                                    "private_ip_set": [
                                        {
                                            "primary": true,
                                            "private_ip_address": "172.16.0.57"
                                        }
                                    ]
                                },
                                "type": "Primary"
                            }
                        ],
                        "osname": "Ubuntu  20.04 64\u4f4d",
                        "osname_en": "Ubuntu  20.04 64 bit",
                        "ostype": "linux",
                        "private_ip_address": "172.16.0.57",
                        "public_ip_address": "",
                        "resource_group_id": "",
                        "status": "running",
                        "tags": {},
                        "user_data": "",
                        "vpc_id": "vpc-bp179mi6isco5xen2wojd",
                        "vswitch_id": "vsw-bp1aclhyjkdy98ujfzspt"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
># Ids #
>* 0: i-bp1io1ygqvbuwxj73izt
># Instances #
>* ## Testserver ##
>* auto_release_time: 
>* availability_zone: cn-hangzhou-b
>* ## Block_Device_Mappings ##
>* ### /Dev/Xvda ###
>  * attach_time: 2021-05-24T10:24:40Z
>  * delete_on_termination: True
>  * device_name: /dev/xvda
>  * status: in_use
>  * volume_id: d-bp1clt44axl1smfropli
>* cpu: 1
>* ## Cpu_Options ##
>  * core_count: 1
>  * numa: 
>  * threads_per_core: 1
>* creation_time: 2021-05-24T10:24Z
>* credit_specification: 
>* ## Dedicated_Instance_Attribute ##
>  * affinity: 
>  * tenancy: 
>* deletion_protection: False
>* deployment_set_id: 
>* description: 
>* ## Ecs_Capacity_Reservation_Attr ##
>  * capacity_reservation_id: 
>  * capacity_reservation_preference: 
>* ## Eip ##
>  * allocation_id: 
>  * internet_charge_type: 
>  * ip_address: 
>* expired_time: 2099-12-31T15:59Z
>* ## Gpu ##
>  * amount: 0
>  * spec: 
>  * specification: 
>* ## Hibernation_Options ##
>  * configured: False
>* host_name: testserver
>* id: i-bp1io1ygqvbuwxj73izt
>* image_id: ubuntu_20_04_x64_20G_alibase_20210420.vhd
>* inner_ip_address: 
>* instance_charge_type: PostPaid
>* instance_id: i-bp1io1ygqvbuwxj73izt
>* instance_name: testserver
>* instance_type: ecs.n4.small
>* instance_type_family: ecs.n4
>* internet_charge_type: PayByBandwidth
>* internet_max_bandwidth_in: -1
>* internet_max_bandwidth_out: 0
>* io_optimized: True
>* memory: 2048
>* ## Metadata_Options ##
>  * http_endpoint: 
>  * http_tokens: 
>* ## Network_Interfaces ##
>* ### Eni-Bp1Brh4Zldkxuugjumeg ###
>  * mac_address: 00:16:3e:01:24:c5
>  * network_interface_id: eni-bp1brh4zldkxuugjumeg
>  * primary_ip_address: 172.16.0.57
>* ### Private_Ip_Sets ###
>* #### Private_Ip_Set ####
>* ##### List #####
>  * primary: True
>  * private_ip_address: 172.16.0.57
>  * type: Primary
>* osname: Ubuntu  20.04 64位
>* osname_en: Ubuntu  20.04 64 bit
>* ostype: linux
>* private_ip_address: 172.16.0.57
>* public_ip_address: 
>* resource_group_id: 
>* status: running
>* ## Tags ##
>* user_data: 
>* vpc_id: vpc-bp179mi6isco5xen2wojd
>* vswitch_id: vsw-bp1aclhyjkdy98ujfzspt

