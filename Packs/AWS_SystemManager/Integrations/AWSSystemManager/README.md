AWS Systems Manager is the operations hub for your AWS applications and resources and a secure end-to-end management solution for hybrid cloud environments that enables safe and secure operations at scale.
This integration was integrated and tested with version xx of AWS - System Manager

## Configure AWS - System Manager on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - System Manager.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | AWS Default Region |  | True |
    | Role Arn |  | False |
    | Role Session Name |  | False |
    | Role Session Duration |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-ssm-tag-add

***
Adds or overwrites one tag for the specified resource.
Tags are metadata that you can assign to your automations, documents, managed nodes, maintenance windows, Parameter Store parameters, and patch baselines.
Tags enable you to categorize your resources in different ways, for example, by purpose, owner, or environment.
Each tag consists of a key and an optional value, both of which you define.
For example, you could define a set of tags for your account’s managed nodes that helps you track each node’s owner and stack level.
For example, Key=Owner,Value=SysAdmin.

#### Base Command

`aws-ssm-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_type | Specifies the type of resource for tagging.<br/>Note: The ManagedInstance type for this API operation is for on-premises managed nodes.<br/>Must specify the name of the managed node in the following format: mi-ID_number ``. For example, ``mi-1a2b3c4d5e6f. Possible values are: Association, Automation, Document, MaintenanceWindow, ManagedInstance, OpsItem, OpsMetadata, PatchBaseline, Parameter. | Required | 
| resource_id | The resource ID to be tagged.(e.g. MaintenanceWindow: mw-012345abcde, PatchBaseline: pb-012345abcde, for more example see in the README). | Required | 
| tag_key | The name of the tag. Note: Don’t enter personally identifiable information in this field. | Required | 
| tag_value | The value of the tag. Note: Don’t enter personally identifiable information in this field. | Required | 

#### Context Output

There is no context output for this command.
### aws-ssm-inventory-get

***
Query inventory information. This includes managed node status, such as Stopped or Terminated.

#### Base Command

`aws-ssm-inventory-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return for this call, the default and max is 50. The call also returns a token that you can specify in a subsequent call to get the next set of results. | Optional | 
| next_token | The token for the next set of items to return. (Received this token from a previous call.). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SSM.InventoryNextToken | String | The token for the next set of items to return. | 
| AWS.SSM.Inventory.Entities.Id | String | ID of the inventory result entity. For example, for managed node inventory the result will be the managed node ID. For EC2 instance inventory, the result will be the instance ID. | 
| AWS.SSM.Inventory.Entities.Data.TypeName | String | The name of the inventory result item type. | 
| AWS.SSM.Inventory.Entities.Data.SchemaVersion | String | The schema version for the inventory result item. | 
| AWS.SSM.Inventory.Entities.Data.CaptureTime | String | The time inventory item data was captured. | 
| AWS.SSM.Inventory.Entities.Data.ContentHash | String | MD5 hash of the inventory item type contents. The content hash is used to determine whether to update inventory information. The PutInventory API doesn’t update the inventory item type contents if the MD5 hash hasn’t changed since last update. | 
| AWS.SSM.Inventory.Entities.Data.Content.AgentType | String | The type of SSM agent running on the instance. | 
| AWS.SSM.Inventory.Entities.Data.Content.AgentVersion | String | The version of the SSM agent running on the instance. | 
| AWS.SSM.Inventory.Entities.Data.Content.ComputerName | String | The fully qualified host name of the managed node. | 
| AWS.SSM.Inventory.Entities.Data.Content.IpAddress | String | The IP address of the managed node. | 
| AWS.SSM.Inventory.Entities.Data.Content.PlatformName | String | The name of the operating system platform running on the managed node. | 
| AWS.SSM.Inventory.Entities.Data.Content.PlatformType | String | The operating system platform type. | 
| AWS.SSM.Inventory.Entities.Data.Content.PlatformVersion | String | The version of the OS platform running on the managed node. | 
| AWS.SSM.Inventory.Entities.Data.Content.ResourceType | String | The type of instance. Instances are either EC2 instances or managed instances. | 
| AWS.SSM.Inventory.Entities.Data.Content.InstanceId | String | The managed node ID. | 

#### Command example
```!aws-ssm-inventory-get limit=2```
#### Context Example
```json
{
    "AWS": {
        "SSM": {
            "Inventory": [
            {
                "Id": "i-test_1",
                "Data": {}
            },
            {
                "Id": "i-test_2",
                "Data": {
                    "AWS:InstanceInformation": {
                        "TypeName": "AWS:InstanceInformation",
                        "SchemaVersion": "1.0",
                        "CaptureTime": "2023-07-25T16:02:02Z",
                        "Content": [
                            {
                                "AgentType": "amazon-ssm-agent",
                                "AgentVersion": "agent_version",
                                "ComputerName": "computer_name",
                                "InstanceId": "i-test_2",
                                "InstanceStatus": "Stopped",
                                "IpAddress": "ip_address",
                                "PlatformName": "Ubuntu",
                                "PlatformType": "Linux",
                                "PlatformVersion": "20.04",
                                "ResourceType": "resource_type"
                            }
                        ]
                    }
                }
            },
            ],
            "InventoryNextToken": "test"
        }
    }
}
```

#### Human Readable Output

>### AWS SSM Inventory
>|Id|Instance Id|Computer Name|Platform Type|Platform Name|Agent version|IP address|Resource Type|
>|---|---|---|---|---|---|---|---|
>| i-test1 |  |  |  |  |  |  |  |
>| i-test2 | i-test2 | computer_name | Linux | Ubuntu | agent_version | ip_address | resource_type |


### aws-ssm-inventory-entry-list

***
A list of inventory items returned by the request.

#### Base Command

`aws-ssm-inventory-entry-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| instance_id | The managed node ID to get inventory information for. Note: to get the instance ID, run the aws-ssm-inventory-get command. | Required | 
| type_name | The type of inventory item to get information for. | Required | 
| limit | The maximum number of items to return for this call, the default and max is 50. The call also returns a token that you can specify in a subsequent call to get the next set of results. | Optional | 
| next_token | The token for the next set of items to return. (Received this token from a previous call.). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SSM.InventoryEntryNextToken | String | The token for the next set of items to return. | 
| AWS.SSM.InventoryEntry.TypeName | String | The type of inventory item returned by the request. | 
| AWS.SSM.InventoryEntry.InstanceId | String | The managed node ID targeted by the request to query inventory information. | 
| AWS.SSM.InventoryEntry.SchemaVersion | String | The inventory schema version used by the managed node\(s\). | 
| AWS.SSM.InventoryEntry.CaptureTime | String | The time that inventory information was collected for the managed node\(s\). | 
| AWS.SSM.InventoryEntry.Entries.AgentVersion | String | The version of the SSM agent running on the instance. | 
| AWS.SSM.InventoryEntry.Entries.AgentType | String | The type of SSM agent running on the instance. | 
| AWS.SSM.InventoryEntry.Entries.ComputerName | String | The fully qualified host name of the managed node. | 
| AWS.SSM.InventoryEntry.Entries.IpAddress | String | The IP address of the managed node. | 
| AWS.SSM.InventoryEntry.Entries.PlatformName | String | The name of the operating system platform running on the managed node. | 
| AWS.SSM.InventoryEntry.Entries.PlatformType | String | The operating system platform type. | 
| AWS.SSM.InventoryEntry.Entries.PlatformVersion | String | The version of the OS platform running on the managed node. | 
| AWS.SSM.InventoryEntry.Entries.ResourceType | String | The type of instance. Instances are either EC2 instances or managed instances. | 

#### Command example
```!aws-ssm-inventory-entry-list instance_id=test type_name=AWS:InstanceInformation```
#### Context Example
```json
{
    "AWS": {
        "SSM": {
            "InventoryEntry": {
                "CaptureTime": "2023-07-25T16:01:59Z",
                "Entries": [
                     {
                        "AgentType": "agent_type",
                        "AgentVersion": "agent_version",
                        "ComputerName": "computer_name",
                        "InstanceId": "instance_id",
                        "InstanceStatus": "Stopped",
                        "IpAddress": "ip_address",
                        "PlatformName": "Ubuntu",
                        "PlatformType": "Linux",
                        "PlatformVersion": "20.04",
                        "ResourceType": "resource_type"
                    },
                ],
                "InstanceId": "test",
                "SchemaVersion": "1.0",
                "TypeName": "AWS:InstanceInformation"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS SSM Inventory
>|Agent version|Computer Name|IP address|Instance Id|Platform Name|Platform Type|Resource Type|
>|---|---|---|---|---|---|---|
>| agent_version | computer_name | ip_address | instance_id | Ubuntu | Linux | resource_type |
### aws-ssm-association-list

***
Returns all State Manager associations in the current Amazon Web Services account and Amazon Web Services Region. Note: An association is a binding between a document and a set of targets with a schedule.

#### Base Command

`aws-ssm-association-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return for this call, the default and max is 50. The call also returns a token that you can specify in a subsequent call to get the next set of results. | Optional | 
| next_token | The token for the next set of items to return. (Received this token from a previous call.). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SSM.AssociationNextToken | String | The token for the next set of items to return. | 
| AWS.SSM.Association.Name | String | The name of the SSM document. | 
| AWS.SSM.Association.AssociationName | String | The association name. | 
| AWS.SSM.Association.InstanceId | String | The managed node ID. | 
| AWS.SSM.Association.AssociationId | String | The ID created by the system when crating an association. An association is a binding between a document and a set of targets with a schedule. | 
| AWS.SSM.Association.AssociationVersion | String | The association version. | 
| AWS.SSM.Association.DocumentVersion | String | The version of the document used in the association. | 
| AWS.SSM.Association.Targets.Key | String | User-defined criteria for sending commands that target managed nodes that meet the criteria. | 
| AWS.SSM.Association.Targets.Values | String | User-defined criteria that maps to Key. | 
| AWS.SSM.Association.LastExecutionDate | String | The date on which the association was last run. | 
| AWS.SSM.Association.Overview.Status | String | The status of the association. Status can be: Pending, Success, or Failed. | 
| AWS.SSM.Association.Overview.DetailedStatus | String | A detailed status of the association. | 
| AWS.SSM.Association.Overview.AssociationStatusAggregatedCount | String | Returns the number of targets for the association status. For example, if you created an association with two managed nodes, and one of them was successful, this would return the count of managed nodes by status. | 
| AWS.SSM.Association.ScheduleExpression | String | A cron expression that specifies a schedule when the association runs. The schedule runs in Coordinated Universal Time \(UTC\). | 
| AWS.SSM.Association.ScheduleOffset | Number | Number of days to wait after the scheduled day to run an association. | 

#### Command example
```!aws-ssm-association-list ```
#### Context Example
```json
{
    "AWS": {
        "SSM": {
            "Association": {
                 "Associations": [
                    {
                        "Name": "AWS-GatherSoftwareInventory",
                        "AssociationId": "AssociationId_test",
                        "AssociationVersion": "1",
                        "Targets": [
                            {
                                "Key": "InstanceIds",
                                "Values": [
                                    "instanceId_test1",
                                    "instanceId_test2"
                                ]
                            }
                        ],
                        "LastExecutionDate": "2023-07-25 18:51:28.607000+03:00",
                        "Overview": {
                            "Status": "Pending",
                            "DetailedStatus": "Associated"
                        },
                        "ScheduleExpression": "rate(30 minutes)",
                        "AssociationName": "test"
                    },
                    {
                        "Name": "AWSQuickSetup-CreateAndAttachIAMToInstance",
                        "AssociationId": "AssociationId_test",
                        "AssociationVersion": "1",
                        "Targets": [
                            {
                                "Key": "ParameterValues",
                                "Values": [
                                    "instanceId_test1"
                                ]
                            }
                        ],
                        "LastExecutionDate": "2023-08-13 14:49:38+03:00",
                        "Overview": {
                            "Status": "Failed",
                            "DetailedStatus": "Failed",
                            "AssociationStatusAggregatedCount": {
                                "Failed": 1
                            }
                        },
                        "ScheduleExpression": "rate(30 days)",
                        "AssociationName": "AWS-QuickSetup-SSMHost-AttachIAMToInstance"
                    },
                    {
                        "Name": "AWS-GatherSoftwareInventory",
                        "AssociationId": "AssociationId_test",
                        "AssociationVersion": "1",
                        "Targets": [
                            {
                                "Key": "InstanceIds",
                                "Values": [
                                    "*"
                                ]
                            }
                        ],
                        "LastExecutionDate": "2023-07-25 18:54:37.936000+03:00",
                        "Overview": {
                            "Status": "Pending",
                            "DetailedStatus": "Associated"
                        },
                        "ScheduleExpression": "rate(30 minutes)",
                        "AssociationName": "Inventory-Association"
                    }
                ],
            }
        }
    }
}
```

#### Human Readable Output

>### AWS SSM Association
>|Association id|Association version|Document name|Last execution date|Resource status count|Status|
>|---|---|---|---|---|---|
>| AssociationId_test | 1 | AWS-GatherSoftwareInventory | 2023-07-25 18:51:28.607000+03:00 |  | Pending |
>| AssociationId_test | 1 | AWSQuickSetup-CreateAndAttachIAMToInstance | 2023-08-13 14:49:38+03:00 | Failed: 1 | Failed |
>| AssociationId_test | 1 | AWS-GatherSoftwareInventory | 2023-07-25 18:54:37.936000+03:00 |  | Pending |

       
       


