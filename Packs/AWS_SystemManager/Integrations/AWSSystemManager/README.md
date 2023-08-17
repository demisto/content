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

       
       


### aws-ssm-association-get

***
Describes the association for the specified target or managed node. if the association was established using the Targets parameter, the association details must be retrieved using the associated ID. this command must provide either association id or instance_id and document_name

#### Base Command

`aws-ssm-association-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_name | The name of the SSM document. | Optional | 
| instance_id | The managed node ID. | Optional | 
| association_id | The association ID for which information is requested. | Optional | 
| association_version | Specify the association version to retrieve. To view the latest version, either specify $LATEST for this parameter, or omit this parameter. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SSM.Association.AssociationDescription.Name | String | The name of the SSM document. | 
| AWS.SSM.Association.AssociationDescription.InstanceId | String | The managed node ID. | 
| AWS.SSM.Association.AssociationDescription.AssociationVersion | String | The association version. | 
| AWS.SSM.Association.AssociationDescription.Date | String | The date when the association was made. | 
| AWS.SSM.Association.AssociationDescription.LastUpdateAssociationDate | String | The date when the association was last updated. | 
| AWS.SSM.Association.AssociationDescription.Status.Date | String | The date when the status changed. | 
| AWS.SSM.Association.AssociationDescription.Status.Name | String | The status. | 
| AWS.SSM.Association.AssociationDescription.Status.Message | String | The reason for the status. | 
| AWS.SSM.Association.AssociationDescription.Status.AdditionalInfo | String | A user-defined string. | 
| AWS.SSM.Association.AssociationDescription.Overview.Status | String | The status of the association. Status can be: Pending, Success, or Failed. | 
| AWS.SSM.Association.AssociationDescription.Overview.DetailedStatus | String | A detailed status of the association. | 
| AWS.SSM.Association.AssociationDescription.Overview.AssociationStatusAggregatedCount | Number | Returns the number of targets for the association status. For example, if an association was created with two managed nodes, and one of them was successful, this would return the count of managed nodes by status. | 
| AWS.SSM.Association.AssociationDescription.DocumentVersion | String | The document version. | 
| AWS.SSM.Association.AssociationDescription.AutomationTargetParameterName | String | Choose the parameter that will define how the automation will branch out. This target is required for associations that use an Automation runbook and target resources by using rate controls. Automation is a capability of Amazon Web Services Systems Manager. | 
| AWS.SSM.Association.AssociationDescription.Parameters | Dictionary | A description of the parameters for a document. | 
| AWS.SSM.Association.AssociationDescription.AssociationId | String | The association ID. | 
| AWS.SSM.Association.AssociationDescription.Targets.Key | String | User-defined criteria for sending commands that target managed nodes that meet the criteria. | 
| AWS.SSM.Association.AssociationDescription.Targets.Values | String | User-defined criteria that maps to Key. | 
| AWS.SSM.Association.AssociationDescription.ScheduleExpression | String | A cron expression that specifies a schedule when the association runs. | 
| AWS.SSM.Association.AssociationDescription.OutputLocation | unknown | An S3 bucket where to store the output details of the request. | 
| AWS.SSM.Association.AssociationDescription.OutputLocation.S3Location.OutputS3Region | String | The Amazon Web Services Region of the S3 bucket. | 
| AWS.SSM.Association.AssociationDescription.OutputLocation.S3Location.OutputS3BucketName | String | The name of the S3 bucket. | 
| AWS.SSM.Association.AssociationDescription.OutputLocation.S3Location.OutputS3KeyPrefix | String | The S3 bucket subfolder. | 
| AWS.SSM.Association.AssociationDescription.LastExecutionDate | String | The date on which the association was last run. | 
| AWS.SSM.Association.AssociationDescription.LastSuccessfulExecutionDate | String | The last date on which the association was successfully run. | 
| AWS.SSM.Association.AssociationDescription.AssociationName | String | The association name. | 
| AWS.SSM.Association.AssociationDescription.MaxErrors | String | The number of errors that are allowed before the system stops sending requests to run the association on additional targets. | 
| AWS.SSM.Association.AssociationDescription.MaxConcurrency | String | The maximum number of targets allowed to run the association at the same time. | 
| AWS.SSM.Association.AssociationDescription.ComplianceSeverity | String | The severity level that is assigned to the association. | 
| AWS.SSM.Association.AssociationDescription.SyncCompliance | String | The mode for generating association compliance. AUTO or MANUAL. In AUTO mode, the system uses the status of the association execution to determine the compliance status. If the association execution runs successfully, then the association is COMPLIANT. If the association execution doesn’t run successfully, the association is NON-COMPLIANT. In MANUAL mode, must specify the AssociationId as a parameter for the PutComplianceItems API operation. In this case, compliance data isn’t managed by State Manager, a capability of Amazon Web Services Systems Manager. It is managed by direct call to the PutComplianceItems API operation. By default, all associations use AUTO mode. | 
| AWS.SSM.Association.AssociationDescription.ApplyOnlyAtCronInterval | Boolean | By default, when creating a new association, the system runs it immediately after it is created and then according to the schedule that was specified. This parameter isn’t supported for rate expressions. | 
| AWS.SSM.Association.AssociationDescription.CalendarNames | String | The names or Amazon Resource Names \(ARNs\) of the Change Calendar type documents your associations are gated under. The associations only run when that change calendar is open. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.Accounts | String | The Amazon Web Services accounts targeted by the current Automation execution. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.Regions | String | The Amazon Web Services Regions targeted by the current Automation execution. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.TargetLocationMaxConcurrency | String | The maximum number of Amazon Web Services Regions and Amazon Web Services accounts allowed to run the Automation concurrently. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.TargetLocationMaxErrors | String | The maximum number of errors allowed before the system stops queueing additional Automation executions for the currently running Automation. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.ExecutionRoleName | String | The Automation execution role used by the currently running Automation. If not specified, the default value is AWS-SystemsManager-AutomationExecutionRole. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.TargetLocationAlarmConfiguration.IgnorePollAlarmFailure | Boolean | When this value is true, the automation or command continues to run in cases where we can’t retrieve alarm status information from CloudWatch. In cases where we successfully retrieve an alarm status of OK or INSUFFICIENT_DATA, the automation or command continues to run, regardless of this value. Default is false. | 
| AWS.SSM.Association.AssociationDescription.TargetLocations.TargetLocationAlarmConfiguration.Alarms.Name | String | The name of the CloudWatch alarm. | 
| AWS.SSM.Association.AssociationDescription.ScheduleOffset | Number | Number of days to wait after the scheduled day to run an association. | 
| AWS.SSM.Association.AssociationDescription.TargetMaps | List | A key-value mapping of document parameters to target resources. Both Targets and TargetMaps can’t be specified together. | 
| AWS.SSM.Association.AssociationDescription.AlarmConfiguration.IgnorePollAlarmFailure | Boolean | When this value is true, the automation or command continues to run in cases where we can’t retrieve alarm status information from CloudWatch. In cases where we successfully retrieve an alarm status of OK or INSUFFICIENT_DATA, the automation or command continues to run, regardless of this value. Default is false. | 
| AWS.SSM.Association.AssociationDescription.AlarmConfiguration.Alarms.Name | String | The name of the CloudWatch alarm. | 
| AWS.SSM.Association.AssociationDescription.TriggeredAlarms.Name | String | The CloudWatch alarm that was invoked during the association. | 
| AWS.SSM.Association.AssociationDescription.TriggeredAlarms.State | String | The state of the CloudWatch alarm. | 

#### Command example
```!aws-ssm-association-get association_id=association_id```
#### Context Example
```json
{
    "AWS": {
        "SSM": {
            "Association": {
                "AssociationDescription": {
                    "ApplyOnlyAtCronInterval": false,
                    "AssociationId": "association_id",
                    "AssociationName": "AWS-QuickSetup-SSMHost",
                    "AssociationVersion": "1",
                    "AutomationTargetParameterName": "InstanceId",
                    "Date": "2023-02-14T11:48:24.511000+00:00",
                    "DocumentVersion": "$DEFAULT",
                    "LastExecutionDate": "2023-08-13T11:49:38+00:00",
                    "LastSuccessfulExecutionDate": "2023-02-14T11:48:48+00:00",
                    "LastUpdateAssociationDate": "2023-02-14T11:48:24.511000+00:00",
                    "Name": "AWSQuickSetup",
                    "Overview": {
                        "AssociationStatusAggregatedCount": {
                            "Failed": 1
                        },
                        "DetailedStatus": "Failed",
                        "Status": "Failed"
                    },
                    "Parameters": {
                        "AutomationAssumeRole": [
                            "automation_assume_role"
                        ],
                        "IsPolicyAttachAllowed": [
                            "false"
                        ]
                    },
                    "ScheduleExpression": "rate(30 days)",
                    "Targets": [
                        {
                            "Key": "ParameterValues",
                            "Values": [
                                "instance_id"
                            ]
                        }
                    ]
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Association
>|Association id|Association name|Association version|Create date|Document name|Document version|Last execution date|Resource status count|Schedule expression|Status|
>|---|---|---|---|---|---|---|---|---|---|
>| association_id | AWS-QuickSetup | 1 | 2023-02-14T11:48:24.511000+00:00 | AWSQuickSetup | $DEFAULT | 2023-08-13T11:49:38+00:00 | Failed: 1 | rate(30 days) | Failed |

