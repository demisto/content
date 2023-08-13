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
| AWS.SSM.Inventory.Entities | String | ID of the inventory result entity. For example, for managed node inventory the result will be the managed node ID. For EC2 instance inventory, the result will be the instance ID. | 
| AWS.SSM.Inventory.Entities.Id | String | ID of the inventory result entity. For example, for managed node inventory the result will be the managed node ID. For EC2 instance inventory, the result will be the instance ID. | 
| AWS.SSM.Inventory.Entities.Data.TypeName | String | The name of the inventory result item type. | 
| AWS.SSM.Inventory.Entities.Data.SchemaVersion | String | The schema version for the inventory result item. | 
| AWS.SSM.Inventory.Entities.Data.CaptureTime | String | The time inventory item data was captured. | 
| AWS.SSM.Inventory.Entities.Data.ContentHash | String | MD5 hash of the inventory item type contents. The content hash is used to determine whether to update inventory information. The PutInventory API doesn’t update the inventory item type contents if the MD5 hash hasn’t changed since last update. | 

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

