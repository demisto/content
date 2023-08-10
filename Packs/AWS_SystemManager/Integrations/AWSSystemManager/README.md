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
| resource_type | Specifies the type of resource for tagging.<br/>Note: The ManagedInstance type for this API operation is for on-premises managed nodes.<br/>Must specify the name of the managed node in the following format: mi-ID_number. For example, ``mi-1a2b3c4d5e6f``. Possible values are: Association, Automation, Document, MaintenanceWindow, ManagedInstance, OpsItem, OpsMetadata, PatchBaseline, Parameter. | Required | 
| resource_id | The resource ID to be tagged.(e.g. MaintenanceWindow: mw-012345abcde, PatchBaseline: pb-012345abcde. (for more example see in the table below.) | Required | 
| tag_key | The name of the tag. Note: Don’t enter personally identifiable information in this field. | Required | 
| tag_value | The value of the tag. Note: Don’t enter personally identifiable information in this field. | Required | 


### resource_id Argument Example

|**ResourceType**|**ResourceID**|
|---|---|---|---|---|---|
| MaintenanceWindow | mw-012345abcde |
| PatchBaseline | pb-012345abcde |
| ManagedInstance | mi-012345abcde |
| Automation | example-c160-4567-8519-012345abcde |
| Document | Use the name of the resource. If you’re tagging a shared document, you must use the full ARN of the document.|
| Parameter| Use the name of the resource. If you’re tagging a shared document, you must use the full ARN of the document.|
| OpsMetadata | `ResourceID` is created from the strings that come after the word `opsmetadata` in the ARN. For example, an OpsMetadata object with an ARN of `arn:aws:ssm:us-east-2:1234567890:opsmetadata/aws/ssm/MyGroup/appmanager` has a `ResourceID` of either `aws/ssm/MyGroup/appmanager` or `/aws/ssm/MyGroup/appmanager`.|


#### Context Output

There is no context output for this command.
#### Command example
```!aws-ssm-tag-add resource_id="test_id" resource_type=Document tag_key=test_key tag_value=test_value```
#### Human Readable Output

>Tags added to resource test_id successfully.
