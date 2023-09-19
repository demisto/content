Amazon Web Services Identity and Access Management Identity Center(IAM)

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).


## Configure AWS - IAM Identity Center on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - IAM Identity Center.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | roleArn | Role Arn | False |
    | roleSessionName | Role Session Name | False |
    | defaultRegion | AWS Default Region | False |
    | sessionDuration | Role Session Duration | False |
    | access_key | Access Key | True |
    | secret_key | Secret Key | True |
    | IdentityStoreId | Identity Store Id | True |
    | timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | insecure | Trust any certificate (not secure) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-iam-identitycenter-create-user
***
Creates a new IAM Identity Center user for your AWS account.


#### Base Command

`aws-iam-identitycenter-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| userName | The name of the user to create. | Required | 
| familyName | The family name of the user to create. | Required | 
| givenName | The first name of the user to create. | Required | 
| userEmailAddress | The email address of the user to create. | Required | 
| displayName | The display name of the user to create. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.IAMIdentityCenter.Users.UserId | string | The stable and unique string identifying the user. | 


#### Command Example
```!aws-iam-identitycenter-create-user userName=Test familyName=Test givenName=Test userEmailAddress=test@test.com displayName="Test Test"```

