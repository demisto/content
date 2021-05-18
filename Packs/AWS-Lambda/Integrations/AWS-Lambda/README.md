Amazon Web Services Serverless Compute service (lambda)

This integration was integrated and tested with version **2015-03-31** of AWS - Lambda.

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

Required AWS IAM Permissions and Roles for Lambda are documented [here](https://docs.aws.amazon.com/lambda/latest/dg/access-control-identity-based.html).

## Configure AWS - Lambda on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - Lambda.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | defaultRegion | AWS Default Region | False |
    | roleArn | Role Arn | False |
    | roleSessionName | Role Session Name | False |
    | sessionDuration | Role Session Duration | False |
    | access_key | Access Key | False |
    | secret_key | Secret Key | False |
    | timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout (for example 60) or also the connect timeout followed after a comma (for example 60,10). If a connect timeout is not specified a default of 10 second will be used. You may also override the value at the aws-lambda-invoke command. | False |
    | retries | The maximum retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. You may also override the value when executing the aws-lambda-invoke command. More details about the retries strategy is available [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html), | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-lambda-get-function
***
Returns the configuration information of the Lambda function and a presigned URL link to the .zip file you uploaded with CreateFunction so you can download the .zip file. Note that the URL is valid for up to 10 minutes. The configuration information is the same information you provided as parameters when uploading the function.  Use the Qualifier parameter to retrieve a published version of the function. Otherwise, returns the unpublished version ($LATEST ).
#### Required Permissions
* `AWSLambda_ReadOnlyAccess`: more details [here](https://docs.aws.amazon.com/lambda/latest/dg/security_iam_troubleshoot.html#security_iam_troubleshoot-admin-deprecation).
#### Base Command

`aws-lambda-get-function`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| functionName | The name of the Lambda function. | Required | 
| qualifier | Specify a version or alias to get details about a published version of the function. | Optional | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.Configuration.FunctionName | string | The name of the function. | 
| AWS.Lambda.Functions.Configuration.FunctionArn | string | The function's Amazon Resource Name. | 
| AWS.Lambda.Functions.Configuration.Runtime | string | The runtime environment for the Lambda function. | 
| AWS.Lambda.Functions.Configuration.Role | string | The function's execution role. | 
| AWS.Lambda.Functions.Configuration.Handler | string | The function Lambda calls to begin executing your function. | 
| AWS.Lambda.Functions.Configuration.CodeSize | string | The size of the function's deployment package in bytes. | 
| AWS.Lambda.Functions.Configuration.Description | string | The function's description. | 
| AWS.Lambda.Functions.Configuration.Timeout | number | The amount of time that Lambda allows a function to run before terminating it. | 
| AWS.Lambda.Functions.Configuration.MemorySize | number | The memory allocated to the function | 
| AWS.Lambda.Functions.Configuration.LastModified  | date | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.Functions.Configuration.CodeSha256 | string | The SHA256 hash of the function's deployment package. | 
| AWS.Lambda.Functions.Configuration.Version | string | The version of the Lambda function. | 
| AWS.Lambda.Functions.Configuration.VpcConfig.SubnetIds | string | A list of VPC subnet IDs. | 
| AWS.Lambda.Functions.Configuration.VpcConfig.SecurityGroupIds | string | A list of VPC security groups IDs. | 
| AWS.Lambda.Functions.Configuration.VpcConfig.VpcId | string | The ID of the VPC. | 
| AWS.Lambda.Functions.Configuration.DeadLetterConfig.TargetArn | string | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. | 
| AWS.Lambda.Functions.Configuration.Environment.Variables | string | Environment variable key-value pairs | 
| AWS.Lambda.Functions.Configuration.Environment.Error.ErrorCode | string | Error messages for environment variables that could not be applied. The error code. | 
| AWS.Lambda.Functions.Configuration.Environment. | string | Error messages for environment variables that could not be applied. The error message. | 
| AWS.Lambda.Functions.Configuration.KMSKeyArn | string | The KMS key used to encrypt the function's environment variables. Only returned if you've configured a customer managed CMK. | 
| AWS.Lambda.Functions.Configuration.TracingConfig.Mode | string | The function's AWS X-Ray tracing configuration. The tracing mode. | 
| AWS.Lambda.Functions.Configuration.MasterArn | string | The ARN of the master function. | 
| AWS.Lambda.Functions.Configuration.RevisionId | string | Represents the latest updated revision of the function or alias. | 
| AWS.Lambda.Functions.Configuration.Layers.Arn | string | The Amazon Resource Name \(ARN\) of the function layer. | 
| AWS.Lambda.Functions.Configuration.Layers.CodeSize | number | The size of the layer archive in bytes. | 
| AWS.Lambda.Functions.Code.RepositoryType | string | The repository from which you can download the function. | 
| AWS.Lambda.Functions.Code.Location | string | The presigned URL you can use to download the function's .zip file that you previously uploaded. The URL is valid for up to 10 minutes. | 
| AWS.Lambda.Functions.Tags | string | list of tags associated with the function. | 
| AWS.Lambda.Functions.Concurrency.ReservedConcurrentExecutions | string | The number of concurrent executions reserved for this function. | 


#### Command Example
```!aws-lambda-get-function functionName="test_echo"```

#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "Functions": {
                "Code": {
                    "Location": "https://awslambda-us-west-2-tasks.s3.us-west-2.amazonaws.com/snapshots/123456789012/test_echo-f4e5b684-10bb-4341-9701-2ec77a3a9455?versionId=EkrCKdR3NiLj4WMGnl4FW7Emnp2LwVj9&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEAkaCXVzLXdlc3QtMiJGMEQCIB97MBosyyMTyFoHXZWE7%2FSLrXNfaxPkqt9JvcPaKCQSAiAedNNcQXK%2B1dKV7bMOjfza9DxC9XTPnuyVauIb0kWeTCq9AwjC%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAMaDDUwMjI5NzA3NjE2MyIMWFyriTbErPSEhGT7KpEDpyrzGUskWDr%2BghzqocY6ZUY%2BWEdDvKrEyUP8CdQFw2SSmn4vXxhFBocUkayPWdpj%2Bxj%2BcjrBh4vHwo5b9GmMJE36omzIiDIyIPcNiBDViHN%2FoaG3YLsDkOxhdLw%2BdB4Z80QwcO61YUXQtFV5CNLmMpCbqNhZ8W%2By0M1nr6ZuEX3NThpWC0e%2BdSPcKzTqTVGo8SjeOMxYeZu5d%2BLkkG1a0wIfxjrYbf1LBIsOdewkNyQa5crt7NEs7ZbFqKe21%2F5v%2BmJudanK6M76U84GRVR0KiRY%2FDuYnFzGWTvi8pWwHvi85tiAd32Nx5SQiqim97hwv53kyyXnkFSIasT76yzQEuRsVlS6TSsMKW8FOOwRwj0ho5a9cPuC5lY0OlAjmJX2r8ruoFJqifDxNjPlErjYe2AvCSIf6Hb28J1RcUC6k%2FS2QC1Y%2Foiy8qWXah8ssDwQXVtmFTtDq8KC1KDXPVOL75zN4wyT7mW18GXXR3%2BAY40U1Rt%2FZsWoqqeb7qkDGevzaLJ1BeOSo53BbQDRC8DxCSkww9PC%2FwU67AFLZ6OqozcNsNierzQTWiHEtk89qOcU8q6glYLPr9kqhS4Hqh7Qbt1tytfGRUHoRiF4vYDYa1oQtEY%2BuG3qvyWTQogSsXUrt%2BvjeOp47uvaGrzUnMfQllgGHgvei2KeOvxQQl4dRuYdhelWbIXFB6HYtnTQ8BvEW401tkgNh41OEw%2F2w7BYBPee3K16MeyLJDlb2eO0Qpe4isP%2BtJgQQRofapkYAkasB7li5Tw8E0EP%2BB5Vi2YT0Dc0Uer6ltKBwuixPJtA6Ul6h6Epcyu61gka8FHsFxjxAMh0d%2B9xZJU5yfiFIm6FE1yo4WbZAQ%3D%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20210102T175325Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIAXJ4Z5EHB73ALY3PB%2F20210102%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Signature=80ef02ae7c589f7c11b2132ad3198ac43c8bbfa64951728f02693cb81b01a494",
                    "RepositoryType": "S3"
                },
                "Configuration": {
                    "CodeSha256": "nhHf3duE8nsbpBFqk1jH/7FrnOwOTXxpjwJJW5IWRDw=",
                    "CodeSize": 394,
                    "Description": "",
                    "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_echo",
                    "FunctionName": "test_echo",
                    "Handler": "handler.test_echo",
                    "LastModified": "2020-12-31T09:12:56.676+0000",
                    "LastUpdateStatus": "Successful",
                    "MemorySize": 128,
                    "PackageType": "Zip",
                    "RevisionId": "d501879f-a589-44fa-92d2-7a984601e289",
                    "Role": "arn:aws:iam::123456789012:role/serverlessrepo-magic-8-ball-Magic8BallRole-11JS8GYNU5JM1",
                    "Runtime": "nodejs12.x",
                    "State": "Active",
                    "Timeout": 3,
                    "TracingConfig": {
                        "Mode": "PassThrough"
                    },
                    "Version": "$LATEST"
                },
                "Region": "us-west-2",
                "ResponseMetadata": {
                    "HTTPHeaders": {
                        "connection": "keep-alive",
                        "content-length": "2642",
                        "content-type": "application/json",
                        "date": "Sat, 02 Jan 2021 17:53:25 GMT",
                        "x-amzn-requestid": "dfbe644c-b2bd-45ae-bb75-d6356c25041b"
                    },
                    "HTTPStatusCode": 200,
                    "RequestId": "dfbe644c-b2bd-45ae-bb75-d6356c25041b",
                    "RetryAttempts": 0
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Lambda Functions
>|FunctionArn|FunctionName|Region|Runtime|
>|---|---|---|---|
>| arn:aws:lambda:us-west-2:123456789012:function:test_echo | test_echo | us-west-2 | nodejs12.x |


### aws-lambda-list-functions
***
Returns a list of your Lambda functions. For each function, the response includes the function configuration information. You must use GetFunction to retrieve the code for your function.
#### Required Permissions
* `AWSLambda_ReadOnlyAccess`: more details [here](https://docs.aws.amazon.com/lambda/latest/dg/security_iam_troubleshoot.html#security_iam_troubleshoot-admin-deprecation).
#### Base Command

`aws-lambda-list-functions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.FunctionName | string | The name of the function. | 
| AWS.Lambda.Functions.FunctionArn | string | The function's Amazon Resource Name. | 
| AWS.Lambda.Functions.Runtime | string | The runtime environment for the Lambda function. | 
| AWS.Lambda.Functions.Role | string | The function's execution role. | 
| AWS.Lambda.Functions.Handler | string | The function Lambda calls to begin executing your function. | 
| AWS.Lambda.Functions.CodeSize | number | The size of the function's deployment package in bytes. | 
| AWS.Lambda.Functions.Description | string | The function's description. | 
| AWS.Lambda.Functions.Timeout | number | The amount of time that Lambda allows a function to run before terminating it. | 
| AWS.Lambda.Functions.MemorySize | number | The memory allocated to the function. | 
| AWS.Lambda.Functions.LastModified | date | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.Functions.CodeSha256 | string | The SHA256 hash of the function's deployment package. | 
| AWS.Lambda.Functions.Version | string | The version of the Lambda function. | 
| AWS.Lambda.Functions.VpcConfig.SubnetIds | string | A list of VPC subnet IDs. | 
| AWS.Lambda.Functions.VpcConfig.SecurityGroupIds | string | A list of VPC security groups IDs. | 
| AWS.Lambda.Functions.VpcConfig.VpcId | string | The ID of the VPC. | 
| AWS.Lambda.Functions.DeadLetterConfig.TargetArn | string | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. | 
| AWS.Lambda.Functions.Environment.Variables | string | Environment variable key-value pairs. | 
| AWS.Lambda.Functions.Environment.Error.ErrorCode | string | Error messages for environment variables that could not be applied. The error code. | 
| AWS.Lambda.Functions.Environment.Error.Message | string | Error messages for environment variables that could not be applied. The error message. | 
| AWS.Lambda.Functions.KMSKeyArn | string | The KMS key used to encrypt the function's environment variables. Only returned if you've configured a customer managed CMK. | 
| AWS.Lambda.Functions.TracingConfig.Mode | string | The function's AWS X-Ray tracing configuration. The tracing mode. | 
| AWS.Lambda.Functions.MasterArn | string | The ARN of the master function. | 
| AWS.Lambda.Functions.RevisionId | string | Represents the latest updated revision of the function or alias. | 
| AWS.Lambda.Functions.Layers.Arn | string | The Amazon Resource Name \(ARN\) of the function layer. | 
| AWS.Lambda.Functions.Layers.CodeSize | string | The size of the layer archive in bytes. | 


#### Command Example
```!aws-lambda-list-functions```

#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "Functions": {
                "Functions": [
                    {
                        "CodeSha256": "oP52F3PYjPdGbkzKpA3yjmjQj1AmoujE5LjEu4V6It0=",
                        "CodeSize": 370,
                        "Description": "",
                        "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_sleep",
                        "FunctionName": "test_sleep",
                        "Handler": "handler.test_sleep",
                        "LastModified": "2020-12-30T16:15:55.726+0000",
                        "MemorySize": 128,
                        "PackageType": "Zip",
                        "RevisionId": "a5094b27-e339-4362-bb69-c82c1fde4376",
                        "Role": "arn:aws:iam::123456789012:role/serverlessrepo-magic-8-ball-Magic8BallRole-11JS8GYNU5JM1",
                        "Runtime": "nodejs12.x",
                        "Timeout": 180,
                        "TracingConfig": {
                            "Mode": "PassThrough"
                        },
                        "Version": "$LATEST"
                    },
                    {
                        "CodeSha256": "nhHf3duE8nsbpBFqk1jH/7FrnOwOTXxpjwJJW5IWRDw=",
                        "CodeSize": 394,
                        "Description": "",
                        "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_echo",
                        "FunctionName": "test_echo",
                        "Handler": "handler.test_echo",
                        "LastModified": "2020-12-31T09:12:56.676+0000",
                        "MemorySize": 128,
                        "PackageType": "Zip",
                        "RevisionId": "d501879f-a589-44fa-92d2-7a984601e289",
                        "Role": "arn:aws:iam::123456789012:role/serverlessrepo-magic-8-ball-Magic8BallRole-11JS8GYNU5JM1",
                        "Runtime": "nodejs12.x",
                        "Timeout": 3,
                        "TracingConfig": {
                            "Mode": "PassThrough"
                        },
                        "Version": "$LATEST"
                    },
                    {
                        "CodeSha256": "yUnb5Nsw5KQzQGj0EBR2meRebGpDy3VuYjNPFA1PsNw=",
                        "CodeSize": 271667,
                        "Description": "",
                        "FunctionArn": "arn:aws:lambda:us-west-2:123456789012:function:testingFunction",
                        "FunctionName": "testingFunction",
                        "Handler": "index.handler",
                        "LastModified": "2019-02-20T15:33:28.335+0000",
                        "MemorySize": 128,
                        "PackageType": "Zip",
                        "RevisionId": "08674053-884d-4a08-8803-a92374b84386",
                        "Role": "arn:aws:iam::123456789012:role/service-role/testingRoleLambda",
                        "Runtime": "nodejs8.10",
                        "Timeout": 3,
                        "TracingConfig": {
                            "Mode": "PassThrough"
                        },
                        "Version": "$LATEST"
                    }
                ],
                "Region": "us-west-2",
                "ResponseMetadata": {
                    "HTTPHeaders": {
                        "connection": "keep-alive",
                        "content-length": "2741",
                        "content-type": "application/json",
                        "date": "Sat, 02 Jan 2021 17:53:23 GMT",
                        "x-amzn-requestid": "5c5115b5-22fa-4f1a-a981-04847a54fe58"
                    },
                    "HTTPStatusCode": 200,
                    "RequestId": "5c5115b5-22fa-4f1a-a981-04847a54fe58",
                    "RetryAttempts": 0
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Lambda Functions
>|FunctionArn|FunctionName|LastModified|Region|Runtime|
>|---|---|---|---|---|
>| arn:aws:lambda:us-west-2:123456789012:function:test_sleep | test_sleep | 2020-12-30T16:15:55.726+0000 | us-west-2 | nodejs12.x |
>| arn:aws:lambda:us-west-2:123456789012:function:test_echo | test_echo | 2020-12-31T09:12:56.676+0000 | us-west-2 | nodejs12.x |
>| arn:aws:lambda:us-west-2:123456789012:function:testingFunction | testingFunction | 2019-02-20T15:33:28.335+0000 | us-west-2 | nodejs8.10 |


### aws-lambda-list-aliases
***
Returns list of aliases created for a Lambda function. For each alias, the response includes information such as the alias ARN, description, alias name, and the function version to which it points.
#### Required Permissions
* `AWSLambda_ReadOnlyAccess`: more details [here](https://docs.aws.amazon.com/lambda/latest/dg/security_iam_troubleshoot.html#security_iam_troubleshoot-admin-deprecation).
#### Base Command

`aws-lambda-list-aliases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| functionName | The name of the lambda function. | Required | 
| functionVersion | If you specify this optional parameter, the API returns only the aliases that are pointing to the specific Lambda function version, otherwise the API returns all of the aliases created for the Lambda function. | Optional | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Aliases.AliasArn | string | Lambda function ARN that is qualified using the alias name as the suffix.  | 
| AWS.Lambda.Aliases.Name | string | Alias name. | 
| AWS.Lambda.Aliases.FunctionVersion | string | Function version to which the alias points. | 
| AWS.Lambda.Aliases.Description | string | Alias description. | 
| AWS.Lambda.Aliases.RoutingConfig.AdditionalVersionWeights | string | The name of the second alias, and the percentage of traffic that is routed to it. | 
| AWS.Lambda.Aliases.RevisionId | string | Represents the latest updated revision of the function or alias. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-lambda-invoke
***
Invokes a Lambda function. Specify just a function name to invoke the latest version of the function. To invoke a published version, use the Qualifier parameter to specify a version or alias .  If you use the RequestResponse (synchronous) invocation option, note that the function may be invoked multiple times if a timeout is reached. For functions with a long timeout, your client may be disconnected during synchronous invocation while it waits for a response. Use the "timeout" and "retries" args to control this behavior. If you use the Event (asynchronous) invocation option, the function will be invoked at least once in response to an event and the function must be idempotent to handle this.
#### Required Permissions
* `AWSLambdaRole`: more details [here](https://docs.aws.amazon.com/lambda/latest/dg/access-control-identity-based.html).
#### Base Command

`aws-lambda-invoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| functionName | The name of the Lambda function. | Required | 
| invocationType | Choose from the following options.  RequestResponse (default) - Invoke the function synchronously. Keep the connection open until the function returns a response or times out. Event - Invoke the function asynchronously. Send events that fail multiple times to the function's dead-letter queue (if configured). DryRun - Validate parameter values and verify that the user or role has permission to invoke the function. Possible values are: Event, RequestResponse, DryRun. | Optional | 
| logType | You can set this optional parameter to Tail in the request only if you specify the InvocationType parameter with value RequestResponse . In this case, AWS Lambda returns the base64-encoded last 4 KB of log data produced by your Lambda function in the x-amz-log-result header. Possible values are: None, Tail. | Optional | 
| clientContext | Using the ClientContext you can pass client-specific information to the Lambda function you are invoking. . | Optional | 
| payload | JSON that you want to provide to your Lambda function as input. | Optional | 
| qualifier | Specify a version or alias to invoke a published version of the function. | Optional | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| retries | The maximum retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. If not specified will use the instances configured default timeout. | Optional | 
| timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout (for example 60) or also the connect timeout followed after a comma (for example 60,10). If not specified will use the instances configured default timeout. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.InvokedFunctions.FunctionName | string | The name of the Lambda function. | 
| AWS.Lambda.InvokedFunctions.FunctionError | string | Indicates whether an error occurred while executing the Lambda function. If an error occurred this field will have one of two values; Handled or Unhandled . Handled errors are errors that are reported by the function while the Unhandled errors are those detected and reported by AWS Lambda. Unhandled errors include out of memory errors and function timeouts. | 
| AWS.Lambda.InvokedFunctions.LogResult | string | logs for the Lambda function invocation. This is present only if the invocation type is RequestResponse and the logs were requested. | 
| AWS.Lambda.InvokedFunctions.Payload | string | It is the JSON representation of the object returned by the Lambda function. This is present only if the invocation type is RequestResponse. | 
| AWS.Lambda.InvokedFunctions.ExecutedVersion | string | The function version that has been executed. This value is returned only if the invocation type is RequestResponse. | 
| AWS.Lambda.InvokedFunctions.Region | string | The AWS Region. | 


#### Command Example
```!aws-lambda-invoke functionName="test_echo" logType="Tail" payload="{\"value\":\"test\"}"```

#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "InvokedFunctions": {
                "ExecutedVersion": "$LATEST",
                "FunctionName": "test_echo",
                "LogResult": "START RequestId: c24e087f-5c05-4e92-a1a8-e54f2d6cd925 Version: $LATEST\nEND RequestId: c24e087f-5c05-4e92-a1a8-e54f2d6cd925\nREPORT RequestId: c24e087f-5c05-4e92-a1a8-e54f2d6cd925\tDuration: 16.00 ms\tBilled Duration: 16 ms\tMemory Size: 128 MB\tMax Memory Used: 65 MB\tInit Duration: 133.86 ms\t\n",
                "Payload": "{\"message\":\"Your function executed successfully!\",\"payload\":{\"value\":\"test\"}}",
                "Region": "us-west-2"
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Lambda Invoked Functions
>|ExecutedVersion|FunctionName|LogResult|Payload|Region|
>|---|---|---|---|---|
>| $LATEST | test_echo | START RequestId: c24e087f-5c05-4e92-a1a8-e54f2d6cd925 Version: $LATEST<br/>END RequestId: c24e087f-5c05-4e92-a1a8-e54f2d6cd925<br/>REPORT RequestId: c24e087f-5c05-4e92-a1a8-e54f2d6cd925	Duration: 16.00 ms	Billed Duration: 16 ms	Memory Size: 128 MB	Max Memory Used: 65 MB	Init Duration: 133.86 ms	<br/> | {"message":"Your function executed successfully!","payload":{"value":"test"}} | us-west-2 |


### aws-lambda-get-account-settings
***
Retrieves details about your account's limits and usage in an AWS Region.
#### Required Permissions
* `AWSLambda_ReadOnlyAccess`: more details [here](https://docs.aws.amazon.com/lambda/latest/dg/security_iam_troubleshoot.html#security_iam_troubleshoot-admin-deprecation).
#### Base Command

`aws-lambda-get-account-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.AccountLimit.TotalCodeSize | number | The amount of storage space that you can use for all deployment packages and layer archives. | 
| AWS.Lambda.AccountLimit.CodeSizeUnzipped | number | The maximum size of your function's code and layers when they're extracted. | 
| AWS.Lambda.AccountLimit.CodeSizeZipped | number | The maximum size of a deployment package when it's uploaded directly to AWS Lambda. Use Amazon S3 for larger files. | 
| AWS.Lambda.AccountLimit.ConcurrentExecutions | number | The maximum number of simultaneous function executions. | 
| AWS.Lambda.AccountLimit.UnreservedConcurrentExecutions | number | The maximum number of simultaneous function executions, minus the capacity that's reserved for individual functions with PutFunctionConcurrency . | 
| AWS.Lambda.AccountUsage.TotalCodeSize | number | The amount of storage space, in bytes, that's being used by deployment packages and layer archives. | 
| AWS.Lambda.AccountUsage. FunctionCount | number | The number of Lambda functions. | 


#### Command Example
```!aws-lambda-get-account-settings```

#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "Functions": {
                "AccountLimit": {
                    "CodeSizeUnzipped": 262144000,
                    "CodeSizeZipped": 52428800,
                    "ConcurrentExecutions": 1000,
                    "TotalCodeSize": 80530636800,
                    "UnreservedConcurrentExecutions": 1000
                },
                "AccountUsage": {
                    "FunctionCount": 3,
                    "TotalCodeSize": 272431
                },
                "Region": "us-west-2",
                "ResponseMetadata": {
                    "HTTPHeaders": {
                        "connection": "keep-alive",
                        "content-length": "393",
                        "content-type": "application/json",
                        "date": "Sat, 02 Jan 2021 17:53:27 GMT",
                        "x-amzn-requestid": "2030cf7b-b4f7-4f57-b13b-1572cdaa3286"
                    },
                    "HTTPStatusCode": 200,
                    "RequestId": "2030cf7b-b4f7-4f57-b13b-1572cdaa3286",
                    "RetryAttempts": 0
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Lambda Functions
>|AccountLimit|AccountUsage|
>|---|---|
>| TotalCodeSize: 80530636800<br/>CodeSizeUnzipped: 262144000<br/>CodeSizeZipped: 52428800<br/>ConcurrentExecutions: 1000<br/>UnreservedConcurrentExecutions: 1000 | TotalCodeSize: 272431<br/>FunctionCount: 3 |

