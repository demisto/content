Amazon Web Services Serverless Compute service (lambda)

This integration was integrated and tested with version **2015-03-31** of AWS - Lambda.

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

Required AWS IAM Permissions and Roles for Lambda are documented [here](https://docs.aws.amazon.com/lambda/latest/dg/access-control-identity-based.html).

## Configure AWS - Lambda in Cortex


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
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. You may also override the value at the aws-lambda-invoke command. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. You may also override the value when executing the aws-lambda-invoke command. | False |
| PrivateLink service URL. |  | False |
| STS PrivateLink URL |  | False |
| AWS STS Regional Endpoints | Sets the AWS_STS_REGIONAL_ENDPOINTS environment variable to specify the AWS STS endpoint resolution logic. By default, this option is set to “legacy” in AWS. Leave empty if the environment variable is already set using server configuration. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| AWS.Lambda.Functions.Configuration.LastModified | date | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.Functions.Configuration.CodeSha256 | string | The SHA256 hash of the function's deployment package. | 
| AWS.Lambda.Functions.Configuration.Version | string | The version of the Lambda function. | 
| AWS.Lambda.Functions.Configuration.VpcConfig.SubnetIds | string | A list of VPC subnet IDs. | 
| AWS.Lambda.Functions.Configuration.VpcConfig.SecurityGroupIds | string | A list of VPC security groups IDs. | 
| AWS.Lambda.Functions.Configuration.VpcConfig.VpcId | string | The ID of the VPC. | 
| AWS.Lambda.Functions.Configuration.DeadLetterConfig.TargetArn | string | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. | 
| AWS.Lambda.Functions.Configuration.Environment.Variables | string | Environment variable key-value pairs. | 
| AWS.Lambda.Functions.Configuration.Environment.Error.ErrorCode | string | The error code for environment variables that could not be applied. | 
| AWS.Lambda.Functions.Configuration.Environment.Error.Message | string | The error message for environment variables that could not be applied. |
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
Invokes a Lambda function. Specify just a function name to invoke the latest version of the function. To invoke a published version, use the Qualifier parameter to specify a version or alias.  If you use the RequestResponse (synchronous) invocation option, note that the function may be invoked multiple times if a timeout is reached. For functions with a long timeout, your client may be disconnected during synchronous invocation while it waits for a response. Use the "timeout" and "retries" arguments to control this behavior. If you use the Event (asynchronous) invocation option, the function will be invoked at least once in response to an event and the function must be idempotent to handle this.

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
| clientContext | Using the ClientContext you can pass client-specific information to the Lambda function you are invoking. | Optional | 
| payload | JSON that you want to provide to your Lambda function as input. | Optional | 
| qualifier | Specify a version or alias to invoke a published version of the function. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| retries | The maximum retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. If not specified, will use the instances configured default timeout. | Optional | 
| timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout (for example 60) or also the connect timeout followed after a comma (for example 60,10). If not specified, will use the instances configured default timeout. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.InvokedFunctions.FunctionName | string | The name of the Lambda function. | 
| AWS.Lambda.InvokedFunctions.FunctionError | string | Indicates whether an error occurred while executing the Lambda function. If an error occurred this field will have one of two values; Handled or Unhandled. Handled errors are errors that are reported by the function while the Unhandled errors are those detected and reported by AWS Lambda. Unhandled errors include out of memory errors and function timeouts. | 
| AWS.Lambda.InvokedFunctions.LogResult | string | Logs for the Lambda function invocation. This is present only if the invocation type is RequestResponse and the logs were requested. | 
| AWS.Lambda.InvokedFunctions.Payload | string | The JSON representation of the object returned by the Lambda function. This is present only if the invocation type is RequestResponse. | 
| AWS.Lambda.InvokedFunctions.ExecutedVersion | string | The function version that has been executed. This value is returned only if the invocation type is RequestResponse. | 
| AWS.Lambda.InvokedFunctions.Region | string | The AWS Region. | 
| AWS.Lambda.InvokedFunctions.RequestPayload | unknown | The JSON representation of the object passed to the Lambda function as input. | 


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
| region | The AWS Region. If not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
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


 ### aws-lambda-get-policy

***
Returns the resource-based IAM policy for a function, version, or alias.

#### Base Command

`aws-lambda-get-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| functionName | The name of the Lambda function, version, or alias. You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Policy.Version | String | The version of the policy. | 
| AWS.Lambda.Policy.Id | String | The ID of the policy. | 
| AWS.Lambda.Policy.Statement.Sid | String | The statement ID within the policy. | 
| AWS.Lambda.Policy.Statement.Effect | String | The effect \(allow/deny\) specified in the policy statement. | 
| AWS.Lambda.Policy.Statement.Principal.AWS | String | The AWS principal ARN specified in the AWS Lambda policy statement. | 
| AWS.Lambda.Policy.Statement.Action | String | The action specified in the AWS Lambda policy statement. | 
| AWS.Lambda.Policy.Statement.Resource | String | The resource ARN specified in the AWS Lambda policy statement. | 
| AWS.Lambda.RevisionId | String | A unique identifier for the current revision of the policy. | 

#### Command example
```!aws-lambda-get-policy functionName="test"```
#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "Policy": {
                "Id": "default",
                "Statement": [
                    {
                        "Action": "lambda",
                        "Condition": {
                            "ArnLike": {
                                "AWS:SourceArn": "arn:aws:dummy-api:dummy:12345678:dummy/*/*/test"
                            }
                        },
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "apidummy.dummy.com"
                        },
                        "Resource": "arn:aws:dummy-api:dummy:12345678:dummy/*/*/test",
                        "Sid": "lambda-1111-1111-1111-1111-1111"
                    }
                ],
                "Version": "2012-10-17"
            },
            "RevisionId": "1111-1111-111-111-11111"
        }
    }
}
```

#### Human Readable Output

>### Policy
>|Action|Effect|Id|Resource|RevisionId|Sid|Version|Principal|
>|---|---|---|---|---|---|---|
>| lambda | Allow | default | arn:aws:dummy-api:dummy:12345678:dummy/*/*/test | 1111-1111-111-111-11111 | arn:aws:dummy-api:dummy:12345678:dummy/*/*/test | 2015-10-17 | apidummy.dummy.com |


### aws-lambda-list-versions-by-function

***
Returns a list of versions, with the version-specific configuration of each.

#### Base Command

`aws-lambda-list-versions-by-function`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| functionName | The name of the Lambda function, version, or alias. You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length. | Required | 
| Marker | Specify the pagination token that’s returned by a previous request to retrieve the next page of results. | Optional | 
| MaxItems | The maximum number of versions to return. Note that ListVersionsByFunction returns a maximum of 50 items in each response, even if you set the number higher. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.NextMarker | String | The pagination token that's included if more results are available. | 
| AWS.Lambda.Versions.FunctionName | String | The name of the function. | 
| AWS.Lambda.Versions.FunctionArn | String | The function’s Amazon Resource Name \(ARN\). | 
| AWS.Lambda.Versions.Runtime | String | The identifier of the function’s runtime. Runtime is required if the deployment package is a .zip file archive. | 
| AWS.Lambda.Versions.Role | String | The function’s execution role. | 
| AWS.Lambda.Versions.Handler | String | The function that Lambda calls to begin running your function. | 
| AWS.Lambda.Versions.CodeSize | Number | The size of the function’s deployment package, in bytes. | 
| AWS.Lambda.Versions.Description | String | The function’s description. | 
| AWS.Lambda.Versions.Timeout | Number | The amount of time in seconds that Lambda allows a function to run before stopping it. | 
| AWS.Lambda.Versions.MemorySize | Number | The amount of memory available to the function at runtime. | 
| AWS.Lambda.Versions.LastModified | String | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.Versions.CodeSha256 | String | The SHA256 hash of the function’s deployment package. | 
| AWS.Lambda.Versions.Version | String | The version of the Lambda function. | 
| AWS.Lambda.Versions.VpcConfig.SubnetIds | String | A list of VPC subnet IDs. | 
| AWS.Lambda.Versions.VpcConfig.SecurityGroupIds | String | A list of VPC security group IDs. | 
| AWS.Lambda.Versions.VpcConfig.VpcId | String | The ID of the VPC. | 
| AWS.Lambda.Versions.DeadLetterConfig.TargetArn | String | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. | 
| AWS.Lambda.Versions.Environment.Variables.string | String | Environment variable key-value pairs. Omitted from CloudTrail logs. | 
| AWS.Lambda.Versions.Environment.Error.ErrorCode | String | The error code for environment variables that couldn't be applied. | 
| AWS.Lambda.Versions.Environment.Error.Message | String | The error message for environment variables that couldn't be applied. | 
| AWS.Lambda.Versions.KMSKeyArn | String | The ARN of the KMS key used to encrypt the function's environment variables. | 
| AWS.Lambda.Versions.TracingConfig.Mode | String | The tracing mode for the Lambda function. | 
| AWS.Lambda.Versions.MasterArn | String | The ARN of the main function for Lambda@Edge functions. | 
| AWS.Lambda.Versions.FunctionVersion | String | The specific function version. | 
| AWS.Lambda.Versions.Tags | Object | The tags assigned to the Lambda function. | 
| AWS.Lambda.Versions.State | String | The current state of the function. When the state is Inactive, you can reactivate the function by invoking it. | 
| AWS.Lambda.Versions.StateReason | String | The reason for the function’s current state. | 
| AWS.Lambda.Versions.StateReasonCode | String | The reason code for the current state of the function. | 
| AWS.Lambda.Versions.LastUpdateStatus | String | The status of the last update that was performed on the function. This is first set to Successful after function creation completes. | 
| AWS.Lambda.Versions.LastUpdateStatusReason | String | The reason for the last update that was performed on the function. | 
| AWS.Lambda.Versions.LastUpdateStatusReasonCode | String | The reason code for the last update operation status. | 
| AWS.Lambda.Versions.PackageType | String | The type of deployment package. Set to Image for container image and set Zip for .zip file archive. | 
| AWS.Lambda.Versions.ImageConfigResponse.ImageConfigError.ErrorCode | String | The error code for image configuration. | 
| AWS.Lambda.Versions.ImageConfigResponse.ImageConfigError.Message | String | The error message for image configuration. | 
| AWS.Lambda.Versions.ImageConfigResponse.ImageConfigError.Type | String | The error type for image configuration. | 
| AWS.Lambda.Versions.ImageConfigResponse.ImageConfig | Object | The image configuration values. | 

#### Command example
```!aws-lambda-list-versions-by-function functionName=test```
#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "Versions": [
                {
                    "Architectures": [
                        "test"
                    ],
                    "CodeSha256": "111111111111111",
                    "CodeSize": 111,
                    "Description": "",
                    "EphemeralStorage": {
                        "Size": 111
                    },
                    "FunctionArn": "arn:aws:dummy-api:dummy:12345678:dummy/*/*/test",
                    "FunctionName": "test",
                    "Handler": "handler",
                    "LastModified": "2024-06-05T11:54:29.646+0000",
                    "MemorySize": 128,
                    "PackageType": "Zip",
                    "RevisionId": "11111-11111-1111",
                    "Role": "dummyy.111111:role/dummy-role/test-role-11111",
                    "Runtime": "nodejs18.x",
                    "SnapStart": {
                        "ApplyOn": "None",
                        "OptimizationStatus": "Off"
                    },
                    "Timeout": 3,
                    "TracingConfig": {
                        "Mode": "PassThrough"
                    },
                    "Version": "$LATEST"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Versions
>|Function Name|Role|Runtime|Last Modified|State|Description|
>|---|---|---|---|---|---|
>| test | dummy.111111:role/dummy-role/test-role-11111 | nodejs18.x | 2024-06-05T11:54:29.646+0000 |  |  |


### aws-lambda-get-function-url-config

***
Returns details about a Lambda function URL.

#### Base Command

`aws-lambda-get-function-url-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| functionName | The name of the Lambda function, version, or alias. You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length. | Required | 
| qualifier | The alias name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.FunctionURLConfig.FunctionUrl | String | The HTTP URL endpoint for the function. | 
| AWS.Lambda.FunctionURLConfig.FunctionArn | String | The Amazon Resource Name \(ARN\) of your function. | 
| AWS.Lambda.FunctionURLConfig.AuthType | String | The type of authentication that the function URL uses. Set to AWS_IAM if you want to restrict access to authenticated users only. Set to NONE if you want to bypass IAM authentication to create a public endpoint. | 
| AWS.Lambda.FunctionURLConfig.Cors.AllowCredentials | Boolean | Whether to allow cookies or other credentials in requests to the function URL. The default is false. | 
| AWS.Lambda.FunctionURLConfig.Cors.AllowHeaders | List | The HTTP headers that origins can include in requests to the function URL. For example Date, Keep-Alive, X-Custom-Header. | 
| AWS.Lambda.FunctionURLConfig.Cors.AllowMethods | List | The HTTP methods that are allowed when calling the function URL. For example GET, POST, DELETE, or the wildcard character \( \*\). | 
| AWS.Lambda.FunctionURLConfig.Cors.AllowOrigins | List | The origins that can access the function URL.You can list any number of specific origins, separated by a comma. For example https://www.example.com, http://localhost:8080. Alternatively, you can grant access to all origins using the wildcard character \( \*\). | 
| AWS.Lambda.FunctionURLConfig.Cors.ExposeHeaders | List | The HTTP headers in the function response that you want to expose to origins that call the function URL. For example Date, Keep-Alive, X-Custom-Header. | 
| AWS.Lambda.FunctionURLConfig.Cors.MaxAge | Number | The maximum amount of time, in seconds, that web browsers can cache results of a preflight request. By default, this is set to 0, which means that the browser doesn’t cache results. | 
| AWS.Lambda.FunctionURLConfig.CreationTime | String | When the function URL was created, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.FunctionURLConfig.LastModifiedTime | String | When the function URL configuration was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.FunctionURLConfig.InvokeMode | String | Use one of the following options: BUFFERED – This is the default option. Lambda invokes your function using the Invoke API operation. Invocation results are available when the payload is complete. The maximum payload size is 6 MB. RESPONSE_STREAM – Your function streams payload results as they become available. Lambda invokes your function using the InvokeWithResponseStream API operation. The maximum response payload size is 20 MB, however, you can request a quota increase. | 

#### Command example
```!aws-lambda-get-function-url-config functionName="test"```
#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "FunctionURLConfig": {
                "AuthType": "NONE",
                "CreationTime": "2024-05-02T07:23:12.573458Z",
                "FunctionArn": "dummy111111:role/dummy/test-11111",
                "FunctionUrl": "hxxps://dummy.com/",
                "InvokeMode": "BUFFERED",
                "LastModifiedTime": "2024-05-02T07:23:12.573458Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Function URL Config
>|Auth Type|Creation Time|Function Arn|Function Url|Invoke Mode|Last Modified Time|
>|---|---|---|---|---|---|
>| NONE | 2024-05-02T07:23:12.573458Z | dummy.111111:role/dummy/test-11111 | hxxps:<span>//</span>dummy.com/ | BUFFERED | 2024-05-02T07:23:12.573458Z |


### aws-lambda-get-function-configuration

***
Returns the version-specific settings of a Lambda function or version. The output includes only options that can vary between versions of a function.

#### Base Command

`aws-lambda-get-function-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| functionName | The name of the Lambda function, version, or alias. You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length. | Required | 
| qualifier | Specify a version or alias to get details about a published version of the function. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.FunctionConfig.FunctionName | String | The name of the function. | 
| AWS.Lambda.FunctionConfig.FunctionArn | String | The function’s Amazon Resource Name \(ARN\). | 
| AWS.Lambda.FunctionConfig.Runtime | String | The identifier of the function’s runtime. Runtime is required if the deployment package is a .zip file archive. | 
| AWS.Lambda.FunctionConfig.Role | String | The function’s execution role. | 
| AWS.Lambda.FunctionConfig.Handler | String | The function that Lambda calls to begin running your function. | 
| AWS.Lambda.FunctionConfig.CodeSize | Number | The size of the function’s deployment package, in bytes. | 
| AWS.Lambda.FunctionConfig.Description | String | The function’s description. | 
| AWS.Lambda.FunctionConfig.Timeout | Number | The amount of time in seconds that Lambda allows a function to run before stopping it. | 
| AWS.Lambda.FunctionConfig.MemorySize | Number | The amount of memory available to the function at runtime. | 
| AWS.Lambda.FunctionConfig.LastModified | String | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.FunctionConfig.CodeSha256 | String | The SHA256 hash of the function’s deployment package. | 
| AWS.Lambda.FunctionConfig.Version | String | The version of the Lambda function. | 
| AWS.Lambda.FunctionConfig.VpcConfig.SubnetIds | String | A list of VPC subnet IDs. | 
| AWS.Lambda.FunctionConfig.VpcConfig.SecurityGroupIds | String | A list of VPC security group IDs. | 
| AWS.Lambda.FunctionConfig.VpcConfig.VpcId | String | The ID of the VPC. | 
| AWS.Lambda.FunctionConfig.DeadLetterConfig.TargetArn | String | The Amazon Resource Name \(ARN\) of an Amazon SQS queue or Amazon SNS topic. | 
| AWS.Lambda.FunctionConfig.Environment.Variables.string | String | Environment variable key-value pairs. Omitted from CloudTrail logs. | 
| AWS.Lambda.FunctionConfig.Environment.Error.ErrorCode | String | The error code for environment variables that couldn't be applied. | 
| AWS.Lambda.FunctionConfig.Environment.Error.Message | String | The error message for environment variables that couldn't be applied. | 
| AWS.Lambda.FunctionConfig.KMSKeyArn | String | The ARN of the KMS key used to encrypt the function's environment variables. | 
| AWS.Lambda.FunctionConfig.TracingConfig.Mode | String | The tracing mode for the Lambda function. | 
| AWS.Lambda.FunctionConfig.MasterArn | String | The ARN of the main function for Lambda@Edge functions. | 
| AWS.Lambda.FunctionConfig.FunctionVersion | String | The specific function version. | 
| AWS.Lambda.FunctionConfig.Tags | Object | The tags assigned to the Lambda function. | 
| AWS.Lambda.FunctionConfig.State | String | The current state of the function. When the state is Inactive, you can reactivate the function by invoking it. | 
| AWS.Lambda.FunctionConfig.StateReason | String | The reason for the function’s current state. | 
| AWS.Lambda.FunctionConfig.StateReasonCode | String | The reason code for the current state of the function. | 
| AWS.Lambda.FunctionConfig.LastUpdateStatus | String | The status of the last update that was performed on the function. This is first set to Successful after function creation completes. | 
| AWS.Lambda.FunctionConfig.LastUpdateStatusReason | String | The reason for the last update that was performed on the function. | 
| AWS.Lambda.FunctionConfig.LastUpdateStatusReasonCode | String | The reason code for the last update operation status. | 
| AWS.Lambda.FunctionConfig.PackageType | String | The type of deployment package. Set to Image for container image and set Zip for .zip file archive. | 
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfigError.ErrorCode | String | The error code for image configuration. | 
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfigError.Message | String | The error message for image configuration. | 
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfigError.Type | String | The error type for image configuration. | 
| AWS.Lambda.FunctionConfig.ImageConfigResponse.ImageConfig | Object | The image configuration values. | 

#### Command example
```!aws-lambda-get-function-configuration functionName=test```
#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "FunctionConfig": {
                "Architectures": [
                    "x86"
                ],
                "CodeSha256": "111111/1111111",
                "CodeSize": 000,
                "Description": "",
                "EphemeralStorage": {
                    "Size": 000
                },
                "FunctionArn": "arn:aws:lambda:dummy1111:function:test",
                "FunctionName": "test",
                "Handler": "handler",
                "LastModified": "2024-06-05T11:54:29.646+0000",
                "LastUpdateStatus": "Successful",
                "MemorySize": 128,
                "PackageType": "Zip",
                "RevisionId": "11111-1111-11111",
                "Role": "11111:role/dummy-role/test-role-11111",
                "Runtime": "nodejs18.x",
                "RuntimeVersionConfig": {
                    "RuntimeVersionArn": "arn:aws:lambda:dummy::runtime11111111"
                },
                "SnapStart": {
                    "ApplyOn": "None",
                    "OptimizationStatus": "Off"
                },
                "State": "Active",
                "Timeout": 3,
                "TracingConfig": {
                    "Mode": "PassThrough"
                },
                "Version": "$LATEST"
            }
        }
    }
}
```

#### Human Readable Output

>### Function Configuration
>|Code Sha256|Description|Function Arn|Function Name|Revision Id|Runtime|State|
>|---|---|---|---|---|---|---|
>| 11111111 |  | dummy:role/dummy-role/test-role-11111 | test | 11111-11111-111 | nodejs18.x | Active |


### aws-lambda-delete-function-url-config

***
Deletes a Lambda function URL. When you delete a function URL, you can’t recover it. Creating a new function URL results in a different URL address.

#### Base Command

`aws-lambda-delete-function-url-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| functionName | The name of the Lambda function, version, or alias. You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length. | Required | 
| qualifier | Specify a version or alias to get details about a published version of the function. | Optional | 

#### Context Output

There is no context output for this command.
### aws-lambda-delete-function

***
Deletes a Lambda function. To delete a specific function version, use the Qualifier parameter. Otherwise, all versions and aliases are deleted.

#### Base Command

`aws-lambda-delete-function`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| functionName | The name of the Lambda function, version, or alias. You can append a version number or alias to any of the formats. The length constraint applies only to the full ARN. If you specify only the function name, it is limited to 64 characters in length. | Required | 
| qualifier | Specify a version or alias to get details about a published version of the function. | Optional | 

#### Context Output

There is no context output for this command.
### aws-lambda-create-function

***
Creates a Lambda function. To create a function, you need a deployment package and an execution role.

#### Base Command

`aws-lambda-create-function`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| functionName | The name of the Lambda function. | Required | 
| runtime | The runtime environment for the function. | Required | 
| handler | The name of the method within your code that Lambda calls to execute your function. Example: lambda_function.lambda_handler'. | Required | 
| code | Entry ID of the uploaded base64-encoded contents of the deployment package. Amazon Web Services SDK and CLI clients handle the encoding for you. | Optional | 
| S3-bucket | An Amazon S3 bucket in the same Amazon Web Services Region as your function. The bucket can be in a different Amazon Web Services account. | Optional | 
| description | A description of the function. | Optional | 
| functionTimeout | The amount of time that Lambda allows a function to run before stopping it. Default is 3. | Optional | 
| memorySize | The amount of memory available to the function at runtime. Default is 128. | Optional | 
| publish | Set to true to publish the first version of the function during creation. Possible values are: True, False. | Optional | 
| vpcConfig | Json string contains SubnetIds - list of VPC subnet IDs, SecurityGroupIds - A list of VPC security group IDs,  and boolean Ipv6AllowedForDualStack - allows outbound IPv6 traffic. | Optional | 
| packageType | The type of deployment package. Possible values are: Image, Zip. | Optional | 
| environment | The environment variables for the function. Should be given as key-value pairs in a json string. | Optional | 
| tracingConfig | The tracing configuration for the function. Set to Active to sample and trace a subset of incoming requests with X-Ray. Default is Active. | Optional | 
| tags | The list of tags to apply to the function. | Optional | 
| role | The Amazon Resource Name (ARN) of the function’s execution role. | Required | 
| layers | A list of function layers to add to the function's execution environment. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Functions.FunctionName | string | The name of the function. | 
| AWS.Lambda.Functions.FunctionArn | string | The function’s Amazon Resource Name \(ARN\). | 
| AWS.Lambda.Functions.Runtime | string | The identifier of the function’s runtime. Runtime is required if the deployment package is a .zip file archive. | 
| AWS.Lambda.Functions.Role | string | The function’s execution role. | 
| AWS.Lambda.Functions.Handler | string | The function that Lambda calls to begin running your function. | 
| AWS.Lambda.Functions.CodeSize | number | The size of the function’s deployment package, in bytes. | 
| AWS.Lambda.Functions.Description | string | The function’s description. | 
| AWS.Lambda.Functions.Timeout | number | The amount of time in seconds that Lambda allows a function to run before stopping it. | 
| AWS.Lambda.Functions.MemorySize | number | The amount of memory available to the function at runtime. | 
| AWS.Lambda.Functions.Version | string | The version of the Lambda function. | 
| AWS.Lambda.Functions.VpcConfig.SubnetIds | list | A list of VPC subnet IDs. | 
| AWS.Lambda.Functions.VpcConfig.SecurityGroupIds | list | A list of VPC security group IDs. | 
| AWS.Lambda.Functions.VpcConfig.VpcId | string | The ID of the VPC. | 
| AWS.Lambda.Functions.VpcConfig.Ipv6AllowedForDualStack | boolean | Allows outbound IPv6 traffic on VPC functions that are connected to dual-stack subnets. | 
| AWS.Lambda.Functions.PackageType | string | The type of deployment package. Set to Image for container image and set Zip for .zip file archive. | 
| AWS.Lambda.Functions.LastModified | string | The date and time that the function was last updated, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 


#### Command example
```!aws-lambda-create-function code=entry_id functionName=test runtime=nodejs role=test-role handler=test.handler vpcConfig="{\"SubnetIds\": [\"subnet-1\",\"subnet-2\"], \"SecurityGroupIds\":[\"sg-1\"]}" ```

#### Context Example
```json
{
    "AWS": {
        "Lambda": {
            "Functions": {
                "FunctionName": "test",
                "FunctionArn": "test",
                "Runtime": "nodejs",
                "Role": "test-role",
                "Handler": "test.handler",
                "CodeSize": 30,
                "Description": "test function",
                "Timeout": 30,
                "MemorySize": 123,
                "Version": "test",
                "VpcConfig": {
                    "SubnetIds": ["subnet-1","subnet-2"],
                    "SecurityGroupIds": ["sg-1"],
                    "VpcId": "test",
                    "Ipv6AllowedForDualStack": true},
                "PackageType": "Zip",
                "LastModified": "test"}
        }
    }
}
```

#### Human Readable Output

>### Create Function
>| Function Name |Function Arn|Runtime| Role      | Handler      |Code Size|Description|Timeout|Memory Size|Version| Vpc Config                                                                                                            |Package Type|Last Modified|
>|---------------|---|---|-----------|--------------|---|---|---|---|---|-----------------------------------------------------------------------------------------------------------------------|---|---|
>| test          | test | nodejs | test-role | test.handler | 30 | test function | 30 | 123 | test | SubnetIds: subnet-1,<br>subnet-2<br>SecurityGroupIds: sg-1<br>VpcId: test<br>Ipv6AllowedForDualStack: true | Zip | test |



### aws-lambda-publish-layer-version

***
Creates an Lambda layer from a ZIP archive.

#### Base Command

`aws-lambda-publish-layer-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| layer-name | The name or Amazon Resource Name (ARN) of the layer. | Required | 
| description | The description of the version. | Optional | 
| s3-bucket | The Amazon S3 bucket of the layer archive. | Optional | 
| s3-key | The Amazon S3 key of the layer archive. | Optional | 
| s3-object-version | For versioned objects, the version of the layer archive object to use. | Optional | 
| zip-file | Entry ID of the base64-encoded contents of the layer archive. | Optional | 
| compatible-runtimes |  The name of the method within your code that Lambda calls to execute your function. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| compatible-architectures | A list of compatible architectures. Possible values are: x86_64, arm64. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.Layers.LayerVersionArn | string | The ARN of the layer version. | 
| AWS.Lambda.Layers.LayerArn | string | The ARN of the layer. | 
| AWS.Lambda.Layers.Description | string | The description of the version. | 
| AWS.Lambda.Layers.CreatedDate | string | The date that the layer version was created, in ISO-8601 format \(YYYY-MM-DDThh:mm:ss.sTZD\). | 
| AWS.Lambda.Layers.Version | number | The version number. | 
| AWS.Lambda.Layers.CompatibleRuntimes | list | The layer’s compatible runtimes. | 
| AWS.Lambda.Layers.CompatibleArchitectures | list | The layer’s compatible architectures. | 


#### Command example
```!aws-lambda-publish-layer-version layer-name=test zip-file=entry_id description=test-layer-3
 ```

#### Context Example
```json
{
    "CompatibleRuntimes": ["nodejs"],
    "CreatedDate": "2024-03-01T10:12:00.0TZD",
    "Description": "test",
    "LayerArn": "test_layer_arn",
    "LayerVersionArn": "test_version_arn",
    "Version": 2
}
```

#### Human Readable Output

>### Publish Layer Version
>|Layer Version Arn|Layer Arn|Description|Created Date|Version|Compatible Runtimes|
>|---|---|---|---|---|---|
>| test_version_arn | test_layer_arn | test | 2024-03-01T10:12:00.0TZD | 2 | nodejs |


### aws-lambda-list-layer-version

***
Lists the versions of an Lambda layer.

#### Base Command

`aws-lambda-list-layer-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| compatible-runtime | A runtime identifier. For example, java21. | Optional | 
| layer-name | The name or Amazon Resource Name (ARN) of the layer. | Required | 
| token | A pagination token returned by a previous call. | Optional | 
| limit | The maximum number of versions to return. | Optional | 
| compatible-architecture | The compatible instruction set architecture. | Optional | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Lambda.LayerVersionsNextToken | string | A pagination token returned when the response doesn’t contain all versions. | 
| AWS.Lambda.Layers.LayerVersionArn | string | The ARN of the layer version. | 
| AWS.Lambda.Layers.Version | number | The version number. | 
| AWS.Lambda.Layers.Description | string | The description of the version. | 
| AWS.Lambda.Layers.CreatedDate | string | The date that the version was created, in ISO 8601 format. For example, 2018-11-27T15:10:45.123\+0000. | 
| AWS.Lambda.Layers.CompatibleRuntimes | list | The layer’s compatible runtimes. | 
| AWS.Lambda.Layers.LicenseInfo | string | The layer’s open-source license. | 
| AWS.Lambda.Layers.CompatibleArchitectures | list | A list of compatible instruction set architectures. | 


#### Command example
```!aws-lambda-list-layer-version layer-name=test```

#### Context Example
```json
{
    "NextMarker": "test_marker",
    "LayerVersions": [{
        "LayerVersionArn": "testLayer",
        "Version": 1,
        "Description": "test",
        "CreatedDate": "2018-11-27T15:10:45.123+0000",
        "CompatibleRuntimes": ["nodejs"],
        "LicenseInfo": "test",
        "CompatibleArchitectures": ["x86_64"]
    }]
}
```

#### Human Readable Output

>### Layer Version List
>|Compatible Architectures|Compatible Runtimes|Created Date|Description|Layer Version Arn|License Info|Version|
>|---|---|---|---|---|---|---|
>| x86_64 | nodejs | 2018-11-27T15:10:45.123+0000 | test | testLayer | test | 1 |


### aws-lambda-delete-layer-version

***
Deletes a version of an Lambda layer.

#### Base Command

`aws-lambda-delete-layer-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version-number | The version number.  | Required | 
| layer-name | The name or Amazon Resource Name (ARN) of the layer.  | Required | 
| region | The AWS Region. If not specified, the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Command example
```!aws-lambda-delete-layer-version version-number=4 layer-name=test_layer```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>Deleted version number 2 of testLayer Successfully