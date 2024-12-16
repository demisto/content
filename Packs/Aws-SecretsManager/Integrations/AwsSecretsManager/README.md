AWS Secrets Manager helps you to securely encrypt, store, and retrieve credentials for your databases and other services.
This integration was integrated and tested with version 1.0 of AwsSecretsManager

## Configure Aws Secrets Manager in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region |  | True |
| Role Arn |  | False |
| Role Session Name |  | False |
| Role Session Duration |  | False |
| Access Key |  | False |
| Secret Key |  | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout separated from the read timeout with a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| Fetches credentials |  | False |
| AWS STS Regional Endpoints | Sets the AWS_STS_REGIONAL_ENDPOINTS environment variable to specify the AWS STS endpoint resolution logic. By default, this option is set to “legacy” in AWS. Leave empty if the environment variable is already set using server configuration. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Disable sensitive commands | Disables the following sensitive commands from running: aws-secrets-manager-secret–value-get. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-secrets-manager-secret-list

***
Retrieve all secrets.


#### Base Command

`aws-secrets-manager-secret-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Description field to filter by. | Optional | 
| name | Secret name. | Optional | 
| tag_key | Tag key to filter by. | Optional | 
| tag_value | Tag value to filter by. | Optional | 
| general_search | Search in all possible fields. | Optional | 
| sort | Direction by which to display the results. Possible values are: Asc, Desc. | Optional | 
| limit | Number of total results to query. | Optional | 
| page | Specific page to query. | Optional | 
| page_size | Number of total results in each page. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecretsManager.Secret.ResponseMetadata.HTTPHeaders.content-length | String | The length of the HTTP header response content. | 
| AWS.SecretsManager.Secret.ResponseMetadata.HTTPHeaders.content-type | String | The type of the HTTP header response content. | 
| AWS.SecretsManager.Secret.ResponseMetadata.HTTPHeaders.date | Date | The date of the HTTP header response. | 
| AWS.SecretsManager.Secret.ResponseMetadata.HTTPHeaders.x-amzn-requestid | String | The ID of the HTTP header Amazon request. | 
| AWS.SecretsManager.Secret.ResponseMetadata.HTTPStatusCode | Number | The status code in the HTTP header. | 
| AWS.SecretsManager.Secret.ResponseMetadata.RequestId | String | The ID of the HTTP header response request. | 
| AWS.SecretsManager.Secret.ResponseMetadata.RetryAttempts | Number | The number of HTTP header response retry attempts. | 
| AWS.SecretsManager.Secret.SecretList.ARN | String | The secret ARN. | 
| AWS.SecretsManager.Secret.SecretList.CreatedDate | Date | The date and time this version of the secret was created. | 
| AWS.SecretsManager.Secret.SecretList.LastAccessedDate | Date | The date the secret was last accessed. | 
| AWS.SecretsManager.Secret.SecretList.LastChangedDate | Date | The date the secret was last changed. | 
| AWS.SecretsManager.Secret.SecretList.Name | String | The secret name. | 
| AWS.SecretsManager.Secret.SecretList.SecretVersionsToStages.c88e2176-aca4-4776-a422-c3a0616079bc | String | The SecretVersionStage staging labels for the provided hash. | 
| AWS.SecretsManager.Secret.SecretList.SecretVersionsToStages.5889c662-13a6-4318-bec3-b234fcae3826 | String | The SecretVersionStage staging labels for the provided hash. | 
| AWS.SecretsManager.Secret.SecretList.SecretVersionsToStages.f2a389e8-3860-47a0-b4a0-16424ad63a24 | String | The SecretVersionStage staging labels for the provided hash. | 
| AWS.SecretsManager.Secret.SecretList.Description | String | The secret description. | 
| AWS.SecretsManager.Secret.SecretList.SecretVersionsToStages.01cba660-28be-45d7-8597-d1ab295b0f35 | String | The SecretVersionStage staging labels for the provided hash. | 
| AWS.SecretsManager.Secret.SecretList.SecretVersionsToStages.ac32e535-79e7-4188-a732-7f02dbe399f0 | String | The SecretVersionStage staging labels for the provided hash. | 

#### Command example

```!aws-secrets-manager-secret-list```

#### Context Example

```json
{
    "AWS": {
        "SecretsManager": {
            "Secret": {
                "ResponseMetadata": {
                    "HTTPHeaders": {
                        "content-length": "1267",
                        "content-type": "application/x-amz-json-1.1",
                        "date": "Sun, 23 Oct 2022 13:41:30 GMT",
                        "x-amzn-requestid": "615f197f-c54c-4c45-be33-1064ae9652a5"
                    },
                    "HTTPStatusCode": 200,
                    "RequestId": "615f197f-c54c-4c45-be33-1064ae9652a5",
                    "RetryAttempts": 0
                },
                "SecretList": [
                    {
                        "ARN": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:fdff-vnNyyc",
                        "CreatedDate": "2022-09-04T09:10:12",
                        "LastAccessedDate": "2022-10-23T00:00:00",
                        "LastChangedDate": "2022-10-23T13:40:55",
                        "Name": "fdff",
                        "SecretVersionsToStages": {
                            "c88e2176-aca4-4776-a422-c3a0616079bc": [
                                "AWSCURRENT"
                            ]
                        },
                        "Tags": []
                    },
                    {
                        "ARN": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:gmail-oF08mg",
                        "CreatedDate": "2022-08-31T09:47:24",
                        "LastAccessedDate": "2022-10-23T00:00:00",
                        "LastChangedDate": "2022-08-31T09:47:24",
                        "Name": "gmail",
                        "SecretVersionsToStages": {
                            "5889c662-13a6-4318-bec3-b234fcae3826": [
                                "AWSCURRENT"
                            ]
                        },
                        "Tags": []
                    },
                    {
                        "ARN": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:DB_credentials-3ic9K7",
                        "CreatedDate": "2022-08-31T09:45:33",
                        "LastAccessedDate": "2022-10-23T00:00:00",
                        "LastChangedDate": "2022-08-31T09:45:33",
                        "Name": "DB_credentials",
                        "SecretVersionsToStages": {
                            "f2a389e8-3860-47a0-b4a0-16424ad63a24": [
                                "AWSCURRENT"
                            ]
                        },
                        "Tags": []
                    },
                    {
                        "ARN": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:test_account",
                        "CreatedDate": "2022-08-21T13:54:05",
                        "Description": "new description",
                        "LastAccessedDate": "2022-10-23T00:00:00",
                        "LastChangedDate": "2022-09-08T07:14:13",
                        "Name": "test_for_moishy",
                        "SecretVersionsToStages": {
                            "01cba660-28be-45d7-8597-d1ab295b0f35": [
                                "AWSCURRENT"
                            ],
                            "ac32e535-79e7-4188-a732-7f02dbe399f0": [
                                "AWSPREVIOUS"
                            ]
                        },
                        "Tags": []
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Secrets List

>|ARN|Description|LastAccessedDate|Name|
>|---|---|---|---|
>| arn:aws:secretsmanager:eu-central-1:123456789012:secret:fdff-vnNyyc |  | 2022-10-23T13:40:55 | fdff |
>| arn:aws:secretsmanager:eu-central-1:123456789012:secret:gmail-oF08mg |  | 2022-08-31T09:47:24 | gmail |
>| arn:aws:secretsmanager:eu-central-1:123456789012:secret:DB_credentials-3ic9K7 |  | 2022-08-31T09:45:33 | DB_credentials |
>| arn:aws:secretsmanager:eu-central-1:123456789012:secret:test_account | new description | 2022-09-08T07:14:13 | test_for_moishy |


### aws-secrets-manager-secret–value-get

***
Retrieve a secret value by key.


#### Base Command

`aws-secrets-manager-secret–value-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| secret_id | The ID of the secret or ARN. | Required | 
| version_id | The version ID of the secret. | Optional | 
| version_stage | The version stage of the secret. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecretsManager.Secret.SecretValue.ARN | String | The secret ARN. | 
| AWS.SecretsManager.Secret.SecretValue.Name | String | The secret name. | 
| AWS.SecretsManager.Secret.SecretValue.VersionId | String | The secret version ID. | 
| AWS.SecretsManager.Secret.SecretValue.SecretString | String | The secret value. | 
| AWS.SecretsManager.Secret.SecretValue.VersionStages | String | A list of all of the staging labels currently attached to this version of the secret. | 
| AWS.SecretsManager.Secret.SecretValue.CreatedDate | Date | The date and time this version of the secret was created. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.RequestId | String | The ID of the HTTP header response request. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.HTTPStatusCode | Number | The status code in the HTTP header. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.HTTPHeaders.x-amzn-requestid | String | The ID of the HTTP header Amazon request. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.HTTPHeaders.content-type | String | The type of the HTTP header response content. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.HTTPHeaders.content-length | String | The length of the HTTP header response content. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.HTTPHeaders.date | Date | The date of the HTTP header response. | 
| AWS.SecretsManager.Secret.SecretValue.ResponseMetadata.RetryAttempts | Number | The number of HTTP header response retry attempts. | 

#### Command example

```!aws-secrets-manager-secret–value-get secret_id="fdff"```

#### Context Example

```json
{
    "AWS": {
        "SecretsManager": {
            "Secret": {
                "SecretValue": {
                    "ARN": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:fdff-vnNyyc",
                    "CreatedDate": "2022-09-04T09:10:13",
                    "Name": "fdff",
                    "ResponseMetadata": {
                        "HTTPHeaders": {
                            "content-length": "271",
                            "content-type": "application/x-amz-json-1.1",
                            "date": "Sun, 23 Oct 2022 13:41:27 GMT",
                            "x-amzn-requestid": "cc592da7-198b-483c-a106-e91bdbe59e30"
                        },
                        "HTTPStatusCode": 200,
                        "RequestId": "cc592da7-198b-483c-a106-e91bdbe59e30",
                        "RetryAttempts": 0
                    },
                    "SecretString": "{\"password\":\"cvcvcv\",\"username\":\"cvcvcv\"}",
                    "VersionId": "c88e2176-aca4-4776-a422-c3a0616079bc",
                    "VersionStages": [
                        "AWSCURRENT"
                    ]
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Get Secret

>|ARN|CreatedDate|Name|SecretBinary|SecretString|
>|---|---|---|---|---|
>| arn:aws:secretsmanager:eu-central-1:123456789012:secret:fdff-vnNyyc | 2022-09-04T09:10:13 | fdff |  | {"password":"cvcvcv","username":"cvcvcv"} |


### aws-secrets-manager-secret–delete

***
Delete a specific secret.


#### Base Command

`aws-secrets-manager-secret–delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| secret_id | The ID of the secret or ARN. | Required | 
| delete_immediately | Delete with grace period. | Optional | 
| days_of_recovery | The number of days allowed to restore the secret (default in AWS - 30 days). | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!aws-secrets-manager-secret–delete secret_id="fdff"```

#### Human Readable Output

>The Secret was Deleted

### aws-secrets-manager-secret–restore

***
Restore a specific secret after deletion.


#### Base Command

`aws-secrets-manager-secret–restore`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| secret_id | The ID of the secret or ARN. | Required | 


#### Context Output

There is no context output for this command.

#### Command example

```!aws-secrets-manager-secret–restore secret_id="fdff"```

#### Human Readable Output

>the secret was restored successfully

### aws-secrets-manager-secret–policy-get

***
Get the Secret Manager policy for a specific secret.


#### Base Command

`aws-secrets-manager-secret–policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| secret_id | The ID of the secret or ARN. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecretsManager.Policy.ARN | String | The policy ARN. | 
| AWS.SecretsManager.Policy.Name | String | The policy name. | 
| AWS.SecretsManager.Policy.ResponseMetadata.RequestId | String | The ID of the HTTP header response request. | 
| AWS.SecretsManager.Policy.ResponseMetadata.HTTPStatusCode | Number | The status code in the HTTP header. | 
| AWS.SecretsManager.Policy.ResponseMetadata.HTTPHeaders.x-amzn-requestid | String | The ID of the HTTP header Amazon request. | 
| AWS.SecretsManager.Policy.ResponseMetadata.HTTPHeaders.content-type | String | The type of the HTTP header response content. | 
| AWS.SecretsManager.Policy.ResponseMetadata.HTTPHeaders.content-length | String | The length of the HTTP header response content. | 
| AWS.SecretsManager.Policy.ResponseMetadata.HTTPHeaders.date | Date | The date of the HTTP header response. | 
| AWS.SecretsManager.Policy.ResponseMetadata.RetryAttempts | Number | The number of HTTP header response retry attempts. | 

#### Command example

```!aws-secrets-manager-secret–policy-get secret_id="fdff"```

#### Context Example

```json
{
    "AWS": {
        "SecretsManager": {
            "Policy": {
                "ARN": "arn:aws:secretsmanager:eu-central-1:123456789012:secret:fdff-vnNyyc",
                "Name": "fdff",
                "ResponseMetadata": {
                    "HTTPHeaders": {
                        "content-length": "91",
                        "content-type": "application/x-amz-json-1.1",
                        "date": "Sun, 23 Oct 2022 13:41:28 GMT",
                        "x-amzn-requestid": "b49e5847-387f-44a8-b7c8-a37540e89ad1"
                    },
                    "HTTPStatusCode": 200,
                    "RequestId": "b49e5847-387f-44a8-b7c8-a37540e89ad1",
                    "RetryAttempts": 0
                }
            }
        }
    }
}
```

#### Human Readable Output

>### AWS Secret Policy

>|ARN|Name|Policy|
>|---|---|---|
>| arn:aws:secretsmanager:eu-central-1:123456789012:secret:fdff-vnNyyc | fdff |  |
