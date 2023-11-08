Amazon Web Services Athena.

## Configure AWS - Athena on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - Athena.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Role Arn |  | False |
    | Role Session Name |  | False |
    | Role Session Duration |  | False |
    | AWS Default Region |  | False |
    | Access Key |  | True |
    | Secret Key |  | True |
    | Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-athena-start-query

***
Start Athena Query.

#### Base Command

`aws-athena-start-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| QueryString | The SQL query statements to be executed. | Required | 
| ClientRequestToken | A unique case-sensitive string used to ensure the request to create the query is idempotent (executes only once). Possible values are: private, public-read, public-read-write, authenticated-read. | Optional | 
| Database | The name of the database. | Optional | 
| OutputLocation | he location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/. | Optional | 
| EncryptionOption | Indicates whether Amazon S3 server-side encryption with Amazon S3-managed keys (SSE-S3 ), server-side encryption with KMS-managed keys (SSE-KMS ), or client-side encryption with KMS-managed keys (CSE-KMS) is used. | Optional | 
| KmsKey | For SSE-KMS and CSE-KMS , this is the KMS key ARN or ID. | Optional | 
| WorkGroup | The name of the workgroup in which the query is being started. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Athena.StartQuery | String | ID of the newly created query. | 
| AWS.Athena.QueryString | String | Object size. | 

### aws-athena-stop-query

***
Stops a query execution. Requires you to have access to the workgroup in which the query ran.

#### Base Command

`aws-athena-stop-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| QueryExecutionId | The unique ID of the query execution to stop.  This field is auto-populated if not provided. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.
### aws-athena-get-query-execution

***
Returns information about a single execution of a query if you have access to the workgroup in which the query ran.

#### Base Command

`aws-athena-get-query-execution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| QueryExecutionId | The unique ID of the query execution. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Athena.QueryExecution | Dictionary | Query execution details. | 

### aws-athena-get-query-results

***
Returns the results of a single query execution specified by QueryExecutionId if you have access to the workgroup in which the query ran.

#### Base Command

`aws-athena-get-query-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| QueryExecutionId | The unique ID of the query execution. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Athena.QueryResults | List | List of query results. | 
