Amazon Web Services Athena.

## Configure AWS - Athena in Cortex


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


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-athena-execute-query

***
Execute a new query, wait for the query to complete (using polling), and return query's execution information, and query's results (if successful). Either 'OutputLocation' or 'WorkGroup' must be specified for the query to run.

#### Base Command

`aws-athena-execute-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| QueryString | The SQL query statements to be executed. | Required | 
| QueryLimit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored. Default is 50. | Optional | 
| ClientRequestToken | A unique case-sensitive string used to ensure the request to create the query is idempotent (executes only once). If another StartQueryExecution request is received, the same response is returned and another query is not created. | Optional | 
| Database | The name of the database. | Optional | 
| OutputLocation | The location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/. | Optional | 
| EncryptionOption | Indicates whether Amazon S3 server-side encryption with Amazon S3-managed keys (SSE-S3 ), server-side encryption with KMS-managed keys (SSE-KMS ), or client-side encryption with KMS-managed keys (CSE-KMS) is used. | Optional | 
| KmsKey | For SSE-KMS and CSE-KMS , this is the KMS key ARN or ID. | Optional | 
| WorkGroup | The name of the workgroup in which the query is being started. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| QueryExecutionId | ID of the newly created query. Used internally for polling. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Athena.Query.QueryExecutionId | String | The unique identifier for each query execution. | 
| AWS.Athena.Query.Query | String | The SQL query statements which the query execution ran. | 
| AWS.Athena.Query.StatementType | String | The type of query statement that was run. | 
| AWS.Athena.Query.ResultConfiguration.OutputLocation | String | The location in Amazon S3 where your query and calculation results are stored, such as 's3://path/to/query/bucket/'. | 
| AWS.Athena.Query.ResultConfiguration.EncryptionConfiguration.EncryptionOption | String | If query and calculation results are encrypted in Amazon S3, indicates the encryption option used \(for example, SSE_KMS or CSE_KMS\) and key information. | 
| AWS.Athena.Query.ResultConfiguration.EncryptionConfiguration.KmsKey | String | For SSE_KMS and CSE_KMS, this is the KMS key ARN or ID. | 
| AWS.Athena.Query.ResultConfiguration.ExpectedBucketOwner | String | The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by ResultConfiguration.OutputLocation. | 
| AWS.Athena.Query.ResultConfiguration.AclConfiguration.S3AclOption | String | The Amazon S3 canned ACL that Athena should specify when storing query results. | 
| AWS.Athena.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled | Boolean | True if previous query results can be reused when the query is run; otherwise, false. The default is false. | 
| AWS.Athena.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes | Number | Specifies, in minutes, the maximum age of a previous query result that Athena should consider for reuse. The default is 60. | 
| AWS.Athena.Query.QueryExecutionContext.Database | String | The name of the database used in the query execution. | 
| AWS.Athena.Query.QueryExecutionContext.Catalog | String | The name of the data catalog used in the query execution. | 
| AWS.Athena.Query.Status.State | String | The state of query execution. | 
| AWS.Athena.Query.Status.StateChangeReason | String | Further detail about the status of the query. | 
| AWS.Athena.Query.Status.SubmissionDateTime | String | The date and time that the query was submitted. | 
| AWS.Athena.Query.Status.CompletionDateTime | String | The date and time that the query completed. | 
| AWS.Athena.Query.Status.AthenaError.ErrorCategory | Number | An integer value that specifies the category of a query failure error. | 
| AWS.Athena.Query.Status.AthenaError.ErrorType | Number | An integer value that provides specific information about an Athena query error. For the meaning of specific values, see the Error Type Reference in the Amazon Athena User Guide. | 
| AWS.Athena.Query.Status.AthenaError.Retryable | Boolean | True if the query might succeed if resubmitted. | 
| AWS.Athena.Query.Status.AthenaError.ErrorMessage | String | Contains a short description of the error that occurred. | 
| AWS.Athena.Query.Statistics.EngineExecutionTimeInMillis | Number | The number of milliseconds that the query took to execute. | 
| AWS.Athena.Query.Statistics.DataScannedInBytes | Number | The number of bytes in the data that was queried. | 
| AWS.Athena.Query.Statistics.DataManifestLocation | String | The location and file name of a data manifest file. The manifest file is saved to the Athena query results location in Amazon S3. | 
| AWS.Athena.Query.Statistics.TotalExecutionTimeInMillis | Number | The number of milliseconds that Athena took to run the query. | 
| AWS.Athena.Query.Statistics.QueryQueueTimeInMillis | Number | The number of milliseconds that the query was in your query queue waiting for resources. | 
| AWS.Athena.Query.Statistics.ServicePreProcessingTimeInMillis | Number | The number of milliseconds that Athena took to preprocess the query before submitting the query to the query engine. | 
| AWS.Athena.Query.Statistics.QueryPlanningTimeInMillis | Number | The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. | 
| AWS.Athena.Query.Statistics.ServiceProcessingTimeInMillis | Number | The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query. | 
| AWS.Athena.Query.ResultReuseInformation.ReusedPreviousResult | Boolean | True if a previous query result was reused; false if the result was generated from a new run of the query. | 
| AWS.Athena.Query.WorkGroup | String | The name of the workgroup in which the query ran. | 
| AWS.Athena.Query.EngineVersion.SelectedEngineVersion | String | The engine version requested by the user. Possible values are determined by the output of ListEngineVersions, including AUTO. | 
| AWS.Athena.Query.EngineVersion.EffectiveEngineVersion | String | The engine version on which the query runs. | 
| AWS.Athena.Query.ExecutionParameters | List | A list of values for the parameters in a query. The values are applied sequentially to the parameters in the query in the order in which the parameters occur. The list of parameters is not returned in the response. | 
| AWS.Athena.Query.SubstatementType | String | The kind of query statement that was run. | 
| AWS.Athena.QueryResults | List | List of query results. | 

### aws-athena-start-query

***
Start an Athena query. Either 'OutputLocation' or 'WorkGroup' must be specified for the query to run.

#### Base Command

`aws-athena-start-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| QueryString | The SQL query statements to be executed. | Required | 
| QueryLimit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored. Default is 50. | Optional | 
| ClientRequestToken | A unique case-sensitive string used to ensure the request to create the query is idempotent (executes only once). If another StartQueryExecution request is received, the same response is returned and another query is not created. | Optional | 
| Database | The name of the database. | Optional | 
| OutputLocation | The location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/. | Optional | 
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
| AWS.Athena.Query.QueryExecutionId | String | ID of the newly created query. | 
| AWS.Athena.Query.Query | String | The query string submitted. | 

### aws-athena-stop-query

***
Stop an existing running query.

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
Return execution information of a query.

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
| AWS.Athena.Query.QueryExecutionId | String | The unique identifier for each query execution. | 
| AWS.Athena.Query.Query | String | The SQL query statements which the query execution ran. | 
| AWS.Athena.Query.StatementType | String | The type of query statement that was run. | 
| AWS.Athena.Query.ResultConfiguration.OutputLocation | String | The location in Amazon S3 where your query and calculation results are stored, such as 's3://path/to/query/bucket/'. | 
| AWS.Athena.Query.ResultConfiguration.EncryptionConfiguration.EncryptionOption | String | If query and calculation results are encrypted in Amazon S3, indicates the encryption option used \(for example, SSE_KMS or CSE_KMS\) and key information. | 
| AWS.Athena.Query.ResultConfiguration.EncryptionConfiguration.KmsKey | String | For SSE_KMS and CSE_KMS, this is the KMS key ARN or ID. | 
| AWS.Athena.Query.ResultConfiguration.ExpectedBucketOwner | String | The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by ResultConfiguration.OutputLocation. | 
| AWS.Athena.Query.ResultConfiguration.AclConfiguration.S3AclOption | String | The Amazon S3 canned ACL that Athena should specify when storing query results. | 
| AWS.Athena.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled | Boolean | True if previous query results can be reused when the query is run; otherwise, false. The default is false. | 
| AWS.Athena.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes | Number | Specifies, in minutes, the maximum age of a previous query result that Athena should consider for reuse. The default is 60. | 
| AWS.Athena.Query.QueryExecutionContext.Database | String | The name of the database used in the query execution. | 
| AWS.Athena.Query.QueryExecutionContext.Catalog | String | The name of the data catalog used in the query execution. | 
| AWS.Athena.Query.Status.State | String | The state of query execution. | 
| AWS.Athena.Query.Status.StateChangeReason | String | Further detail about the status of the query. | 
| AWS.Athena.Query.Status.SubmissionDateTime | String | The date and time that the query was submitted. | 
| AWS.Athena.Query.Status.CompletionDateTime | String | The date and time that the query completed. | 
| AWS.Athena.Query.Status.AthenaError.ErrorCategory | Number | An integer value that specifies the category of a query failure error. | 
| AWS.Athena.Query.Status.AthenaError.ErrorType | Number | An integer value that provides specific information about an Athena query error. For the meaning of specific values, see the Error Type Reference in the Amazon Athena User Guide. | 
| AWS.Athena.Query.Status.AthenaError.Retryable | Boolean | True if the query might succeed if resubmitted. | 
| AWS.Athena.Query.Status.AthenaError.ErrorMessage | String | Contains a short description of the error that occurred. | 
| AWS.Athena.Query.Statistics.EngineExecutionTimeInMillis | Number | The number of milliseconds that the query took to execute. | 
| AWS.Athena.Query.Statistics.DataScannedInBytes | Number | The number of bytes in the data that was queried. | 
| AWS.Athena.Query.Statistics.DataManifestLocation | String | The location and file name of a data manifest file. The manifest file is saved to the Athena query results location in Amazon S3. | 
| AWS.Athena.Query.Statistics.TotalExecutionTimeInMillis | Number | The number of milliseconds that Athena took to run the query. | 
| AWS.Athena.Query.Statistics.QueryQueueTimeInMillis | Number | The number of milliseconds that the query was in your query queue waiting for resources. | 
| AWS.Athena.Query.Statistics.ServicePreProcessingTimeInMillis | Number | The number of milliseconds that Athena took to preprocess the query before submitting the query to the query engine. | 
| AWS.Athena.Query.Statistics.QueryPlanningTimeInMillis | Number | The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. | 
| AWS.Athena.Query.Statistics.ServiceProcessingTimeInMillis | Number | The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query. | 
| AWS.Athena.Query.ResultReuseInformation.ReusedPreviousResult | Boolean | True if a previous query result was reused; false if the result was generated from a new run of the query. | 
| AWS.Athena.Query.WorkGroup | String | The name of the workgroup in which the query ran. | 
| AWS.Athena.Query.EngineVersion.SelectedEngineVersion | String | The engine version requested by the user. Possible values are determined by the output of ListEngineVersions, including AUTO. | 
| AWS.Athena.Query.EngineVersion.EffectiveEngineVersion | String | The engine version on which the query runs. | 
| AWS.Athena.Query.ExecutionParameters | List | A list of values for the parameters in a query. The values are applied sequentially to the parameters in the query in the order in which the parameters occur. The list of parameters is not returned in the response. | 
| AWS.Athena.Query.SubstatementType | String | The kind of query statement that was run. | 

### aws-athena-get-query-results

***
Return the results of a query.

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