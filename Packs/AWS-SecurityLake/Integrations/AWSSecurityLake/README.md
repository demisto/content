Amazon Security Lake is a fully managed security data lake service.
This integration was integrated and tested with version 1.34.20 of AWS Security Lake SDK (boto3).

## Configure Amazon Security Lake in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | User name | True |
| Role Arn | Role ARN | False |
| Role Session Name | Role Session Name | False |
| Role Session Duration | Role Session Duration | False |
| AWS Default Region | AWS Default Region | False |
| Access Key | Access Key | False |
| Secret Key | Secret Key | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout (for example 60) or also the connect timeout followed after a comma (for example 60,10). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-security-lake-query-execute

***
Execute a new query, wait for the query to complete (using polling), and return query's execution information, and query's results (if successful). Either 'OutputLocation' or 'WorkGroup' must be specified for the query to run.

#### Base Command

`aws-security-lake-query-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_string | The SQL query statements to be executed.  | Required | 
| query_limit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored.  Default is 50. | Optional | 
| client_request_token | A unique case-sensitive string used to ensure the request to create the query is idempotent (executes only once). If another StartQueryExecution request is received, the same response is returned and another query is not created.  | Optional | 
| database | The name of the database.  | Optional | 
| output_location | The location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/.  | Optional | 
| encryption_option | Indicates whether Amazon S3 server-side encryption with Amazon S3-managed keys (SSE-S3 ), server-side encryption with KMS-managed keys (SSE-KMS ), or client-side encryption with KMS-managed keys (CSE-KMS) is used.  | Optional | 
| kms_key | For SSE-KMS and CSE-KMS , this is the KMS key ARN or ID.  | Optional | 
| work_group | The name of the workgroup in which the query is being started.  | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| QueryExecutionId | ID of the newly created query. Used internally for polling. | Optional | 
| hide_polling_output |  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.Query.QueryExecutionId | String | The unique identifier for each query execution. | 
| AWS.SecurityLake.Query.Query | String | The SQL query statements which the query execution ran. | 
| AWS.SecurityLake.Query.StatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.Query.ResultConfiguration.OutputLocation | String | The location in Amazon S3 where your query and calculation results are stored, such as 's3://path/to/query/bucket/'. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.EncryptionOption | String | If query and calculation results are encrypted in Amazon S3, indicates the encryption option used \(for example, SSE_KMS or CSE_KMS\) and key information. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.KmsKey | String | For SSE_KMS and CSE_KMS, this is the KMS key ARN or ID. | 
| AWS.SecurityLake.Query.ResultConfiguration.ExpectedBucketOwner | String | The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by ResultConfiguration.OutputLocation. | 
| AWS.SecurityLake.Query.ResultConfiguration.AclConfiguration.S3AclOption | String | The Amazon S3 canned ACL that Athena should specify when storing query results. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled | Boolean | True if previous query results can be reused when the query is run; otherwise, false. The default is false. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes | Number | Specifies, in minutes, the maximum age of a previous query result that Athena should consider for reuse. The default is 60. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Database | String | The name of the database used in the query execution. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Catalog | String | The name of the data catalog used in the query execution. | 
| AWS.SecurityLake.Query.Status.State | String | The state of the query execution. | 
| AWS.SecurityLake.Query.Status.StateChangeReason | String | Further detail about the status of the query. | 
| AWS.SecurityLake.Query.Status.SubmissionDateTime | String | The date and time that the query was submitted. | 
| AWS.SecurityLake.Query.Status.CompletionDateTime | String | The date and time that the query completed. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorCategory | Number | An integer value that specifies the category of a query failure error. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorType | Number | An integer value that provides specific information about an Athena query error. For the meaning of specific values, see the Error Type Reference in the Amazon Athena User Guide. | 
| AWS.SecurityLake.Query.Status.AthenaError.Retryable | Boolean | True if the query might succeed if resubmitted. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorMessage | String | Contains a short description of the error that occurred. | 
| AWS.SecurityLake.Query.Statistics.EngineExecutionTimeInMillis | Number | The number of milliseconds that the query took to execute. | 
| AWS.SecurityLake.Query.Statistics.DataScannedInBytes | Number | The number of bytes in the data that was queried. | 
| AWS.SecurityLake.Query.Statistics.DataManifestLocation | String | The location and file name of a data manifest file. The manifest file is saved to the Athena query results location in Amazon S3. | 
| AWS.SecurityLake.Query.Statistics.TotalExecutionTimeInMillis | Number | The number of milliseconds that Athena took to run the query. | 
| AWS.SecurityLake.Query.Statistics.QueryQueueTimeInMillis | Number | The number of milliseconds that the query was in your query queue waiting for resources. | 
| AWS.SecurityLake.Query.Statistics.ServicePreProcessingTimeInMillis | Number | The number of milliseconds that Athena took to preprocess the query before submitting the query to the query engine. | 
| AWS.SecurityLake.Query.Statistics.QueryPlanningTimeInMillis | Number | The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. | 
| AWS.SecurityLake.Query.Statistics.ServiceProcessingTimeInMillis | Number | The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query. | 
| AWS.SecurityLake.Query.ResultReuseInformation.ReusedPreviousResult | Boolean | True if a previous query result was reused; false if the result was generated from a new run of the query. | 
| AWS.SecurityLake.Query.WorkGroup | String | The name of the workgroup in which the query ran. | 
| AWS.SecurityLake.Query.EngineVersion.SelectedEngineVersion | String | The engine version requested by the user. Possible values are determined by the output of ListEngineVersions, including AUTO. | 
| AWS.SecurityLake.Query.EngineVersion.EffectiveEngineVersion | String | The engine version on which the query runs. | 
| AWS.SecurityLake.Query.ExecutionParameters | List | A list of values for the parameters in a query. The values are applied sequentially to the parameters in the query in the order in which the parameters occur. The list of parameters is not returned in the response. | 
| AWS.SecurityLake.Query.SubstatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.QueryResults | List | List of query results. | 

### aws-security-lake-data-catalogs-list

***
Lists the data catalogs in the current Amazon Web Services account.

#### Base Command

`aws-security-lake-data-catalogs-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| work_group | The name of the workgroup. Required if making an IAM Identity Center request.  | Optional | 
| region | The AWS region. If not specified, the default region will be used.  | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| limit | Specifies the maximum number of data catalogs to return.  | Optional | 
| next_token | Specifies the maximum number of data catalogs to return.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.Catalog.CatalogName | String | The name of the data catalog. | 
| AWS.SecurityLake.Catalog.Type | String | The data catalog type. | 
| AWS.SecurityLake.CatalogNextToken | String | A token generated by the SecurityLake service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call. | 

### aws-security-lake-databases-list

***
Lists the databases in the specified data catalog.

#### Base Command

`aws-security-lake-databases-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| catalog_name | The name of the data catalog that contains the databases to return.  | Required | 
| work_group | The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.  | Optional | 
| region | The AWS region. If not specified, the default region will be used.  | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| limit | Specifies the maximum number of results to return.  | Optional | 
| next_token | A token generated by the SecurityLake. service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.Database.Name | String | The name of the database. | 
| AWS.SecurityLake.Database.Description | String | An optional description of the database. | 
| AWS.SecurityLake.Database.Parameters | List | A set of custom key/value pairs. | 
| AWS.SecurityLake.DatabaseNextToken | String | A token generated by the SecurityLake service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call. | 

#### Command Example
```!aws-security-lake-databases-list catalog_name=Test```

### aws-security-lake-table-metadata-list

***
Lists the metadata for the tables in the specified data catalog database.

#### Base Command

`aws-security-lake-table-metadata-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| catalog_name | The name of the data catalog that contains the databases to return.  | Required | 
| database_name | The name of the database for which table metadata should be returned.  | Required | 
| expression | A regex filter that pattern-matches table names. If no expression is supplied, metadata for all tables are listed.  | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| limit | Specifies the maximum number of results to return.  | Optional | 
| next_token | A token generated by the SecurityLake service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.  | Optional | 
| work_group | The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.TableMetadata.Name | String | The name of the table. | 
| AWS.SecurityLake.TableMetadata.CreateTime | Date | The time that the table was created. | 
| AWS.SecurityLake.TableMetadata.LastAccessTime | Date | The last time the table was accessed. | 
| AWS.SecurityLake.TableMetadata.TableType | String | The type of table. In Athena, only EXTERNAL_TABLE is supported. | 
| AWS.SecurityLake.TableMetadata.Columns.Name | String | The name of the column. | 
| AWS.SecurityLake.TableMetadata.Columns.Type | String | The data type of the column. | 
| AWS.SecurityLake.TableMetadata.Columns.Comment | String | Optional information about the column. | 
| AWS.SecurityLake.TableMetadata.PartitionKeys.Name | String | The name of the column. | 
| AWS.SecurityLake.TableMetadata.PartitionKeys.Type | String | The data type of the column. | 
| AWS.SecurityLake.TableMetadata.PartitionKeys.Comment | String | Optional information about the column. | 
| AWS.SecurityLake.TableMetadata.Parameters | List | A set of custom key/value pairs for table properties. | 
| AWS.SecurityLake.TableMetadataNextToken | String | A token generated by the SecurityLake service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call. | 

#### Command Example
```!aws-security-lake-table-metadata-list catalog_name=Test database_name=test```

### aws-security-lake-user-mfalogin-query

***
Runs query that takes a provided username and queries the AWS Security Lake for MFA login attempts (Success/Failed) associated with the user's account, using AWS CloudTrail logs.

#### Base Command

`aws-security-lake-user-mfalogin-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database | The database to run the query against.  | Required | 
| table | The table to run the query against.  | Required | 
| user_name | The username to search for MFA login attempts.  | Required | 
| output_location | The location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/.  | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| query_limit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.Query.QueryExecutionId | String | The unique identifier for each query execution. | 
| AWS.SecurityLake.Query.Query | String | The SQL query statements which the query execution ran. | 
| AWS.SecurityLake.Query.StatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.Query.ResultConfiguration.OutputLocation | String | The location in Amazon S3 where your query and calculation results are stored, such as 's3://path/to/query/bucket/'. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.EncryptionOption | String | If query and calculation results are encrypted in Amazon S3, indicates the encryption option used \(for example, SSE_KMS or CSE_KMS\) and key information. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.KmsKey | String | For SSE_KMS and CSE_KMS, this is the KMS key ARN or ID. | 
| AWS.SecurityLake.Query.ResultConfiguration.ExpectedBucketOwner | String | The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by ResultConfiguration.OutputLocation. | 
| AWS.SecurityLake.Query.ResultConfiguration.AclConfiguration.S3AclOption | String | The Amazon S3 canned ACL that Athena should specify when storing query results. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled | Boolean | True if previous query results can be reused when the query is run; otherwise, false. The default is false. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes | Number | Specifies, in minutes, the maximum age of a previous query result that Athena should consider for reuse. The default is 60. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Database | String | The name of the database used in the query execution. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Catalog | String | The name of the data catalog used in the query execution. | 
| AWS.SecurityLake.Query.Status.State | String | The state of the query execution. | 
| AWS.SecurityLake.Query.Status.StateChangeReason | String | Further detail about the status of the query. | 
| AWS.SecurityLake.Query.Status.SubmissionDateTime | String | The date and time that the query was submitted. | 
| AWS.SecurityLake.Query.Status.CompletionDateTime | String | The date and time that the query completed. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorCategory | Number | An integer value that specifies the category of a query failure error. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorType | Number | An integer value that provides specific information about an Athena query error. For the meaning of specific values, see the Error Type Reference in the Amazon Athena User Guide. | 
| AWS.SecurityLake.Query.Status.AthenaError.Retryable | Boolean | True if the query might succeed if resubmitted. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorMessage | String | Contains a short description of the error that occurred. | 
| AWS.SecurityLake.Query.Statistics.EngineExecutionTimeInMillis | Number | The number of milliseconds that the query took to execute. | 
| AWS.SecurityLake.Query.Statistics.DataScannedInBytes | Number | The number of bytes in the data that was queried. | 
| AWS.SecurityLake.Query.Statistics.DataManifestLocation | String | The location and file name of a data manifest file. The manifest file is saved to the Athena query results location in Amazon S3. | 
| AWS.SecurityLake.Query.Statistics.TotalExecutionTimeInMillis | Number | The number of milliseconds that Athena took to run the query. | 
| AWS.SecurityLake.Query.Statistics.QueryQueueTimeInMillis | Number | The number of milliseconds that the query was in your query queue waiting for resources. | 
| AWS.SecurityLake.Query.Statistics.ServicePreProcessingTimeInMillis | Number | The number of milliseconds that Athena took to preprocess the query before submitting the query to the query engine. | 
| AWS.SecurityLake.Query.Statistics.QueryPlanningTimeInMillis | Number | The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. | 
| AWS.SecurityLake.Query.Statistics.ServiceProcessingTimeInMillis | Number | The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query. | 
| AWS.SecurityLake.Query.ResultReuseInformation.ReusedPreviousResult | Boolean | True if a previous query result was reused; false if the result was generated from a new run of the query. | 
| AWS.SecurityLake.Query.WorkGroup | String | The name of the workgroup in which the query ran. | 
| AWS.SecurityLake.Query.EngineVersion.SelectedEngineVersion | String | The engine version requested by the user. Possible values are determined by the output of ListEngineVersions, including AUTO. | 
| AWS.SecurityLake.Query.EngineVersion.EffectiveEngineVersion | String | The engine version on which the query runs. | 
| AWS.SecurityLake.Query.ExecutionParameters | List | A list of values for the parameters in a query. The values are applied sequentially to the parameters in the query in the order in which the parameters occur. The list of parameters is not returned in the response. | 
| AWS.SecurityLake.Query.SubstatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.MfaLoginQueryResults | List | List of query results. | 

#### Command Example
```!aws-security-lake-user-mfalogin-query table=Test database=test user_name=123 output_location=s3://path/to/query/bucket/```

### aws-security-lake-source-ip-query

***
Runs a query that takes a provided source IP address and queries the AWS Security Lake for console login attempts (Success/Failed) associated with the IP address, using AWS CloudTrail logs.

#### Base Command

`aws-security-lake-source-ip-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database | The database to run the query against.  | Required | 
| table | The table to run the query against.  | Required | 
| ip_src | The source IP address to search for console login attempts.  | Required | 
| output_location | The location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/.  | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| query_limit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.Query.QueryExecutionId | String | The unique identifier for each query execution. | 
| AWS.SecurityLake.Query.Query | String | The SQL query statements which the query execution ran. | 
| AWS.SecurityLake.Query.StatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.Query.ResultConfiguration.OutputLocation | String | The location in Amazon S3 where your query and calculation results are stored, such as 's3://path/to/query/bucket/'. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.EncryptionOption | String | If query and calculation results are encrypted in Amazon S3, indicates the encryption option used \(for example, SSE_KMS or CSE_KMS\) and key information. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.KmsKey | String | For SSE_KMS and CSE_KMS, this is the KMS key ARN or ID. | 
| AWS.SecurityLake.Query.ResultConfiguration.ExpectedBucketOwner | String | The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by ResultConfiguration.OutputLocation. | 
| AWS.SecurityLake.Query.ResultConfiguration.AclConfiguration.S3AclOption | String | The Amazon S3 canned ACL that Athena should specify when storing query results. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled | Boolean | True if previous query results can be reused when the query is run; otherwise, false. The default is false. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes | Number | Specifies, in minutes, the maximum age of a previous query result that Athena should consider for reuse. The default is 60. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Database | String | The name of the database used in the query execution. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Catalog | String | The name of the data catalog used in the query execution. | 
| AWS.SecurityLake.Query.Status.State | String | The state of the query execution. | 
| AWS.SecurityLake.Query.Status.StateChangeReason | String | Further detail about the status of the query. | 
| AWS.SecurityLake.Query.Status.SubmissionDateTime | String | The date and time that the query was submitted. | 
| AWS.SecurityLake.Query.Status.CompletionDateTime | String | The date and time that the query completed. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorCategory | Number | An integer value that specifies the category of a query failure error. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorType | Number | An integer value that provides specific information about an Athena query error. For the meaning of specific values, see the Error Type Reference in the Amazon Athena User Guide. | 
| AWS.SecurityLake.Query.Status.AthenaError.Retryable | Boolean | True if the query might succeed if resubmitted. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorMessage | String | Contains a short description of the error that occurred. | 
| AWS.SecurityLake.Query.Statistics.EngineExecutionTimeInMillis | Number | The number of milliseconds that the query took to execute. | 
| AWS.SecurityLake.Query.Statistics.DataScannedInBytes | Number | The number of bytes in the data that was queried. | 
| AWS.SecurityLake.Query.Statistics.DataManifestLocation | String | The location and file name of a data manifest file. The manifest file is saved to the Athena query results location in Amazon S3. | 
| AWS.SecurityLake.Query.Statistics.TotalExecutionTimeInMillis | Number | The number of milliseconds that Athena took to run the query. | 
| AWS.SecurityLake.Query.Statistics.QueryQueueTimeInMillis | Number | The number of milliseconds that the query was in your query queue waiting for resources. | 
| AWS.SecurityLake.Query.Statistics.ServicePreProcessingTimeInMillis | Number | The number of milliseconds that Athena took to preprocess the query before submitting the query to the query engine. | 
| AWS.SecurityLake.Query.Statistics.QueryPlanningTimeInMillis | Number | The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. | 
| AWS.SecurityLake.Query.Statistics.ServiceProcessingTimeInMillis | Number | The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query. | 
| AWS.SecurityLake.Query.ResultReuseInformation.ReusedPreviousResult | Boolean | True if a previous query result was reused; false if the result was generated from a new run of the query. | 
| AWS.SecurityLake.Query.WorkGroup | String | The name of the workgroup in which the query ran. | 
| AWS.SecurityLake.Query.EngineVersion.SelectedEngineVersion | String | The engine version requested by the user. Possible values are determined by the output of ListEngineVersions, including AUTO. | 
| AWS.SecurityLake.Query.EngineVersion.EffectiveEngineVersion | String | The engine version on which the query runs. | 
| AWS.SecurityLake.Query.ExecutionParameters | List | A list of values for the parameters in a query. The values are applied sequentially to the parameters in the query in the order in which the parameters occur. The list of parameters is not returned in the response. | 
| AWS.SecurityLake.Query.SubstatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.SourceIPQueryResults | List | List of query results. | 

#### Command Example
```!aws-security-lake-source-ip-query table=Test database=test ip_src=1.2.3.4 output_location=s3://path/to/query/bucket/```

### aws-security-lake-guardduty-activity-query

***
This command is used to search for Guard Duty logs for any criticality level activity.

#### Base Command

`aws-security-lake-guardduty-activity-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| database | The database to run the query against.  | Required | 
| table | The table to run the query against.  | Required | 
| severity | The severity of searchingto search related events for. Possible values are: 0-Unknown, 1-Informational, 2-Low, 3-Medium, 4-High, 5-Critical, 6-Fatal, 99-Other. | Required | 
| output_location | The location in Amazon S3 where your query results are stored, such as s3://path/to/query/bucket/.  | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| query_limit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.Query.QueryExecutionId | String | The unique identifier for each query execution. | 
| AWS.SecurityLake.Query.Query | String | The SQL query statements which the query execution ran. | 
| AWS.SecurityLake.Query.StatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.Query.ResultConfiguration.OutputLocation | String | The location in Amazon S3 where your query and calculation results are stored, such as 's3://path/to/query/bucket/'. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.EncryptionOption | String | If query and calculation results are encrypted in Amazon S3, indicates the encryption option used \(for example, SSE_KMS or CSE_KMS\) and key information. | 
| AWS.SecurityLake.Query.ResultConfiguration.EncryptionConfiguration.KmsKey | String | For SSE_KMS and CSE_KMS, this is the KMS key ARN or ID. | 
| AWS.SecurityLake.Query.ResultConfiguration.ExpectedBucketOwner | String | The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by ResultConfiguration.OutputLocation. | 
| AWS.SecurityLake.Query.ResultConfiguration.AclConfiguration.S3AclOption | String | The Amazon S3 canned ACL that Athena should specify when storing query results. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.Enabled | Boolean | True if previous query results can be reused when the query is run; otherwise, false. The default is false. | 
| AWS.SecurityLake.Query.ResultReuseConfiguration.ResultReuseByAgeConfiguration.MaxAgeInMinutes | Number | Specifies, in minutes, the maximum age of a previous query result that Athena should consider for reuse. The default is 60. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Database | String | The name of the database used in the query execution. | 
| AWS.SecurityLake.Query.QueryExecutionContext.Catalog | String | The name of the data catalog used in the query execution. | 
| AWS.SecurityLake.Query.Status.State | String | The state of the query execution. | 
| AWS.SecurityLake.Query.Status.StateChangeReason | String | Further detail about the status of the query. | 
| AWS.SecurityLake.Query.Status.SubmissionDateTime | String | The date and time that the query was submitted. | 
| AWS.SecurityLake.Query.Status.CompletionDateTime | String | The date and time that the query completed. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorCategory | Number | An integer value that specifies the category of a query failure error. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorType | Number | An integer value that provides specific information about an Athena query error. For the meaning of specific values, see the Error Type Reference in the Amazon Athena User Guide. | 
| AWS.SecurityLake.Query.Status.AthenaError.Retryable | Boolean | True if the query might succeed if resubmitted. | 
| AWS.SecurityLake.Query.Status.AthenaError.ErrorMessage | String | Contains a short description of the error that occurred. | 
| AWS.SecurityLake.Query.Statistics.EngineExecutionTimeInMillis | Number | The number of milliseconds that the query took to execute. | 
| AWS.SecurityLake.Query.Statistics.DataScannedInBytes | Number | The number of bytes in the data that was queried. | 
| AWS.SecurityLake.Query.Statistics.DataManifestLocation | String | The location and file name of a data manifest file. The manifest file is saved to the Athena query results location in Amazon S3. | 
| AWS.SecurityLake.Query.Statistics.TotalExecutionTimeInMillis | Number | The number of milliseconds that Athena took to run the query. | 
| AWS.SecurityLake.Query.Statistics.QueryQueueTimeInMillis | Number | The number of milliseconds that the query was in your query queue waiting for resources. | 
| AWS.SecurityLake.Query.Statistics.ServicePreProcessingTimeInMillis | Number | The number of milliseconds that Athena took to preprocess the query before submitting the query to the query engine. | 
| AWS.SecurityLake.Query.Statistics.QueryPlanningTimeInMillis | Number | The number of milliseconds that Athena took to plan the query processing flow. This includes the time spent retrieving table partitions from the data source. | 
| AWS.SecurityLake.Query.Statistics.ServiceProcessingTimeInMillis | Number | The number of milliseconds that Athena took to finalize and publish the query results after the query engine finished running the query. | 
| AWS.SecurityLake.Query.ResultReuseInformation.ReusedPreviousResult | Boolean | True if a previous query result was reused; false if the result was generated from a new run of the query. | 
| AWS.SecurityLake.Query.WorkGroup | String | The name of the workgroup in which the query ran. | 
| AWS.SecurityLake.Query.EngineVersion.SelectedEngineVersion | String | The engine version requested by the user. Possible values are determined by the output of ListEngineVersions, including AUTO. | 
| AWS.SecurityLake.Query.EngineVersion.EffectiveEngineVersion | String | The engine version on which the query runs. | 
| AWS.SecurityLake.Query.ExecutionParameters | List | A list of values for the parameters in a query. The values are applied sequentially to the parameters in the query in the order in which the parameters occur. The list of parameters is not returned in the response. | 
| AWS.SecurityLake.Query.SubstatementType | String | The type of query statement that was run. | 
| AWS.SecurityLake.GuardDutyActivityQueryResults | List | List of query results. | 

#### Command Example
```!aws-security-lake-guardduty-activity-query table=Test database=test severity=0-Unknown output_location=s3://path/to/query/bucket/```

### aws-security-lake-data-sources-list

***
Retrieves a snapshot of the current region, including whether Amazon Security Lake is enabled for those accounts and which sources Security Lake is collecting data from.
In order to run this command the user must have 'securitylake' permissions.

#### Base Command

`aws-security-lake-data-sources-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| accounts | The Amazon Web Services account ID for which a static snapshot of the current Amazon Web Services Region, including enabled accounts and log sources, is retrieved.  | Optional | 
| limit | Specifies the maximum number of results to return.  | Optional | 
| next_token | Lists if there are more results available. The value of nextToken is a unique pagination token for each page. Repeat the call using the returned token to retrieve the next page. Keep all other arguments unchanged.  | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| query_limit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.DataLakeSource.DataLakeArn | String | The Amazon Resource Name \(ARN\) created by you to provide to the subscriber. | 
| AWS.SecurityLake.DataLakeSource.DataLakeSources.account | String | The ID of the Security Lake account for which logs are collected. | 
| AWS.SecurityLake.DataLakeSource.DataLakeSources.eventClasses | List | The Open Cybersecurity Schema Framework \(OCSF\) event classes which describes the type of data that the custom source will send to Security Lake. | 
| AWS.SecurityLake.DataLakeSource.DataLakeSources.sourceName | String | The supported Amazon Web Services from which logs and events are collected. Amazon Security Lake supports log and event collection for natively supported Amazon Web Services. | 
| AWS.SecurityLake.DataLakeSource.DataLakeSources.sourceStatuses.resource | String | Defines the path in which the stored logs are available which has information on your systems, applications, and services. | 
| AWS.SecurityLake.DataLakeSource.DataLakeSources.sourceStatuses.status | String | The health status of services, including error codes and patterns. | 
| AWS.SecurityLake.DataLakeSourceNextToken | String | Lists if there are more results available. The value of nextToken is a unique pagination token for each page. Repeat the call using the returned token to retrieve the next page. Keep all other arguments unchanged. | 

#### Command Example
```!aws-security-lake-data-sources-list```

### aws-security-lake-data-lakes-list

***
Retrieves the Amazon Security Lake configuration object for the specified Amazon Web Services Regions.
In order to run this command the user must have 'securitylake' permissions.

#### Base Command

`aws-security-lake-data-lakes-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regions | The list of regions where Security Lake is enabled.  | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume.  | Optional | 
| roleSessionName | An identifier for the assumed role session.  | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| region | The AWS region. If not specified, the default region will be used. | Optional | 
| query_limit | A limit (number) to use for the query. If the keyword 'LIMIT' exists within 'QueryString', this parameter will be ignored.  | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityLake.createStatus | String | Retrieves the status of the configuration operation for an account in Amazon Security Lake. | 
| AWS.SecurityLake.dataLakeArn | String | The Amazon Resource Name \(ARN\) created by you to provide to the subscriber. | 
| AWS.SecurityLake.encryptionConfiguration.kmsKeyId | String | The ID of the KMS encryption key used by Amazon Security Lake to encrypt the Security Lake object. | 
| AWS.SecurityLake.lifecycleConfiguration.expiration.days | Number | Number of days before data expires in the Amazon Security Lake object. | 
| AWS.SecurityLake.lifecycleConfiguration.transitions.days | Number | Number of days before data transitions to a different S3 Storage Class in the Amazon Security Lake object. | 
| AWS.SecurityLake.lifecycleConfiguration.transitions.storageClass | String | The range of storage classes that you can choose from based on the data access, resiliency, and cost requirements of your workloads. | 
| AWS.SecurityLake.region | String | The Amazon Web Services regions where Security Lake is enabled. | 
| AWS.SecurityLake.replicationConfiguration.regions | String | Replication enables automatic, asynchronous copying of objects across Amazon S3 buckets. | 
| AWS.SecurityLake.replicationConfiguration.roleArn | String | Replication settings for the Amazon S3 buckets. This parameter uses the Identity and Access Management \(IAM\) role you created that is managed by Security Lake, to ensure the replication setting is correct. | 
| AWS.SecurityLake.s3BucketArn | String | The ARN for the Amazon Security Lake Amazon S3 bucket. | 
| AWS.SecurityLake.updateStatus.exception.code | String | The reason code for the exception of the last UpdateDataLake or DeleteDataLake API request. | 
| AWS.SecurityLake.updateStatus.exception.reason | String | The reason for the exception of the last UpdateDataLake or DeleteDataLake API request. | 
| AWS.SecurityLake.updateStatus.requestId | String | The unique ID for the last UpdateDataLake or DeleteDataLake API request. | 
| AWS.SecurityLake.updateStatus.status | String | The status of the last UpdateDataLake or DeleteDataLake API request that was requested. | 

#### Command Example
```!aws-security-lake-data-lakes-list```