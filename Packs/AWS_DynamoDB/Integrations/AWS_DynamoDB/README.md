Amazon DynamoDB Amazon DynamoDB is a fully managed NoSQL database service that provides fast and predictable performance with seamless scalability. DynamoDB lets you offload the administrative burdens of operating and scaling a distributed database, so that you don't have to worry about hardware provisioning, setup and configuration, replication, software patching, or cluster scaling. With DynamoDB, you can create database tables that can store and retrieve any amount of data, and serve any level of request traffic. You can scale up or scale down your tables' throughput capacity without downtime or performance degradation, and use the AWS Management Console to monitor resource utilization and performance metrics. DynamoDB automatically spreads the data and traffic for your tables over a sufficient number of servers to handle your throughput and storage requirements, while maintaining consistent and fast performance. All of your data is stored on solid state disks (SSDs) and automatically replicated across multiple Availability Zones in an AWS region, providing built-in high availability and data durability. 
For more information regarding the AWS DynamoDB service, please visit the official documentation found [here](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html).

## Configure Amazon DynamoDB in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | Role Arn | False |
| roleSessionName | Role Session Name | False |
| defaultRegion | AWS Default Region | False |
| sessionDuration | Role Session Duration | False |
| access_key | Access Key | False |
| secret_key | Secret Key | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-dynamodb-batch-get-item
***
The BatchGetItem operation returns the attributes of one or more items from one or more tables. You identify requested items by primary key. A single operation can retrieve up to 16 MB of data, which can contain as many as 100 items. BatchGetItem returns a partial result if the response size limit is exceeded, the table's provisioned throughput is exceeded, or an internal processing failure occurs. If a partial result is returned, the operation returns a value for UnprocessedKeys. You can use this value to retry the operation starting with the next item to get.  If you request more than 100 items, BatchGetItem returns a ValidationException with the message "Too many items requested for the BatchGetItem call."  For example, if you ask to retrieve 100 items, but each individual item is 300 KB in size, the system returns 52 items (so as not to exceed the 16 MB limit). It also returns an appropriate UnprocessedKeys value so you can get the next page of results. If desired, your application can include its own logic to assemble the pages of results into one dataset. If *none* of the items can be processed due to insufficient provisioned throughput on all of the tables in the request, then BatchGetItem returns a ProvisionedThroughputExceededException. If *at least one* of the items is successfully processed, then BatchGetItem completes successfully, while returning the keys of the unread items in UnprocessedKeys.  If DynamoDB returns any unprocessed items, you should retry the batch operation on those items. However, *we strongly recommend that you use an exponential backoff algorithm*. If you retry the batch operation immediately, the underlying read or write requests can still fail due to throttling on the individual tables. If you delay the batch operation using exponential backoff, the individual requests in the batch are much more likely to succeed. For more information, see Batch Operations and Error Handling in the *Amazon DynamoDB Developer Guide*.  By default, BatchGetItem performs eventually consistent reads on every table in the request. If you want strongly consistent reads instead, you can set ConsistentRead to true for any or all tables. In order to minimize response latency, BatchGetItem retrieves items in parallel. When designing your application, keep in mind that DynamoDB does not return items in any particular order. To help parse the response by item, include the primary key values for the items in your request in the ProjectionExpression parameter. If a requested item does not exist, it is not returned in the result. Requests for nonexistent items consume the minimum read capacity units according to the type of read. For more information, see Working with Tables in the *Amazon DynamoDB Developer Guide*.


#### Base Command

`aws-dynamodb-batch-get-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| request_items | A map of one or more table names and, for each table, a map that describes one or more items to retrieve from that table. Each table name can be used only once per BatchGetItem request. Each element in the map of items to retrieve consists of the following:  *   ConsistentRead - If true, a strongly consistent read is used; if false (the default), an eventually consistent read is used. <br/> *   ExpressionAttributeNames - One or more substitution tokens for attribute names in the ProjectionExpression parameter. The following are some use cases for using ExpressionAttributeNames: <br/>	 +  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/>	 +  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/>	 +  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>	  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name: <br/>	 +   Percentile  <br/>	  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*). To work around this, you could specify the following for ExpressionAttributeNames: <br/>	 +   {"#P":"Percentile"}  <br/>	  You could then use this substitution in an expression, as in this example: <br/>	 +   #P = :val  <br/>	   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information about expression attribute names, see Accessing Item Attributes in the *Amazon DynamoDB Developer Guide*. <br/> *   Keys - An array of primary key attribute values that define specific items in the table. For each primary key, you must provide *all* of the key attributes. For example, with a simple primary key, you only need to provide the partition key value. For a composite key, you must provide *both* the partition key value and the sort key value. <br/> *   ProjectionExpression - A string that identifies one or more attributes to retrieve from the table. These attributes can include scalars, sets, or elements of a JSON document. The attributes in the expression must be separated by commas. If no attribute names are specified, then all attributes are returned. If any of the requested attributes are not found, they do not appear in the result. For more information, see Accessing Item Attributes in the *Amazon DynamoDB Developer Guide*. <br/> *   AttributesToGet - This is a legacy parameter. Use ProjectionExpression instead. For more information, see AttributesToGet in the *Amazon DynamoDB Developer Guide*.  <br/>  | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Responses | unknown | A map of table name to a list of items. Each object in Responses consists of a table name, along with a map of attribute data consisting of the data type and attribute value. | 
| AWS-DynamoDB.UnprocessedKeys | unknown | A map of tables and their respective keys that were not processed with the current response. The UnprocessedKeys value is in the same form as RequestItems, so the value can be provided directly to a subsequent BatchGetItem operation. For more information, see RequestItems in the Request Parameters section. Each element consists of:  \*   Keys - An array of primary key attribute values that define specific items in the table.<br/>\*   ProjectionExpression - One or more attributes to be retrieved from the table or index. By default, all attributes are returned. If a requested attribute is not found, it does not appear in the result.<br/>\*   ConsistentRead - The consistency of a read operation. If set to true, then a strongly consistent read is used; otherwise, an eventually consistent read is used.<br/>If there are no unprocessed keys remaining, the response contains an empty UnprocessedKeys map. | 
| AWS-DynamoDB.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.docs | unknown | The read capacity units consumed by the entire BatchGetItem operation. Each element consists of:  \*   TableName - The table that consumed the provisioned throughput. <br/>\*   CapacityUnits - The total number of capacity units consumed. | 


### aws-dynamodb-batch-write-item
***
The BatchWriteItem operation puts or deletes multiple items in one or more tables. A single call to BatchWriteItem can write up to 16 MB of data, which can comprise as many as 25 put or delete requests. Individual items to be written can be as large as 400 KB.   BatchWriteItem cannot update items. To update items, use the UpdateItem action.  The individual PutItem and DeleteItem operations specified in BatchWriteItem are atomic; however BatchWriteItem as a whole is not. If any requested operations fail because the table's provisioned throughput is exceeded or an internal processing failure occurs, the failed operations are returned in the UnprocessedItems response parameter. You can investigate and optionally resend the requests. Typically, you would call BatchWriteItem in a loop. Each iteration would check for unprocessed items and submit a new BatchWriteItem request with those unprocessed items until all items have been processed. If *none* of the items can be processed due to insufficient provisioned throughput on all of the tables in the request, then BatchWriteItem returns a ProvisionedThroughputExceededException.  If DynamoDB returns any unprocessed items, you should retry the batch operation on those items. However, *we strongly recommend that you use an exponential backoff algorithm*. If you retry the batch operation immediately, the underlying read or write requests can still fail due to throttling on the individual tables. If you delay the batch operation using exponential backoff, the individual requests in the batch are much more likely to succeed. For more information, see Batch Operations and Error Handling in the *Amazon DynamoDB Developer Guide*.  With BatchWriteItem, you can efficiently write or delete large amounts of data, such as from Amazon EMR, or copy data from another database into DynamoDB. In order to improve performance with these large-scale operations, BatchWriteItem does not behave in the same way as individual PutItem and DeleteItem calls would. For example, you cannot specify conditions on individual put and delete requests, and BatchWriteItem does not return deleted items in the response. If you use a programming language that supports concurrency, you can use threads to write items in parallel. Your application must include the necessary logic to manage the threads. With languages that don't support threading, you must update or delete the specified items one at a time. In both situations, BatchWriteItem performs the specified put and delete operations in parallel, giving you the power of the thread pool approach without having to introduce complexity into your application. Parallel processing reduces latency, but each specified put and delete request consumes the same number of write capacity units whether it is processed in parallel or not. Delete operations on nonexistent items consume one write capacity unit. If one or more of the following is true, DynamoDB rejects the entire batch write operation:  *  One or more tables specified in the BatchWriteItem request does not exist. 
 *  Primary key attributes specified on an item in the request do not match those in the corresponding table's primary key schema. 
 *  You try to perform multiple operations on the same item in the same BatchWriteItem request. For example, you cannot put and delete the same item in the same BatchWriteItem request.  
 *   Your request contains at least two items with identical hash and range keys (which essentially is two put operations).  
 *  There are more than 25 requests in the batch. 
 *  Any individual item in a batch exceeds 400 KB. 
 *  The total request size exceeds 16 MB. 
 


#### Base Command

`aws-dynamodb-batch-write-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| request_items | A map of one or more table names and, for each table, a list of operations to be performed (DeleteRequest or PutRequest). Each element in the map consists of the following:  *   DeleteRequest - Perform a DeleteItem operation on the specified item. The item to be deleted is identified by a Key subelement: <br/>	 +   Key - A map of primary key attribute values that uniquely identify the item. Each entry in this map consists of an attribute name and an attribute value. For each primary key, you must provide *all* of the key attributes. For example, with a simple primary key, you only need to provide a value for the partition key. For a composite primary key, you must provide values for *both* the partition key and the sort key. <br/>	  <br/> *   PutRequest - Perform a PutItem operation on the specified item. The item to be put is identified by an Item subelement: <br/>	 +   Item - A map of attributes and their values. Each entry in this map consists of an attribute name and an attribute value. Attribute values must not be null; string and binary type attributes must have lengths greater than zero; and set type attributes must not be empty. Requests that contain empty values are rejected with a ValidationException exception. If you specify any attributes that are part of an index key, then the data types for those attributes must match those of the schema in the table's attribute definition. <br/>	  <br/>  | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| return_item_collection_metrics | Determines whether item collection metrics are returned. If set to SIZE, the response includes statistics about item collections, if any, that were modified during the operation are returned in the response. If set to NONE (the default), no statistics are returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.UnprocessedItems | unknown | A map of tables and requests against those tables that were not processed. The UnprocessedItems value is in the same form as RequestItems, so you can provide this value directly to a subsequent BatchGetItem operation. For more information, see RequestItems in the Request Parameters section. Each UnprocessedItems entry consists of a table name and, for that table, a list of operations to perform \(DeleteRequest or PutRequest\).  \*   DeleteRequest - Perform a DeleteItem operation on the specified item. The item to be deleted is identified by a Key subelement: <br/>\+   Key - A map of primary key attribute values that uniquely identify the item. Each entry in this map consists of an attribute name and an attribute value. <br/>\*   PutRequest - Perform a PutItem operation on the specified item. The item to be put is identified by an Item subelement: <br/>\+   Item - A map of attributes and their values. Each entry in this map consists of an attribute name and an attribute value. Attribute values must not be null; string and binary type attributes must have lengths greater than zero; and set type attributes must not be empty. Requests that contain empty values will be rejected with a ValidationException exception. If you specify any attributes that are part of an index key, then the data types for those attributes must match those of the schema in the table's attribute definition. <br/><br/>If there are no unprocessed items remaining, the response contains an empty UnprocessedItems map. | 
| AWS-DynamoDB.ItemCollectionMetrics | unknown | A list of tables that were processed by BatchWriteItem and, for each table, information about any item collections that were affected by individual DeleteItem or PutItem operations. Each entry consists of the following subelements:  \*   ItemCollectionKey - The partition key value of the item collection. This is the same as the partition key value of the item. <br/>\*   SizeEstimateRangeGB - An estimate of item collection size, expressed in GB. This is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on the table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 
| AWS-DynamoDB.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.docs | unknown | The capacity units consumed by the entire BatchWriteItem operation. Each element consists of:  \*   TableName - The table that consumed the provisioned throughput. \*   CapacityUnits - The total number of capacity units consumed. | 


### aws-dynamodb-create-backup
***
Creates a backup for an existing table.  Each time you create an on-demand backup, the entire table data is backed up. There is no limit to the number of on-demand backups that can be taken.   When you create an on-demand backup, a time marker of the request is cataloged, and the backup is created asynchronously, by applying all changes until the time of the request to the last full table snapshot. Backup requests are processed instantaneously and become available for restore within minutes.  You can call CreateBackup at a maximum rate of 50 times per second. All backups in DynamoDB work without consuming any provisioned throughput on the table.  If you submit a backup request on 2018-12-14 at 14:25:00, the backup is guaranteed to contain all data committed to the table up to 14:24:00, and data committed after 14:26:00 will not be. The backup might contain data modifications made between 14:24:00 and 14:26:00. On-demand backup does not support causal consistency.   Along with data, the following are also included on the backups:   *  Global secondary indexes (GSIs) 
 *  Local secondary indexes (LSIs) 
 *  Streams 
 *  Provisioned read and write capacity 
 


#### Base Command

`aws-dynamodb-create-backup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table. | Optional | 
| backup_name | Specified name for the backup. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.BackupDetails.BackupArn | unknown | ARN associated with the backup. | 
| AWS-DynamoDB.BackupDetails.BackupName | unknown | Name of the requested backup. | 
| AWS-DynamoDB.BackupDetails.BackupSizeBytes | unknown | Size of the backup in bytes. | 
| AWS-DynamoDB.BackupDetails.BackupStatus | unknown | Backup can be in one of the following states: CREATING, ACTIVE, DELETED.  | 
| AWS-DynamoDB.BackupDetails.BackupType | unknown | BackupType:  \*   USER - You create and manage these using the on-demand backup feature. <br/>\*   SYSTEM - If you delete a table with point-in-time recovery enabled, a SYSTEM backup is automatically created and is retained for 35 days \(at no additional cost\). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.  <br/>\*   AWS\\_BACKUP - On-demand backup created by you from AWS Backup service. | 
| AWS-DynamoDB.BackupDetails.BackupCreationDateTime | unknown | Time at which the backup was created. This is the request time of the backup.  | 
| AWS-DynamoDB.BackupDetails.BackupExpiryDateTime | unknown | Time at which the automatic on-demand backup created by DynamoDB will expire. This SYSTEM on-demand backup expires automatically 35 days after its creation. | 
| AWS-DynamoDB.BackupDetails | unknown | Contains the details of the backup created for the table. | 


### aws-dynamodb-create-global-table
***
Creates a global table from an existing table. A global table creates a replication relationship between two or more DynamoDB tables with the same table name in the provided Regions.  If you want to add a new replica table to a global table, each of the following conditions must be true:  *  The table must have the same primary key as all of the other replicas. 
 *  The table must have the same name as all of the other replicas. 
 *  The table must have DynamoDB Streams enabled, with the stream containing both the new and the old images of the item. 
 *  None of the replica tables in the global table can contain any data. 
   If global secondary indexes are specified, then the following conditions must also be met:   *   The global secondary indexes must have the same name.  
 *   The global secondary indexes must have the same hash key and sort key (if present).  
    Write capacity settings should be set consistently across your replica tables and secondary indexes. DynamoDB strongly recommends enabling auto scaling to manage the write capacity settings for all of your global tables replicas and indexes.   If you prefer to manage write capacity settings manually, you should provision equal replicated write capacity units to your replica tables. You should also provision equal replicated write capacity units to matching secondary indexes across your global table.  


#### Base Command

`aws-dynamodb-create-global-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| global_table_name | The global table name. | Optional | 
| replication_group_region_name | The Region where the replica needs to be created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.GlobalTableDescription.ReplicationGroup.RegionName | unknown | The name of the Region. | 
| AWS-DynamoDB.GlobalTableDescription.ReplicationGroup | unknown | The Regions where the global table has replicas. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableArn | unknown | The unique identifier of the global table. | 
| AWS-DynamoDB.GlobalTableDescription.CreationDateTime | unknown | The creation time of the global table. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableStatus | unknown | The current state of the global table:  \*   CREATING - The global table is being created. <br/> \*   UPDATING - The global table is being updated. <br/> \*   DELETING - The global table is being deleted. <br/> \*   ACTIVE - The global table is ready for use. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableName | unknown | The global table name. | 
| AWS-DynamoDB.GlobalTableDescription | unknown | Contains the details of the global table. | 


### aws-dynamodb-create-table
***
The CreateTable operation adds a new table to your account. In an AWS account, table names must be unique within each Region. That is, you can have two tables with same name if you create the tables in different Regions.  CreateTable is an asynchronous operation. Upon receiving a CreateTable request, DynamoDB immediately returns a response with a TableStatus of CREATING. After the table is created, DynamoDB sets the TableStatus to ACTIVE. You can perform read and write operations only on an ACTIVE table.  You can optionally define secondary indexes on the new table, as part of the CreateTable operation. If you want to create multiple tables with secondary indexes on them, you must create the tables sequentially. Only one table with secondary indexes can be in the CREATING state at any given time. You can use the DescribeTable action to check the table status.


#### Base Command

`aws-dynamodb-create-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| attribute_definitions_attribute_name | A name for the attribute. | Optional | 
| attribute_definitions_attribute_type | The data type for the attribute, where:  *   S - the attribute is of type String <br/> *   N - the attribute is of type Number <br/> *   B - the attribute is of type Binary <br/>  | Optional | 
| table_name | The name of the table to create. | Optional | 
| local_secondary_indexes_index_name | The name of the local secondary index. The name must be unique among all other indexes on this table. | Optional | 
| key_schema_attribute_name | The name of a key attribute. | Optional | 
| global_secondary_indexes_index_name | The name of the global secondary index. The name must be unique among all other indexes on this table. | Optional | 
| key_schema_key_type | The role that this key attribute will assume:  *   HASH - partition key <br/> *   RANGE - sort key <br/>   The partition key of an item is also known as its *hash attribute*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its *range attribute*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | Optional | 
| projection_projection_type | The set of attributes that are projected into the index:  *   KEYS\_ONLY - Only the index and primary keys are projected into the index. <br/> *   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> *   ALL - All of the table attributes are projected into the index. <br/>  | Optional | 
| projection_non_key_attributes | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | Optional | 
| billing_mode | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  *   PROVISIONED - We recommend using PROVISIONED for predictable workloads. PROVISIONED sets the billing mode to Provisioned Mode. <br/> *   PAY\_PER\_REQUEST - We recommend using PAY\_PER\_REQUEST for unpredictable workloads. PAY\_PER\_REQUEST sets the billing mode to On-Demand Mode.  <br/>  | Optional | 
| provisioned_throughput_read_capacity_units | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| provisioned_throughput_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| stream_specification_stream_enabled | &lt;p&gt;Indicates whether DynamoDB Streams is enabled (true) or disabled (false) on the table.&lt;/p&gt; | Optional | 
| stream_specification_stream_view_type |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  *   KEYS\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> *   NEW\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> *   OLD\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> *   NEW\_AND\_OLD\_IMAGES - Both the new and the old item images of the item are written to the stream. <br/>  | Optional | 
| sse_specification_enabled | &lt;p&gt;Indicates whether server-side encryption is done using an AWS managed CMK or an AWS owned CMK. If enabled (true), server-side encryption type is set to &lt;code&gt;KMS&lt;/code&gt; and an AWS managed CMK is used (AWS KMS charges apply). If disabled (false) or not specified, server-side encryption is set to AWS owned CMK.&lt;/p&gt; | Optional | 
| sse_specification_sse_type | Server-side encryption type. The only supported value is:  *   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS (AWS KMS charges apply). <br/>  | Optional | 
| sse_specification_kms_master_key_id | The KMS customer master key (CMK) that should be used for the AWS KMS encryption. To specify a CMK, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB customer master key alias/aws/dynamodb. | Optional | 
| tag_key | The Tags key identifier. | Optional | 
| tag_value | The Tags value identifier. | Optional | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeName | unknown | A name for the attribute. | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeType | unknown | The data type for the attribute, where:  \*   S - the attribute is of type String <br/> \*   N - the attribute is of type Number <br/> \*   B - the attribute is of type Binary | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions | unknown | An array of AttributeDefinition objects. Each of these objects describes one attribute in the table and index key schema. Each AttributeDefinition object in this array is composed of:  \*   AttributeName - The name of the attribute. <br/> \*   AttributeType - The data type for the attribute. | 
| AWS-DynamoDB.TableDescription.TableName | unknown | The name of the table. | 
| AWS-DynamoDB.TableDescription.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.KeySchema | unknown | The primary key structure for the table. Each KeySchemaElement consists of:  \*   AttributeName - The name of the attribute. <br/> \*   KeyType - The role of the attribute: <br/>	 \+   HASH - partition key <br/>	 \+   RANGE - sort key <br/>	   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  <br/>  For more information about primary keys, see Primary Key in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.TableStatus | unknown | The current state of the table:  \*   CREATING - The table is being created. <br/> \*   UPDATING - The table is being updated. <br/> \*   DELETING - The table is being deleted. <br/> \*   ACTIVE - The table is ready for use. | 
| AWS-DynamoDB.TableDescription.CreationDateTime | unknown | The date and time when the table was created, in UNIX epoch time format. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput | unknown | The provisioned throughput settings for the table, consisting of read and write capacity units, along with data about increases and decreases. | 
| AWS-DynamoDB.TableDescription.TableSizeBytes | unknown | The total size of the specified table, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.ItemCount | unknown | The number of items in the specified table. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.TableArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the table. | 
| AWS-DynamoDB.TableDescription.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads. | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.BillingModeSummary | unknown | Contains the details for the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for the local secondary index, consisting of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes | unknown | Represents one or more local secondary indexes on the table. Each index is scoped to a given partition key value. Tables with one or more local secondary indexes are subject to an item collection size limit, where the amount of data within a given item collection cannot exceed 10 GB. Each element is composed of:  \*   IndexName - The name of the local secondary index. <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 	  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. <br/> \*   IndexSizeBytes - Represents the total size of the index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/> \*   ItemCount - Represents the number of items in the index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index.   | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexStatus | unknown | The current state of the global secondary index:  \*   CREATING - The index is being created. <br/> \*   UPDATING - The index is being updated. <br/> \*   DELETING - The index is being deleted. <br/> \*   ACTIVE - The index is ready for use. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Backfilling | unknown | Indicates whether the index is currently backfilling. \*Backfilling\* is the process of reading items from the table and determining whether they can be added to the index. \(Not all items will qualify: For example, a partition key cannot have any duplicate values.\) If an item can be added to the index, DynamoDB will do so. After all items have been processed, the backfilling operation is complete and Backfilling is false. You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false.   For indexes that were created during a CreateTable operation, the Backfilling attribute does not appear in the DescribeTable output.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index. For current minimum and maximum provisioned throughput values, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes | unknown | The global secondary indexes, if any, on the table. Each index is scoped to a given partition key value. Each element is composed of:  \*   Backfilling - If true, then the index is currently in the backfilling phase. Backfilling occurs only when a new global secondary index is added to the table. It is the process by which DynamoDB populates the new index with data from the table. \(This attribute does not appear for indexes that were created during a CreateTable operation.\)   You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false. \(This attribute does not appear for indexes that were created during a CreateTable operation.\) <br/> \*   IndexName - The name of the global secondary index. <br/> \*   IndexSizeBytes - The total size of the global secondary index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   IndexStatus - The current status of the global secondary index: <br/>	 \+   CREATING - The index is being created. <br/>	 \+   UPDATING - The index is being updated. <br/>	 \+   DELETING - The index is being deleted. <br/>	 \+   ACTIVE - The index is ready for use. 	  <br/> \*   ItemCount - The number of items in the global secondary index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. <br/> \*   ProvisionedThroughput - The provisioned throughput settings for the global secondary index, consisting of read and write capacity units, along with data about increases and decreases.  <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream.  | 
| AWS-DynamoDB.TableDescription.StreamSpecification | unknown | The current DynamoDB Streams configuration for the table. | 
| AWS-DynamoDB.TableDescription.LatestStreamLabel | unknown | A timestamp, in ISO 8601 format, for this stream. Note that LatestStreamLabel is not a unique identifier for the stream, because it is possible that a stream from another table might have the same timestamp. However, the combination of the following three elements is guaranteed to be unique:  \*  AWS customer ID <br/> \*  Table name <br/> \*   StreamLabel   | 
| AWS-DynamoDB.TableDescription.LatestStreamArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the latest stream for this table. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceBackupArn | unknown | The Amazon Resource Name \(ARN\) of the backup from which the table was restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceTableArn | unknown | The ARN of the source table of the backup that is being restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreDateTime | unknown | Point in time or source backup time. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreInProgress | unknown | Indicates if a restore is in progress or not. | 
| AWS-DynamoDB.TableDescription.RestoreSummary | unknown | Contains details for the restore. | 
| AWS-DynamoDB.TableDescription.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated. | 
| AWS-DynamoDB.TableDescription.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\). | 
| AWS-DynamoDB.TableDescription.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.TableDescription.SSEDescription | unknown | The description of the server-side encryption status on the specified table. | 
| AWS-DynamoDB.TableDescription | unknown | Represents the properties of the table. | 


### aws-dynamodb-delete-backup
***
Deletes an existing backup of a table. You can call DeleteBackup at a maximum rate of 10 times per second.


#### Base Command

`aws-dynamodb-delete-backup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| backup_arn | The ARN associated with the backup. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupArn | unknown | ARN associated with the backup. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupName | unknown | Name of the requested backup. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupSizeBytes | unknown | Size of the backup in bytes. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupStatus | unknown | Backup can be in one of the following states: CREATING, ACTIVE, DELETED.  | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupType | unknown | BackupType:  \*   USER - You create and manage these using the on-demand backup feature. <br/> \*   SYSTEM - If you delete a table with point-in-time recovery enabled, a SYSTEM backup is automatically created and is retained for 35 days \(at no additional cost\). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.  <br/> \*   AWS\\_BACKUP - On-demand backup created by you from AWS Backup service.  | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupCreationDateTime | unknown | Time at which the backup was created. This is the request time of the backup.  | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupExpiryDateTime | unknown | Time at which the automatic on-demand backup created by DynamoDB will expire. This SYSTEM on-demand backup expires automatically 35 days after its creation. | 
| AWS-DynamoDB.BackupDescription.BackupDetails | unknown | Contains the details of the backup created for the table.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableName | unknown | The name of the table for which the backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableArn | unknown | ARN of the table for which backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableSizeBytes | unknown | Size of the table in bytes. Note that this is an approximate value. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.KeySchema | unknown | Schema of the table.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableCreationDateTime | unknown | Time when the source table was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ProvisionedThroughput | unknown | Read IOPs and Write IOPS on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ItemCount | unknown | Number of items in the table. Note that this is an approximate value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.    | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails | unknown | Contains the details of the table when the backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for a local secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes | unknown | Represents the LSI properties for the table when the backup was created. It includes the IndexName, KeySchema and Projection for the LSIs on the table at the time of backup.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes | unknown | Represents the GSI properties for the table when the backup was created. It includes the IndexName, KeySchema, Projection, and ProvisionedThroughput for the GSIs on the table at the time of backup.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.StreamDescription.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.StreamDescription.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.StreamDescription | unknown | Stream settings on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.TimeToLiveDescription.TimeToLiveStatus | unknown |  The TTL status for the table. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.TimeToLiveDescription.AttributeName | unknown |  The name of the TTL attribute for items in the table. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.TimeToLiveDescription | unknown | Time to Live settings on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\). | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription | unknown | The description of the server-side encryption status on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails | unknown | Contains the details of the features enabled on the table when the backup was created. For example, LSIs, GSIs, streams, TTL. | 
| AWS-DynamoDB.BackupDescription | unknown | Contains the description of the backup created for the table. | 


### aws-dynamodb-delete-item
***
Deletes a single item in a table by primary key. You can perform a conditional delete operation that deletes the item if it exists, or if it has an expected attribute value. In addition to deleting an item, you can also return the item's attribute values in the same operation, using the ReturnValues parameter. Unless you specify conditions, the DeleteItem is an idempotent operation; running it multiple times on the same item or attribute does *not* result in an error response. Conditional deletes are useful for deleting items only if specific conditions are met. If those conditions are met, DynamoDB performs the delete. Otherwise, the item is not deleted.


#### Base Command

`aws-dynamodb-delete-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table from which to delete the item. | Optional | 
| key | A map of attribute names to AttributeValue objects, representing the primary key of the item to delete. For the primary key, you must provide all of the attributes. For example, with a simple primary key, you only need to provide a value for the partition key. For a composite primary key, you must provide values for both the partition key and the sort key. | Optional | 
| expected | This is a legacy parameter. Use ConditionExpression instead. For more information, see Expected in the *Amazon DynamoDB Developer Guide*. | Optional | 
| conditional_operator | This is a legacy parameter. Use ConditionExpression instead. For more information, see ConditionalOperator in the *Amazon DynamoDB Developer Guide*. | Optional | 
| return_values | Use ReturnValues if you want to get the item attributes as they appeared before they were deleted. For DeleteItem, the valid values are:  *   NONE - If ReturnValues is not specified, or if its value is NONE, then nothing is returned. (This setting is the default for ReturnValues.) <br/> *   ALL\_OLD - The content of the old item is returned. <br/>   The ReturnValues parameter is used by several DynamoDB operations; however, DeleteItem does not recognize any values other than NONE or ALL\_OLD.  | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| return_item_collection_metrics | Determines whether item collection metrics are returned. If set to SIZE, the response includes statistics about item collections, if any, that were modified during the operation are returned in the response. If set to NONE (the default), no statistics are returned. | Optional | 
| condition_expression | A condition that must be satisfied in order for a conditional DeleteItem to succeed. An expression can contain any of the following:  *  Functions: attribute\_exists \| attribute\_not\_exists \| attribute\_type \| contains \| begins\_with \| size  These function names are case-sensitive. <br/> *  Comparison operators: = \| &lt;&gt; \| &lt; \| &gt; \| &lt;= \| &gt;= \| BETWEEN \| IN   <br/> *   Logical operators: AND \| OR \| NOT  <br/>  For more information about condition expressions, see Condition Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_names | One or more substitution tokens for attribute names in an expression. The following are some use cases for using ExpressionAttributeNames:  *  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/> *  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/> *  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name:  *   Percentile  <br/>  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*). To work around this, you could specify the following for ExpressionAttributeNames:  *   {"#P":"Percentile"}  <br/>  You could then use this substitution in an expression, as in this example:  *   #P = :val  <br/>   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information on expression attribute names, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_values | One or more values that can be substituted in an expression. Use the **:** (colon) character in an expression to dereference an attribute value. For example, suppose that you wanted to check whether the value of the *ProductStatus* attribute was one of the following:   Available \| Backordered \| Discontinued  You would first need to specify ExpressionAttributeValues as follows:  { ":avail":{"S":"Available"}, ":back":{"S":"Backordered"}, ":disc":{"S":"Discontinued"} }  You could then use these values in an expression, such as this:  ProductStatus IN (:avail, :back, :disc)  For more information on expression attribute values, see Condition Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Attributes | unknown | A map of attribute names to AttributeValue objects, representing the item as it appeared before the DeleteItem operation. This map appears in the response only if ReturnValues was specified as ALL\\_OLD in the request. | 
| AWS-DynamoDB.ConsumedCapacity.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity | unknown | The capacity units consumed by the DeleteItem operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. ConsumedCapacity is only returned if the ReturnConsumedCapacity parameter was specified. For more information, see Provisioned Mode in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.ItemCollectionMetrics.ItemCollectionKey | unknown | The partition key value of the item collection. This value is the same as the partition key value of the item. | 
| AWS-DynamoDB.ItemCollectionMetrics.SizeEstimateRangeGB | unknown | An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 
| AWS-DynamoDB.ItemCollectionMetrics | unknown | Information about item collections, if any, that were affected by the DeleteItem operation. ItemCollectionMetrics is only returned if the ReturnItemCollectionMetrics parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response. Each ItemCollectionMetrics element consists of:  \*   ItemCollectionKey - The partition key value of the item collection. This is the same as the partition key value of the item itself. <br/> \*   SizeEstimateRangeGB - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 


### aws-dynamodb-delete-table
***
The DeleteTable operation deletes a table and all of its items. After a DeleteTable request, the specified table is in the DELETING state until DynamoDB completes the deletion. If the table is in the ACTIVE state, you can delete it. If a table is in CREATING or UPDATING states, then DynamoDB returns a ResourceInUseException. If the specified table does not exist, DynamoDB returns a ResourceNotFoundException. If table is already in the DELETING state, no error is returned.   DynamoDB might continue to accept data read and write operations, such as GetItem and PutItem, on a table in the DELETING state until the table deletion is complete.  When you delete a table, any indexes on that table are also deleted. If you have DynamoDB Streams enabled on the table, then the corresponding stream on that table goes into the DISABLED state, and the stream is automatically deleted after 24 hours. Use the DescribeTable action to check the status of the table. 


#### Base Command

`aws-dynamodb-delete-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table to delete. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeName | unknown | A name for the attribute. | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeType | unknown | The data type for the attribute, where:  \*   S - the attribute is of type String <br/> \*   N - the attribute is of type Number <br/> \*   B - the attribute is of type Binary  | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions | unknown | An array of AttributeDefinition objects. Each of these objects describes one attribute in the table and index key schema. Each AttributeDefinition object in this array is composed of:  \*   AttributeName - The name of the attribute. <br/> \*   AttributeType - The data type for the attribute.   | 
| AWS-DynamoDB.TableDescription.TableName | unknown | The name of the table. | 
| AWS-DynamoDB.TableDescription.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.KeySchema | unknown | The primary key structure for the table. Each KeySchemaElement consists of:  \*   AttributeName - The name of the attribute. <br/> \*   KeyType - The role of the attribute: <br/>	 \+   HASH - partition key <br/>	 \+   RANGE - sort key <br/>	   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  <br/>  For more information about primary keys, see Primary Key in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.TableStatus | unknown | The current state of the table:  \*   CREATING - The table is being created. <br/> \*   UPDATING - The table is being updated. <br/> \*   DELETING - The table is being deleted. <br/> \*   ACTIVE - The table is ready for use. <br/>  | 
| AWS-DynamoDB.TableDescription.CreationDateTime | unknown | The date and time when the table was created, in UNIX epoch time format. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput | unknown | The provisioned throughput settings for the table, consisting of read and write capacity units, along with data about increases and decreases. | 
| AWS-DynamoDB.TableDescription.TableSizeBytes | unknown | The total size of the specified table, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.ItemCount | unknown | The number of items in the specified table. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.TableArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the table. | 
| AWS-DynamoDB.TableDescription.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.BillingModeSummary | unknown | Contains the details for the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for the local secondary index, consisting of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index.   | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes | unknown | Represents one or more local secondary indexes on the table. Each index is scoped to a given partition key value. Tables with one or more local secondary indexes are subject to an item collection size limit, where the amount of data within a given item collection cannot exceed 10 GB. Each element is composed of:  \*   IndexName - The name of the local secondary index. <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   IndexSizeBytes - Represents the total size of the index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/> \*   ItemCount - Represents the number of items in the index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index.   | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexStatus | unknown | The current state of the global secondary index:  \*   CREATING - The index is being created. <br/> \*   UPDATING - The index is being updated. <br/> \*   DELETING - The index is being deleted. <br/> \*   ACTIVE - The index is ready for use. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Backfilling | unknown | Indicates whether the index is currently backfilling. \*Backfilling\* is the process of reading items from the table and determining whether they can be added to the index. \(Not all items will qualify: For example, a partition key cannot have any duplicate values.\) If an item can be added to the index, DynamoDB will do so. After all items have been processed, the backfilling operation is complete and Backfilling is false. You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false.   For indexes that were created during a CreateTable operation, the Backfilling attribute does not appear in the DescribeTable output.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index. For current minimum and maximum provisioned throughput values, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes | unknown | The global secondary indexes, if any, on the table. Each index is scoped to a given partition key value. Each element is composed of:  \*   Backfilling - If true, then the index is currently in the backfilling phase. Backfilling occurs only when a new global secondary index is added to the table. It is the process by which DynamoDB populates the new index with data from the table. \(This attribute does not appear for indexes that were created during a CreateTable operation.\)   You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false. \(This attribute does not appear for indexes that were created during a CreateTable operation.\) <br/> \*   IndexName - The name of the global secondary index. <br/> \*   IndexSizeBytes - The total size of the global secondary index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   IndexStatus - The current status of the global secondary index: <br/>	 \+   CREATING - The index is being created. <br/>	 \+   UPDATING - The index is being updated. <br/>	 \+   DELETING - The index is being deleted. <br/>	 \+   ACTIVE - The index is ready for use. 	  <br/> \*   ItemCount - The number of items in the global secondary index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   ProvisionedThroughput - The provisioned throughput settings for the global secondary index, consisting of read and write capacity units, along with data about increases and decreases.  <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.TableDescription.StreamSpecification | unknown | The current DynamoDB Streams configuration for the table. | 
| AWS-DynamoDB.TableDescription.LatestStreamLabel | unknown | A timestamp, in ISO 8601 format, for this stream. Note that LatestStreamLabel is not a unique identifier for the stream, because it is possible that a stream from another table might have the same timestamp. However, the combination of the following three elements is guaranteed to be unique:  \*  AWS customer ID <br/> \*  Table name <br/> \*   StreamLabel    | 
| AWS-DynamoDB.TableDescription.LatestStreamArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the latest stream for this table. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceBackupArn | unknown | The Amazon Resource Name \(ARN\) of the backup from which the table was restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceTableArn | unknown | The ARN of the source table of the backup that is being restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreDateTime | unknown | Point in time or source backup time. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreInProgress | unknown | Indicates if a restore is in progress or not. | 
| AWS-DynamoDB.TableDescription.RestoreSummary | unknown | Contains details for the restore. | 
| AWS-DynamoDB.TableDescription.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated. | 
| AWS-DynamoDB.TableDescription.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\). | 
| AWS-DynamoDB.TableDescription.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.TableDescription.SSEDescription | unknown | The description of the server-side encryption status on the specified table. | 
| AWS-DynamoDB.TableDescription | unknown | Represents the properties of a table. | 


### aws-dynamodb-describe-backup
***
Describes an existing backup of a table. You can call DescribeBackup at a maximum rate of 10 times per second.


#### Base Command

`aws-dynamodb-describe-backup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| backup_arn | The Amazon Resource Name (ARN) associated with the backup. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupArn | unknown | ARN associated with the backup. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupName | unknown | Name of the requested backup. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupSizeBytes | unknown | Size of the backup in bytes. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupStatus | unknown | Backup can be in one of the following states: CREATING, ACTIVE, DELETED.  | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupType | unknown | BackupType:  \*   USER - You create and manage these using the on-demand backup feature. <br/> \*   SYSTEM - If you delete a table with point-in-time recovery enabled, a SYSTEM backup is automatically created and is retained for 35 days \(at no additional cost\). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.  <br/> \*   AWS\\_BACKUP - On-demand backup created by you from AWS Backup service. | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupCreationDateTime | unknown | Time at which the backup was created. This is the request time of the backup.  | 
| AWS-DynamoDB.BackupDescription.BackupDetails.BackupExpiryDateTime | unknown | Time at which the automatic on-demand backup created by DynamoDB will expire. This SYSTEM on-demand backup expires automatically 35 days after its creation. | 
| AWS-DynamoDB.BackupDescription.BackupDetails | unknown | Contains the details of the backup created for the table.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableName | unknown | The name of the table for which the backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableArn | unknown | ARN of the table for which backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableSizeBytes | unknown | Size of the table in bytes. Note that this is an approximate value. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.KeySchema | unknown | Schema of the table.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.TableCreationDateTime | unknown | Time when the source table was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ProvisionedThroughput | unknown | Read IOPs and Write IOPS on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.ItemCount | unknown | Number of items in the table. Note that this is an approximate value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.BackupDescription.SourceTableDetails | unknown | Contains the details of the table when the backup was created.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for a local secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.LocalSecondaryIndexes | unknown | Represents the LSI properties for the table when the backup was created. It includes the IndexName, KeySchema and Projection for the LSIs on the table at the time of backup.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. If read/write capacity mode is PAY\\_PER\\_REQUEST the value is set to 0. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.GlobalSecondaryIndexes | unknown | Represents the GSI properties for the table when the backup was created. It includes the IndexName, KeySchema, Projection, and ProvisionedThroughput for the GSIs on the table at the time of backup.  | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.StreamDescription.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.StreamDescription.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.StreamDescription | unknown | Stream settings on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.TimeToLiveDescription.TimeToLiveStatus | unknown |  The TTL status for the table. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.TimeToLiveDescription.AttributeName | unknown |  The name of the TTL attribute for items in the table. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.TimeToLiveDescription | unknown | Time to Live settings on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\).   | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails.SSEDescription | unknown | The description of the server-side encryption status on the table when the backup was created. | 
| AWS-DynamoDB.BackupDescription.SourceTableFeatureDetails | unknown | Contains the details of the features enabled on the table when the backup was created. For example, LSIs, GSIs, streams, TTL. | 
| AWS-DynamoDB.BackupDescription | unknown | Contains the description of the backup created for the table. | 


### aws-dynamodb-describe-continuous-backups
***
Checks the status of continuous backups and point in time recovery on the specified table. Continuous backups are ENABLED on all tables at table creation. If point in time recovery is enabled, PointInTimeRecoveryStatus will be set to ENABLED.  After continuous backups and point in time recovery are enabled, you can restore to any point in time within EarliestRestorableDateTime and LatestRestorableDateTime.   LatestRestorableDateTime is typically 5 minutes before the current time. You can restore your table to any point in time during the last 35 days.  You can call DescribeContinuousBackups at a maximum rate of 10 times per second.


#### Base Command

`aws-dynamodb-describe-continuous-backups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | Name of the table for which the customer wants to check the continuous backups and point in time recovery settings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.ContinuousBackupsDescription.ContinuousBackupsStatus | unknown |  ContinuousBackupsStatus can be one of the following states: ENABLED, DISABLED | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus | unknown | The current state of point in time recovery:  \*   ENABLING - Point in time recovery is being enabled. <br/> \*   ENABLED - Point in time recovery is enabled. <br/> \*   DISABLED - Point in time recovery is disabled. | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription.EarliestRestorableDateTime | unknown | Specifies the earliest point in time you can restore your table to. You can restore your table to any point in time during the last 35 days.  | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription.LatestRestorableDateTime | unknown |  LatestRestorableDateTime is typically 5 minutes before the current time.  | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription | unknown | The description of the point in time recovery settings applied to the table. | 
| AWS-DynamoDB.ContinuousBackupsDescription | unknown | Represents the continuous backups and point in time recovery settings on the table. | 


### aws-dynamodb-describe-endpoints
***
Returns the regional endpoint information.


#### Base Command

`aws-dynamodb-describe-endpoints`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Endpoints.Address | unknown | IP address of the endpoint. | 
| AWS-DynamoDB.Endpoints.CachePeriodInMinutes | unknown | Endpoint cache time to live \(TTL\) value. | 
| AWS-DynamoDB.Endpoints | unknown | List of endpoints. | 


### aws-dynamodb-describe-global-table
***
Returns information about the specified global table.


#### Base Command

`aws-dynamodb-describe-global-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| global_table_name | The name of the global table. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.GlobalTableDescription.ReplicationGroup.RegionName | unknown | The name of the Region. | 
| AWS-DynamoDB.GlobalTableDescription.ReplicationGroup | unknown | The Regions where the global table has replicas. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableArn | unknown | The unique identifier of the global table. | 
| AWS-DynamoDB.GlobalTableDescription.CreationDateTime | unknown | The creation time of the global table. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableStatus | unknown | The current state of the global table:  \*   CREATING - The global table is being created. <br/> \*   UPDATING - The global table is being updated. <br/> \*   DELETING - The global table is being deleted. <br/> \*   ACTIVE - The global table is ready for use. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableName | unknown | The global table name. | 
| AWS-DynamoDB.GlobalTableDescription | unknown | Contains the details of the global table. | 


### aws-dynamodb-describe-global-table-settings
***
Describes Region-specific settings for a global table.


#### Base Command

`aws-dynamodb-describe-global-table-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| global_table_name | The name of the global table to describe. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.GlobalTableName | unknown | The name of the global table. | 
| AWS-DynamoDB.ReplicaSettings.RegionName | unknown | The Region name of the replica. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaStatus | unknown | The current state of the Region:  \*   CREATING - The Region is being created. <br/> \*   UPDATING - The Region is being updated. <br/> \*   DELETING - The Region is being deleted. <br/> \*   ACTIVE - The Region is ready for use. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaBillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaBillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaBillingModeSummary | unknown | The read/write capacity mode of the replica. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings | unknown | Auto scaling settings for a global table replica's read capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings | unknown | Auto scaling settings for a global table replica's write capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.IndexName | unknown | The name of the global secondary index. The name must be unique among all other indexes on this table. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.IndexStatus | unknown |  The current status of the global secondary index:  \*   CREATING - The global secondary index is being created. <br/> \*   UPDATING - The global secondary index is being updated. <br/> \*   DELETING - The global secondary index is being deleted. <br/> \*   ACTIVE - The global secondary index is ready for use. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings | unknown | Auto scaling settings for a global secondary index replica's read capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings | unknown | Auto scaling settings for a global secondary index replica's write capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings | unknown | Replica global secondary index settings for the global table. | 
| AWS-DynamoDB.ReplicaSettings | unknown | The Region-specific settings for the global table. | 


### aws-dynamodb-describe-limits
***
Returns the current provisioned-capacity limits for your AWS account in a Region, both for the Region as a whole and for any one DynamoDB table that you create there. When you establish an AWS account, the account has initial limits on the maximum read capacity units and write capacity units that you can provision across all of your DynamoDB tables in a given Region. Also, there are per-table limits that apply when you create a table there. For more information, see Limits page in the *Amazon DynamoDB Developer Guide*. Although you can increase these limits by filing a case at AWS Support Center, obtaining the increase is not instantaneous. The DescribeLimits action lets you write code to compare the capacity you are currently using to those limits imposed by your account so that you have enough time to apply for an increase before you hit a limit. For example, you could use one of the AWS SDKs to do the following:  2.  Call DescribeLimits for a particular Region to obtain your current account limits on provisioned capacity there. 
 4.  Create a variable to hold the aggregate read capacity units provisioned for all your tables in that Region, and one to hold the aggregate write capacity units. Zero them both. 
 6.  Call ListTables to obtain a list of all your DynamoDB tables. 
 8.  For each table name listed by ListTables, do the following: 
	 *  Call DescribeTable with the table name. 
	 *  Use the data returned by DescribeTable to add the read capacity units and write capacity units provisioned for the table itself to your variables. 
	 *  If the table has one or more global secondary indexes (GSIs), loop over these GSIs and add their provisioned capacity values to your variables as well. 
	  
 10.  Report the account limits for that Region returned by DescribeLimits, along with the total current provisioned capacity levels you have calculated. 
  This will let you see whether you are getting close to your account-level limits. The per-table limits apply only when you are creating a new table. They restrict the sum of the provisioned capacity of the new table itself and all its global secondary indexes. For existing tables and their GSIs, DynamoDB doesn't let you increase provisioned capacity extremely rapidly. But the only upper limit that applies is that the aggregate provisioned capacity over all your tables and GSIs cannot exceed either of the per-account limits.   DescribeLimits should only be called periodically. You can expect throttling errors if you call it more than once in a minute.  The DescribeLimits Request element has no content.


#### Base Command

`aws-dynamodb-describe-limits`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.AccountMaxReadCapacityUnits | unknown | The maximum total read capacity units that your account allows you to provision across all of your tables in this Region. | 
| AWS-DynamoDB.AccountMaxWriteCapacityUnits | unknown | The maximum total write capacity units that your account allows you to provision across all of your tables in this Region. | 
| AWS-DynamoDB.TableMaxReadCapacityUnits | unknown | The maximum read capacity units that your account allows you to provision for a new table that you are creating in this Region, including the read capacity units provisioned for its global secondary indexes \(GSIs\). | 
| AWS-DynamoDB.TableMaxWriteCapacityUnits | unknown | The maximum write capacity units that your account allows you to provision for a new table that you are creating in this Region, including the write capacity units provisioned for its global secondary indexes \(GSIs\). | 


### aws-dynamodb-describe-table
***
Returns information about the table, including the current status of the table, when it was created, the primary key schema, and any indexes on the table.  If you issue a DescribeTable request immediately after a CreateTable request, DynamoDB might return a ResourceNotFoundException. This is because DescribeTable uses an eventually consistent query, and the metadata for your table might not be available at that moment. Wait for a few seconds, and then try the DescribeTable request again. 


#### Base Command

`aws-dynamodb-describe-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table to describe. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Table.AttributeDefinitions.AttributeName | unknown | A name for the attribute. | 
| AWS-DynamoDB.Table.AttributeDefinitions.AttributeType | unknown | The data type for the attribute, where:  \*   S - the attribute is of type String <br/> \*   N - the attribute is of type Number <br/> \*   B - the attribute is of type Binary | 
| AWS-DynamoDB.Table.AttributeDefinitions | unknown | An array of AttributeDefinition objects. Each of these objects describes one attribute in the table and index key schema. Each AttributeDefinition object in this array is composed of:  \*   AttributeName - The name of the attribute. <br/> \*   AttributeType - The data type for the attribute. | 
| AWS-DynamoDB.Table.TableName | unknown | The name of the table. | 
| AWS-DynamoDB.Table.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.Table.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.Table.KeySchema | unknown | The primary key structure for the table. Each KeySchemaElement consists of:  \*   AttributeName - The name of the attribute. <br/> \*   KeyType - The role of the attribute: <br/>	 \+   HASH - partition key <br/>	 \+   RANGE - sort key <br/>	   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  <br/>  For more information about primary keys, see Primary Key in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.Table.TableStatus | unknown | The current state of the table:  \*   CREATING - The table is being created. <br/> \*   UPDATING - The table is being updated. <br/> \*   DELETING - The table is being deleted. <br/> \*   ACTIVE - The table is ready for use. | 
| AWS-DynamoDB.Table.CreationDateTime | unknown | The date and time when the table was created, in UNIX epoch time format. | 
| AWS-DynamoDB.Table.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.Table.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.Table.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.Table.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.Table.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.Table.ProvisionedThroughput | unknown | The provisioned throughput settings for the table, consisting of read and write capacity units, along with data about increases and decreases. | 
| AWS-DynamoDB.Table.TableSizeBytes | unknown | The total size of the specified table, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.Table.ItemCount | unknown | The number of items in the specified table. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.Table.TableArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the table. | 
| AWS-DynamoDB.Table.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.Table.BillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.Table.BillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.Table.BillingModeSummary | unknown | Contains the details for the read/write capacity mode. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for the local secondary index, consisting of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.Table.LocalSecondaryIndexes | unknown | Represents one or more local secondary indexes on the table. Each index is scoped to a given partition key value. Tables with one or more local secondary indexes are subject to an item collection size limit, where the amount of data within a given item collection cannot exceed 10 GB. Each element is composed of:  \*   IndexName - The name of the local secondary index. <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   IndexSizeBytes - Represents the total size of the index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/> \*   ItemCount - Represents the number of items in the index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.IndexStatus | unknown | The current state of the global secondary index:  \*   CREATING - The index is being created. <br/> \*   UPDATING - The index is being updated. <br/> \*   DELETING - The index is being deleted. <br/> \*   ACTIVE - The index is ready for use. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.Backfilling | unknown | Indicates whether the index is currently backfilling. \*Backfilling\* is the process of reading items from the table and determining whether they can be added to the index. \(Not all items will qualify: For example, a partition key cannot have any duplicate values.\) If an item can be added to the index, DynamoDB will do so. After all items have been processed, the backfilling operation is complete and Backfilling is false. You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false.   For indexes that were created during a CreateTable operation, the Backfilling attribute does not appear in the DescribeTable output.  | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index. For current minimum and maximum provisioned throughput values, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.Table.GlobalSecondaryIndexes | unknown | The global secondary indexes, if any, on the table. Each index is scoped to a given partition key value. Each element is composed of:  \*   Backfilling - If true, then the index is currently in the backfilling phase. Backfilling occurs only when a new global secondary index is added to the table. It is the process by which DynamoDB populates the new index with data from the table. \(This attribute does not appear for indexes that were created during a CreateTable operation.\)   You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false. \(This attribute does not appear for indexes that were created during a CreateTable operation.\) <br/> \*   IndexName - The name of the global secondary index. <br/> \*   IndexSizeBytes - The total size of the global secondary index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   IndexStatus - The current status of the global secondary index: <br/>	 \+   CREATING - The index is being created. <br/>	 \+   UPDATING - The index is being updated. <br/>	 \+   DELETING - The index is being deleted. <br/>	 \+   ACTIVE - The index is ready for use. 	  <br/> \*   ItemCount - The number of items in the global secondary index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   ProvisionedThroughput - The provisioned throughput settings for the global secondary index, consisting of read and write capacity units, along with data about increases and decreases.  <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.Table.StreamSpecification.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.Table.StreamSpecification.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.Table.StreamSpecification | unknown | The current DynamoDB Streams configuration for the table. | 
| AWS-DynamoDB.Table.LatestStreamLabel | unknown | A timestamp, in ISO 8601 format, for this stream. Note that LatestStreamLabel is not a unique identifier for the stream, because it is possible that a stream from another table might have the same timestamp. However, the combination of the following three elements is guaranteed to be unique:  \*  AWS customer ID <br/> \*  Table name <br/> \*   StreamLabel    | 
| AWS-DynamoDB.Table.LatestStreamArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the latest stream for this table. | 
| AWS-DynamoDB.Table.RestoreSummary.SourceBackupArn | unknown | The Amazon Resource Name \(ARN\) of the backup from which the table was restored. | 
| AWS-DynamoDB.Table.RestoreSummary.SourceTableArn | unknown | The ARN of the source table of the backup that is being restored. | 
| AWS-DynamoDB.Table.RestoreSummary.RestoreDateTime | unknown | Point in time or source backup time. | 
| AWS-DynamoDB.Table.RestoreSummary.RestoreInProgress | unknown | Indicates if a restore is in progress or not. | 
| AWS-DynamoDB.Table.RestoreSummary | unknown | Contains details for the restore. | 
| AWS-DynamoDB.Table.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated. | 
| AWS-DynamoDB.Table.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\). | 
| AWS-DynamoDB.Table.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.Table.SSEDescription | unknown | The description of the server-side encryption status on the specified table. | 
| AWS-DynamoDB.Table | unknown | The properties of the table. | 


### aws-dynamodb-describe-time-to-live
***
Gives a description of the Time to Live (TTL) status on the specified table. 


#### Base Command

`aws-dynamodb-describe-time-to-live`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table to be described. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TimeToLiveDescription.TimeToLiveStatus | unknown |  The TTL status for the table. | 
| AWS-DynamoDB.TimeToLiveDescription.AttributeName | unknown |  The name of the TTL attribute for items in the table. | 
| AWS-DynamoDB.TimeToLiveDescription | unknown | Time to Live settings on the table when the backup was created. | 


### aws-dynamodb-get-item
***
The GetItem operation returns a set of attributes for the item with the given primary key. If there is no matching item, GetItem does not return any data and there will be no Item element in the response.  GetItem provides an eventually consistent read by default. If your application requires a strongly consistent read, set ConsistentRead to true. Although a strongly consistent read might take more time than an eventually consistent read, it always returns the last updated value.


#### Base Command

`aws-dynamodb-get-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table containing the requested item. | Optional | 
| key | A map of attribute names to AttributeValue objects, representing the primary key of the item to retrieve. For the primary key, you must provide all of the attributes. For example, with a simple primary key, you only need to provide a value for the partition key. For a composite primary key, you must provide values for both the partition key and the sort key. | Optional | 
| attributes_to_get | This is a legacy parameter. Use ProjectionExpression instead. For more information, see AttributesToGet in the *Amazon DynamoDB Developer Guide*. | Optional | 
| consistent_read | &lt;p&gt;Determines the read consistency model: If set to &lt;code&gt;true&lt;/code&gt;, then the operation uses strongly consistent reads; otherwise, the operation uses eventually consistent reads.&lt;/p&gt; | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| projection_expression | A string that identifies one or more attributes to retrieve from the table. These attributes can include scalars, sets, or elements of a JSON document. The attributes in the expression must be separated by commas. If no attribute names are specified, then all attributes are returned. If any of the requested attributes are not found, they do not appear in the result. For more information, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_names | One or more substitution tokens for attribute names in an expression. The following are some use cases for using ExpressionAttributeNames:  *  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/> *  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/> *  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name:  *   Percentile  <br/>  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*). To work around this, you could specify the following for ExpressionAttributeNames:  *   {"#P":"Percentile"}  <br/>  You could then use this substitution in an expression, as in this example:  *   #P = :val  <br/>   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information on expression attribute names, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Item | unknown | A map of attribute names to AttributeValue objects, as specified by ProjectionExpression. | 
| AWS-DynamoDB.ConsumedCapacity.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity | unknown | The capacity units consumed by the GetItem operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. ConsumedCapacity is only returned if the ReturnConsumedCapacity parameter was specified. For more information, see Read/Write Capacity Mode in the \*Amazon DynamoDB Developer Guide\*. | 


### aws-dynamodb-list-backups
***
List backups associated with an AWS account. To list backups for a given table, specify TableName. ListBackups returns a paginated list of results with at most 1 MB worth of items in a page. You can also specify a limit for the maximum number of entries to be returned in a page.  In the request, start time is inclusive, but end time is exclusive. Note that these limits are for the time at which the original backup was requested. You can call ListBackups a maximum of five times per second.


#### Base Command

`aws-dynamodb-list-backups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The backups from the table specified by TableName are listed.  | Optional | 
| exclusive_start_backup_arn |  LastEvaluatedBackupArn is the Amazon Resource Name (ARN) of the backup last evaluated when the current page of results was returned, inclusive of the current page of results. This value may be specified as the ExclusiveStartBackupArn of a new ListBackups operation in order to fetch the next page of results.  | Optional | 
| backup_type | The backups from the table specified by BackupType are listed. Where BackupType can be:  *   USER - On-demand backup created by you. <br/> *   SYSTEM - On-demand backup automatically created by DynamoDB. <br/> *   ALL - All types of on-demand backups (USER and SYSTEM). <br/>  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.BackupSummaries.TableName | unknown | Name of the table. | 
| AWS-DynamoDB.BackupSummaries.TableId | unknown | Unique identifier for the table. | 
| AWS-DynamoDB.BackupSummaries.TableArn | unknown | ARN associated with the table. | 
| AWS-DynamoDB.BackupSummaries.BackupArn | unknown | ARN associated with the backup. | 
| AWS-DynamoDB.BackupSummaries.BackupName | unknown | Name of the specified backup. | 
| AWS-DynamoDB.BackupSummaries.BackupCreationDateTime | unknown | Time at which the backup was created. | 
| AWS-DynamoDB.BackupSummaries.BackupExpiryDateTime | unknown | Time at which the automatic on-demand backup created by DynamoDB will expire. This SYSTEM on-demand backup expires automatically 35 days after its creation. | 
| AWS-DynamoDB.BackupSummaries.BackupStatus | unknown | Backup can be in one of the following states: CREATING, ACTIVE, DELETED. | 
| AWS-DynamoDB.BackupSummaries.BackupType | unknown | BackupType:  \*   USER - You create and manage these using the on-demand backup feature. <br/> \*   SYSTEM - If you delete a table with point-in-time recovery enabled, a SYSTEM backup is automatically created and is retained for 35 days \(at no additional cost\). System backups allow you to restore the deleted table to the state it was in just before the point of deletion.  <br/> \*   AWS\\_BACKUP - On-demand backup created by you from AWS Backup service. | 
| AWS-DynamoDB.BackupSummaries.BackupSizeBytes | unknown | Size of the backup in bytes. | 
| AWS-DynamoDB.BackupSummaries | unknown | List of BackupSummary objects. | 
| AWS-DynamoDB.LastEvaluatedBackupArn | unknown |  The ARN of the backup last evaluated when the current page of results was returned, inclusive of the current page of results. This value may be specified as the ExclusiveStartBackupArn of a new ListBackups operation in order to fetch the next page of results.   If LastEvaluatedBackupArn is empty, then the last page of results has been processed and there are no more results to be retrieved.   If LastEvaluatedBackupArn is not empty, this may or may not indicate that there is more data to be returned. All results are guaranteed to have been returned if and only if no value for LastEvaluatedBackupArn is returned.  | 


#### Command Example
```!aws-dynamodb-list-backups```

#### Context Example
```json
{
    "AWS-DynamoDB": {
        "BackupSummaries": [
            {
                "BackupArn": "arn:table/Demisto_Test_Table",
                "BackupCreationDateTime": "2020-01-05 15:22:10.981000+00:00",
                "BackupName": "TestBackup",
                "BackupSizeBytes": 0,
                "BackupStatus": "AVAILABLE",
                "BackupType": "USER",
                "TableArn": "arn:table/Demisto_Test_Table",
                "TableId": "1",
                "TableName": "Demisto_Test_Table"
            },
            {
                "BackupArn": "arn:table/Demisto_Test_Table",
                "BackupCreationDateTime": "2020-01-13 14:00:16.905000+00:00",
                "BackupName": "TestBackup2",
                "BackupSizeBytes": 0,
                "BackupStatus": "AVAILABLE",
                "BackupType": "USER",
                "TableArn": "arn:table/Demisto_Test_Table",
                "TableId": "2",
                "TableName": "Demisto_Test_Table"
            }
        ]
    }
}
```

#### Human Readable Output

>### AWS DynamoDB ListBackups
>|BackupArn|BackupCreationDateTime|BackupName|BackupSizeBytes|BackupStatus|BackupType|TableArn|TableId|TableName|
>|---|---|---|---|---|---|---|---|---|
>| arn:table/Demisto_Test_Table | 2020-01-05 15:22:10.981000+00:00 | TestBackup | 0 | AVAILABLE | USER | arn:table/Demisto_Test_Table | 1 | Demisto_Test_Table |
>| arn:table/Demisto_Test_Table | 2020-01-13 14:00:16.905000+00:00 | TestBackup2 | 0 | AVAILABLE | USER | arn:table/Demisto_Test_Table | 2 | Demisto_Test_Table |


### aws-dynamodb-list-global-tables
***
Lists all global tables that have a replica in the specified Region.


#### Base Command

`aws-dynamodb-list-global-tables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| exclusive_start_global_table_name | The first global table name that this operation will evaluate. | Optional | 
| region_name | Lists the global tables in a specific Region. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.GlobalTables.GlobalTableName | unknown | The global table name. | 
| AWS-DynamoDB.GlobalTables.ReplicationGroup.RegionName | unknown | The Region where the replica needs to be created. | 
| AWS-DynamoDB.GlobalTables.ReplicationGroup | unknown | The Regions where the global table has replicas. | 
| AWS-DynamoDB.GlobalTables | unknown | List of global table names. | 
| AWS-DynamoDB.LastEvaluatedGlobalTableName | unknown | Last evaluated global table name. | 


### aws-dynamodb-list-tables
***
Returns an array of table names associated with the current account and endpoint. The output from ListTables is paginated, with each page returning a maximum of 100 table names.


#### Base Command

`aws-dynamodb-list-tables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| exclusive_start_table_name | The first table name that this operation will evaluate. Use the value that was returned for LastEvaluatedTableName in a previous operation, so that you can obtain the next page of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableNames | unknown | The names of the tables associated with the current account at the current endpoint. The maximum size of this array is 100. If LastEvaluatedTableName also appears in the output, you can use this value as the ExclusiveStartTableName parameter in a subsequent ListTables request and obtain the next page of results. | 
| AWS-DynamoDB.LastEvaluatedTableName | unknown | The name of the last table in the current page of results. Use this value as the ExclusiveStartTableName in a new request to obtain the next page of results, until all the table names are returned. If you do not receive a LastEvaluatedTableName value in the response, this means that there are no more table names to be retrieved. | 

#### Command Example
```!aws-dynamodb-list-tables```

#### Context Example
```json
{
    "AWS-DynamoDB": {
        "TableNames": [
            "Demisto_Test_Table",
            "Items2"
        ]
    }
}
```

#### Human Readable Output

>### AWS DynamoDB ListTables
>|TableNames|
>|---|
>| Demisto_Test_Table,<br/>Items2 |


### aws-dynamodb-list-tags-of-resource
***
List all tags on an Amazon DynamoDB resource. You can call ListTagsOfResource up to 10 times per second, per account. For an overview on tagging DynamoDB resources, see Tagging for DynamoDB in the *Amazon DynamoDB Developer Guide*.


#### Base Command

`aws-dynamodb-list-tags-of-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The Amazon DynamoDB resource with tags to be listed. This value is an Amazon Resource Name (ARN). | Optional | 
| next_token | An optional string that, if supplied, must be copied from the output of a previous call to ListTagOfResource. When provided in this manner, this API fetches the next page of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Tags.Key | unknown | The key of the tag. Tag keys are case sensitive. Each DynamoDB table can only have up to one tag with the same key. If you try to add an existing tag \(same key\), the existing tag value will be updated to the new value.  | 
| AWS-DynamoDB.Tags.Value | unknown | The value of the tag. Tag values are case-sensitive and can be null. | 
| AWS-DynamoDB.Tags | unknown | The tags currently associated with the Amazon DynamoDB resource. | 
| AWS-DynamoDB.NextToken | unknown | If this value is returned, there are additional results to be displayed. To retrieve them, call ListTagsOfResource again, with NextToken set to this value. | 


### aws-dynamodb-put-item
***
Creates a new item, or replaces an old item with a new item. If an item that has the same primary key as the new item already exists in the specified table, the new item completely replaces the existing item. You can perform a conditional put operation (add a new item if one with the specified primary key doesn't exist), or replace an existing item if it has certain attribute values. You can return the item's attribute values in the same operation, using the ReturnValues parameter.  This topic provides general information about the PutItem API. For information on how to call the PutItem API using the AWS SDK in specific languages, see the following:  *    PutItem in the AWS Command Line Interface  
 *    PutItem in the AWS SDK for .NET  
 *    PutItem in the AWS SDK for C++  
 *    PutItem in the AWS SDK for Go  
 *    PutItem in the AWS SDK for Java  
 *    PutItem in the AWS SDK for JavaScript  
 *    PutItem in the AWS SDK for PHP V3  
 *    PutItem in the AWS SDK for Python  
 *    PutItem in the AWS SDK for Ruby V2  
   When you add an item, the primary key attributes are the only required attributes. Attribute values cannot be null. String and Binary type attributes must have lengths greater than zero. Set type attributes cannot be empty. Requests with empty values will be rejected with a ValidationException exception.  To prevent a new item from replacing an existing item, use a conditional expression that contains the attribute\_not\_exists function with the name of the attribute being used as the partition key for the table. Since every record must contain that attribute, the attribute\_not\_exists function will only succeed if no matching item exists.  For more information about PutItem, see Working with Items in the *Amazon DynamoDB Developer Guide*.


#### Base Command

`aws-dynamodb-put-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table to contain the item. | Optional | 
| item | A map of attribute name/value pairs, one for each attribute. Only the primary key attributes are required; you can optionally provide other attribute name-value pairs for the item. You must provide all of the attributes for the primary key. For example, with a simple primary key, you only need to provide a value for the partition key. For a composite primary key, you must provide both values for both the partition key and the sort key. If you specify any attributes that are part of an index key, then the data types for those attributes must match those of the schema in the table's attribute definition. For more information about primary keys, see Primary Key in the *Amazon DynamoDB Developer Guide*. Each element in the Item map is an AttributeValue object. | Optional | 
| expected | This is a legacy parameter. Use ConditionExpression instead. For more information, see Expected in the *Amazon DynamoDB Developer Guide*. | Optional | 
| return_values | Use ReturnValues if you want to get the item attributes as they appeared before they were updated with the PutItem request. For PutItem, the valid values are:  *   NONE - If ReturnValues is not specified, or if its value is NONE, then nothing is returned. (This setting is the default for ReturnValues.) <br/> *   ALL\_OLD - If PutItem overwrote an attribute name-value pair, then the content of the old item is returned. <br/>   The ReturnValues parameter is used by several DynamoDB operations; however, PutItem does not recognize any values other than NONE or ALL\_OLD.  | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| return_item_collection_metrics | Determines whether item collection metrics are returned. If set to SIZE, the response includes statistics about item collections, if any, that were modified during the operation are returned in the response. If set to NONE (the default), no statistics are returned. | Optional | 
| conditional_operator | This is a legacy parameter. Use ConditionExpression instead. For more information, see ConditionalOperator in the *Amazon DynamoDB Developer Guide*. | Optional | 
| condition_expression | A condition that must be satisfied in order for a conditional PutItem operation to succeed. An expression can contain any of the following:  *  Functions: attribute\_exists \| attribute\_not\_exists \| attribute\_type \| contains \| begins\_with \| size  These function names are case-sensitive. <br/> *  Comparison operators: = \| &lt;&gt; \| &lt; \| &gt; \| &lt;= \| &gt;= \| BETWEEN \| IN   <br/> *   Logical operators: AND \| OR \| NOT  <br/>  For more information on condition expressions, see Condition Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_names | One or more substitution tokens for attribute names in an expression. The following are some use cases for using ExpressionAttributeNames:  *  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/> *  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/> *  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name:  *   Percentile  <br/>  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*). To work around this, you could specify the following for ExpressionAttributeNames:  *   {"#P":"Percentile"}  <br/>  You could then use this substitution in an expression, as in this example:  *   #P = :val  <br/>   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information on expression attribute names, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_values | One or more values that can be substituted in an expression. Use the **:** (colon) character in an expression to dereference an attribute value. For example, suppose that you wanted to check whether the value of the *ProductStatus* attribute was one of the following:   Available \| Backordered \| Discontinued  You would first need to specify ExpressionAttributeValues as follows:  { ":avail":{"S":"Available"}, ":back":{"S":"Backordered"}, ":disc":{"S":"Discontinued"} }  You could then use these values in an expression, such as this:  ProductStatus IN (:avail, :back, :disc)  For more information on expression attribute values, see Condition Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Attributes | unknown | The attribute values as they appeared before the PutItem operation, but only if ReturnValues is specified as ALL\\_OLD in the request. Each element consists of an attribute name and an attribute value. | 
| AWS-DynamoDB.ConsumedCapacity.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity | unknown | The capacity units consumed by the PutItem operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. ConsumedCapacity is only returned if the ReturnConsumedCapacity parameter was specified. For more information, see Read/Write Capacity Mode in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.ItemCollectionMetrics.ItemCollectionKey | unknown | The partition key value of the item collection. This value is the same as the partition key value of the item. | 
| AWS-DynamoDB.ItemCollectionMetrics.SizeEstimateRangeGB | unknown | An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 
| AWS-DynamoDB.ItemCollectionMetrics | unknown | Information about item collections, if any, that were affected by the PutItem operation. ItemCollectionMetrics is only returned if the ReturnItemCollectionMetrics parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response. Each ItemCollectionMetrics element consists of:  \*   ItemCollectionKey - The partition key value of the item collection. This is the same as the partition key value of the item itself. <br/> \*   SizeEstimateRangeGB - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 


### aws-dynamodb-query
***
The Query operation finds items based on primary key values. You can query any table or secondary index that has a composite primary key (a partition key and a sort key).  Use the KeyConditionExpression parameter to provide a specific value for the partition key. The Query operation will return all of the items from the table or index with that partition key value. You can optionally narrow the scope of the Query operation by specifying a sort key value and a comparison operator in KeyConditionExpression. To further refine the Query results, you can optionally provide a FilterExpression. A FilterExpression determines which items within the results should be returned to you. All of the other results are discarded.   A Query operation always returns a result set. If no matching items are found, the result set will be empty. Queries that do not return results consume the minimum number of read capacity units for that type of read operation.    DynamoDB calculates the number of read capacity units consumed based on item size, not on the amount of data that is returned to an application. The number of capacity units consumed will be the same whether you request all of the attributes (the default behavior) or just some of them (using a projection expression). The number will also be the same whether or not you use a FilterExpression.    Query results are always sorted by the sort key value. If the data type of the sort key is Number, the results are returned in numeric order; otherwise, the results are returned in order of UTF-8 bytes. By default, the sort order is ascending. To reverse the order, set the ScanIndexForward parameter to false.   A single Query operation will read up to the maximum number of items set (if using the Limit parameter) or a maximum of 1 MB of data and then apply any filtering to the results using FilterExpression. If LastEvaluatedKey is present in the response, you will need to paginate the result set. For more information, see Paginating the Results in the *Amazon DynamoDB Developer Guide*.   FilterExpression is applied after a Query finishes, but before the results are returned. A FilterExpression cannot contain partition key or sort key attributes. You need to specify those attributes in the KeyConditionExpression.    A Query operation can return an empty result set and a LastEvaluatedKey if all the items read for the page of results are filtered out.   You can query a table, a local secondary index, or a global secondary index. For a query on a table or on a local secondary index, you can set the ConsistentRead parameter to true and obtain a strongly consistent result. Global secondary indexes support eventually consistent reads only, so do not specify ConsistentRead when querying a global secondary index.


#### Base Command

`aws-dynamodb-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table containing the requested items. | Optional | 
| index_name | The name of an index to query. This index can be any local secondary index or global secondary index on the table. Note that if you use the IndexName parameter, you must also provide TableName.  | Optional | 
| select | The attributes to be returned in the result. You can retrieve all item attributes, specific item attributes, the count of matching items, or in the case of an index, some or all of the attributes projected into the index.  *   ALL\_ATTRIBUTES - Returns all of the item attributes from the specified table or index. If you query a local secondary index, then for each matching item in the index, DynamoDB fetches the entire item from the parent table. If the index is configured to project all item attributes, then all of the data can be obtained from the local secondary index, and no fetching is required. <br/> *   ALL\_PROJECTED\_ATTRIBUTES - Allowed only when querying an index. Retrieves all attributes that have been projected into the index. If the index is configured to project all attributes, this return value is equivalent to specifying ALL\_ATTRIBUTES. <br/> *   COUNT - Returns the number of matching items, rather than the matching items themselves. <br/> *   SPECIFIC\_ATTRIBUTES - Returns only the attributes listed in AttributesToGet. This return value is equivalent to specifying AttributesToGet without specifying any value for Select. If you query or scan a local secondary index and request only attributes that are projected into that index, the operation will read only the index and not the table. If any of the requested attributes are not projected into the local secondary index, DynamoDB fetches each of these attributes from the parent table. This extra fetching incurs additional throughput cost and latency. If you query or scan a global secondary index, you can only request attributes that are projected into the index. Global secondary index queries cannot fetch attributes from the parent table. <br/>  If neither Select nor AttributesToGet are specified, DynamoDB defaults to ALL\_ATTRIBUTES when accessing a table, and ALL\_PROJECTED\_ATTRIBUTES when accessing an index. You cannot use both Select and AttributesToGet together in a single request, unless the value for Select is SPECIFIC\_ATTRIBUTES. (This usage is equivalent to specifying AttributesToGet without any value for Select.)  If you use the ProjectionExpression parameter, then the value for Select can only be SPECIFIC\_ATTRIBUTES. Any other value for Select will return an error.  | Optional | 
| attributes_to_get | This is a legacy parameter. Use ProjectionExpression instead. For more information, see AttributesToGet in the *Amazon DynamoDB Developer Guide*. | Optional | 
| consistent_read | &lt;p&gt;Determines the read consistency model: If set to &lt;code&gt;true&lt;/code&gt;, then the operation uses strongly consistent reads; otherwise, the operation uses eventually consistent reads.&lt;/p&gt; &lt;p&gt;Strongly consistent reads are not supported on global secondary indexes. If you query a global secondary index with &lt;code&gt;ConsistentRead&lt;/code&gt; set to &lt;code&gt;true&lt;/code&gt;, you will receive a &lt;code&gt;ValidationException&lt;/code&gt;.&lt;/p&gt; | Optional | 
| key_conditions | This is a legacy parameter. Use KeyConditionExpression instead. For more information, see KeyConditions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| query_filter | This is a legacy parameter. Use FilterExpression instead. For more information, see QueryFilter in the *Amazon DynamoDB Developer Guide*. | Optional | 
| conditional_operator | This is a legacy parameter. Use FilterExpression instead. For more information, see ConditionalOperator in the *Amazon DynamoDB Developer Guide*. | Optional | 
| scan_index_forward | &lt;p&gt;Specifies the order for index traversal: If &lt;code&gt;true&lt;/code&gt; (default), the traversal is performed in ascending order; if &lt;code&gt;false&lt;/code&gt;, the traversal is performed in descending order. &lt;/p&gt; &lt;p&gt;Items with the same partition key value are stored in sorted order by sort key. If the sort key data type is Number, the results are stored in numeric order. For type String, the results are stored in order of UTF-8 bytes. For type Binary, DynamoDB treats each byte of the binary data as unsigned.&lt;/p&gt; &lt;p&gt;If &lt;code&gt;ScanIndexForward&lt;/code&gt; is &lt;code&gt;true&lt;/code&gt;, DynamoDB returns the results in the order in which they are stored (by sort key value). This is the default behavior. If &lt;code&gt;ScanIndexForward&lt;/code&gt; is &lt;code&gt;false&lt;/code&gt;, DynamoDB reads the results in reverse order by sort key value, and then returns the results to the client.&lt;/p&gt; | Optional | 
| exclusive_start_key | The primary key of the first item that this operation will evaluate. Use the value that was returned for LastEvaluatedKey in the previous operation. The data type for ExclusiveStartKey must be String, Number, or Binary. No set data types are allowed. | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| projection_expression | A string that identifies one or more attributes to retrieve from the table. These attributes can include scalars, sets, or elements of a JSON document. The attributes in the expression must be separated by commas. If no attribute names are specified, then all attributes will be returned. If any of the requested attributes are not found, they will not appear in the result. For more information, see Accessing Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| filter_expression | A string that contains conditions that DynamoDB applies after the Query operation, but before the data is returned to you. Items that do not satisfy the FilterExpression criteria are not returned. A FilterExpression does not allow key attributes. You cannot define a filter expression based on a partition key or a sort key.  A FilterExpression is applied after the items have already been read; the process of filtering does not consume any additional read capacity units.  For more information, see Filter Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| key_condition_expression | The condition that specifies the key values for items to be retrieved by the Query action. The condition must perform an equality test on a single partition key value. The condition can optionally perform one of several comparison tests on a single sort key value. This allows Query to retrieve one item with a given partition key value and sort key value, or several items that have the same partition key value but different sort key values. The partition key equality test is required, and must be specified in the following format:  partitionKeyName *=* :partitionkeyval  If you also want to provide a condition for the sort key, it must be combined using AND with the condition for the sort key. Following is an example, using the **=** comparison operator for the sort key:  partitionKeyName = :partitionkeyval AND sortKeyName = :sortkeyval  Valid comparisons for the sort key condition are as follows:  *   sortKeyName = :sortkeyval - true if the sort key value is equal to :sortkeyval. <br/> *   sortKeyName &lt; :sortkeyval - true if the sort key value is less than :sortkeyval. <br/> *   sortKeyName &lt;= :sortkeyval - true if the sort key value is less than or equal to :sortkeyval. <br/> *   sortKeyName &gt; :sortkeyval - true if the sort key value is greater than :sortkeyval. <br/> *   sortKeyName &gt;=  :sortkeyval - true if the sort key value is greater than or equal to :sortkeyval. <br/> *   sortKeyName BETWEEN :sortkeyval1 AND :sortkeyval2 - true if the sort key value is greater than or equal to :sortkeyval1, and less than or equal to :sortkeyval2. <br/> *   begins\_with ( sortKeyName, :sortkeyval ) - true if the sort key value begins with a particular operand. (You cannot use this function with a sort key that is of type Number.) Note that the function name begins\_with is case-sensitive. <br/>  Use the ExpressionAttributeValues parameter to replace tokens such as :partitionval and :sortval with actual values at runtime. You can optionally use the ExpressionAttributeNames parameter to replace the names of the partition key and sort key with placeholder tokens. This option might be necessary if an attribute name conflicts with a DynamoDB reserved word. For example, the following KeyConditionExpression parameter causes an error because *Size* is a reserved word:  *   Size = :myval  <br/>  To work around this, define a placeholder (such a #S) to represent the attribute name *Size*. KeyConditionExpression then is as follows:  *   #S = :myval  <br/>  For a list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*. For more information on ExpressionAttributeNames and ExpressionAttributeValues, see Using Placeholders for Attribute Names and Values in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_names | One or more substitution tokens for attribute names in an expression. The following are some use cases for using ExpressionAttributeNames:  *  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/> *  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/> *  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name:  *   Percentile  <br/>  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*). To work around this, you could specify the following for ExpressionAttributeNames:  *   {"#P":"Percentile"}  <br/>  You could then use this substitution in an expression, as in this example:  *   #P = :val  <br/>   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information on expression attribute names, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_values | One or more values that can be substituted in an expression. Use the **:** (colon) character in an expression to dereference an attribute value. For example, suppose that you wanted to check whether the value of the *ProductStatus* attribute was one of the following:   Available \| Backordered \| Discontinued  You would first need to specify ExpressionAttributeValues as follows:  { ":avail":{"S":"Available"}, ":back":{"S":"Backordered"}, ":disc":{"S":"Discontinued"} }  You could then use these values in an expression, such as this:  ProductStatus IN (:avail, :back, :disc)  For more information on expression attribute values, see Specifying Conditions in the *Amazon DynamoDB Developer Guide*. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Items | unknown | An array of item attributes that match the query criteria. Each element in this array consists of an attribute name and the value for that attribute. | 
| AWS-DynamoDB.Count | unknown | The number of items in the response. If you used a QueryFilter in the request, then Count is the number of items returned after the filter was applied, and ScannedCount is the number of matching items before the filter was applied. If you did not use a filter in the request, then Count and ScannedCount are the same. | 
| AWS-DynamoDB.ScannedCount | unknown | The number of items evaluated, before any QueryFilter is applied. A high ScannedCount value with few, or no, Count results indicates an inefficient Query operation. For more information, see Count and ScannedCount in the \*Amazon DynamoDB Developer Guide\*. If you did not use a filter in the request, then ScannedCount is the same as Count. | 
| AWS-DynamoDB.LastEvaluatedKey | unknown | The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request. If LastEvaluatedKey is empty, then the "last page" of results has been processed and there is no more data to be retrieved. If LastEvaluatedKey is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when LastEvaluatedKey is empty. | 
| AWS-DynamoDB.ConsumedCapacity.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity | unknown | The capacity units consumed by the Query operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. ConsumedCapacity is only returned if the ReturnConsumedCapacity parameter was specified. For more information, see Provisioned Throughput in the \*Amazon DynamoDB Developer Guide\*. | 


### aws-dynamodb-restore-table-from-backup
***
Creates a new table from an existing backup. Any number of users can execute up to 4 concurrent restores (any type of restore) in a given account.  You can call RestoreTableFromBackup at a maximum rate of 10 times per second. You must manually set up the following on the restored table:  *  Auto scaling policies 
 *  IAM policies 
 *  Amazon CloudWatch metrics and alarms 
 *  Tags 
 *  Stream settings 
 *  Time to Live (TTL) settings 
 


#### Base Command

`aws-dynamodb-restore-table-from-backup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| target_table_name | The name of the new table to which the backup must be restored. | Optional | 
| backup_arn | The Amazon Resource Name (ARN) associated with the backup. | Optional | 
| billing_mode_override | The billing mode of the restored table. | Optional | 
| global_secondary_index_override_index_name | The name of the global secondary index. The name must be unique among all other indexes on this table. | Optional | 
| key_schema_attribute_name | The name of a key attribute. | Optional | 
| projection_non_key_attributes | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | Optional | 
| provisioned_throughput_read_capacity_units | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| provisioned_throughput_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| local_secondary_index_override_index_name | The name of the local secondary index. The name must be unique among all other indexes on this table. | Optional | 
| key_schema_key_type | The role that this key attribute will assume:  *   HASH - partition key <br/> *   RANGE - sort key <br/>   The partition key of an item is also known as its *hash attribute*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its *range attribute*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | Optional | 
| projection_projection_type | The set of attributes that are projected into the index:  *   KEYS\_ONLY - Only the index and primary keys are projected into the index. <br/> *   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> *   ALL - All of the table attributes are projected into the index. <br/>  | Optional | 
| provisioned_throughput_override_read_capacity_units | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| provisioned_throughput_override_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeName | unknown | A name for the attribute. | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeType | unknown | The data type for the attribute, where:  \*   S - the attribute is of type String <br/> \*   N - the attribute is of type Number <br/> \*   B - the attribute is of type Binary | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions | unknown | An array of AttributeDefinition objects. Each of these objects describes one attribute in the table and index key schema. Each AttributeDefinition object in this array is composed of:  \*   AttributeName - The name of the attribute. <br/> \*   AttributeType - The data type for the attribute. | 
| AWS-DynamoDB.TableDescription.TableName | unknown | The name of the table. | 
| AWS-DynamoDB.TableDescription.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.KeySchema | unknown | The primary key structure for the table. Each KeySchemaElement consists of:  \*   AttributeName - The name of the attribute. <br/> \*   KeyType - The role of the attribute: <br/>	 \+   HASH - partition key <br/>	 \+   RANGE - sort key <br/>	   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  <br/>  For more information about primary keys, see Primary Key in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.TableStatus | unknown | The current state of the table:  \*   CREATING - The table is being created. <br/> \*   UPDATING - The table is being updated. <br/> \*   DELETING - The table is being deleted. <br/> \*   ACTIVE - The table is ready for use. | 
| AWS-DynamoDB.TableDescription.CreationDateTime | unknown | The date and time when the table was created, in UNIX epoch time format. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput | unknown | The provisioned throughput settings for the table, consisting of read and write capacity units, along with data about increases and decreases. | 
| AWS-DynamoDB.TableDescription.TableSizeBytes | unknown | The total size of the specified table, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.ItemCount | unknown | The number of items in the specified table. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.TableArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the table. | 
| AWS-DynamoDB.TableDescription.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.BillingModeSummary | unknown | Contains the details for the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for the local secondary index, consisting of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes | unknown | Represents one or more local secondary indexes on the table. Each index is scoped to a given partition key value. Tables with one or more local secondary indexes are subject to an item collection size limit, where the amount of data within a given item collection cannot exceed 10 GB. Each element is composed of:  \*   IndexName - The name of the local secondary index. <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   IndexSizeBytes - Represents the total size of the index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/> \*   ItemCount - Represents the number of items in the index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexStatus | unknown | The current state of the global secondary index:  \*   CREATING - The index is being created. <br/> \*   UPDATING - The index is being updated. <br/> \*   DELETING - The index is being deleted. <br/> \*   ACTIVE - The index is ready for use. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Backfilling | unknown | Indicates whether the index is currently backfilling. \*Backfilling\* is the process of reading items from the table and determining whether they can be added to the index. \(Not all items will qualify: For example, a partition key cannot have any duplicate values.\) If an item can be added to the index, DynamoDB will do so. After all items have been processed, the backfilling operation is complete and Backfilling is false. You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false.   For indexes that were created during a CreateTable operation, the Backfilling attribute does not appear in the DescribeTable output.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index. For current minimum and maximum provisioned throughput values, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes | unknown | The global secondary indexes, if any, on the table. Each index is scoped to a given partition key value. Each element is composed of:  \*   Backfilling - If true, then the index is currently in the backfilling phase. Backfilling occurs only when a new global secondary index is added to the table. It is the process by which DynamoDB populates the new index with data from the table. \(This attribute does not appear for indexes that were created during a CreateTable operation.\)   You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false. \(This attribute does not appear for indexes that were created during a CreateTable operation.\) <br/> \*   IndexName - The name of the global secondary index. <br/> \*   IndexSizeBytes - The total size of the global secondary index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   IndexStatus - The current status of the global secondary index: <br/>	 \+   CREATING - The index is being created. <br/>	 \+   UPDATING - The index is being updated. <br/>	 \+   DELETING - The index is being deleted. <br/>	 \+   ACTIVE - The index is ready for use. 	  <br/> \*   ItemCount - The number of items in the global secondary index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   ProvisionedThroughput - The provisioned throughput settings for the global secondary index, consisting of read and write capacity units, along with data about increases and decreases.  <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.TableDescription.StreamSpecification | unknown | The current DynamoDB Streams configuration for the table. | 
| AWS-DynamoDB.TableDescription.LatestStreamLabel | unknown | A timestamp, in ISO 8601 format, for this stream. Note that LatestStreamLabel is not a unique identifier for the stream, because it is possible that a stream from another table might have the same timestamp. However, the combination of the following three elements is guaranteed to be unique:  \*  AWS customer ID <br/> \*  Table name <br/> \*   StreamLabel  | 
| AWS-DynamoDB.TableDescription.LatestStreamArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the latest stream for this table. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceBackupArn | unknown | The Amazon Resource Name \(ARN\) of the backup from which the table was restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceTableArn | unknown | The ARN of the source table of the backup that is being restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreDateTime | unknown | Point in time or source backup time. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreInProgress | unknown | Indicates if a restore is in progress or not. | 
| AWS-DynamoDB.TableDescription.RestoreSummary | unknown | Contains details for the restore. | 
| AWS-DynamoDB.TableDescription.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated. | 
| AWS-DynamoDB.TableDescription.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\). | 
| AWS-DynamoDB.TableDescription.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.TableDescription.SSEDescription | unknown | The description of the server-side encryption status on the specified table. | 
| AWS-DynamoDB.TableDescription | unknown | The description of the table created from an existing backup. | 


### aws-dynamodb-restore-table-to-point-in-time
***
Restores the specified table to the specified point in time within EarliestRestorableDateTime and LatestRestorableDateTime. You can restore your table to any point in time during the last 35 days. Any number of users can execute up to 4 concurrent restores (any type of restore) in a given account.   When you restore using point in time recovery, DynamoDB restores your table data to the state based on the selected date and time (day:hour:minute:second) to a new table.   Along with data, the following are also included on the new restored table using point in time recovery:   *  Global secondary indexes (GSIs) 
 *  Local secondary indexes (LSIs) 
 *  Provisioned read and write capacity 
 *  Encryption settings   All these settings come from the current settings of the source table at the time of restore.   
  You must manually set up the following on the restored table:  *  Auto scaling policies 
 *  IAM policies 
 *  Amazon CloudWatch metrics and alarms 
 *  Tags 
 *  Stream settings 
 *  Time to Live (TTL) settings 
 *  Point in time recovery settings 
 


#### Base Command

`aws-dynamodb-restore-table-to-point-in-time`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| source_table_name | Name of the source table that is being restored. | Optional | 
| target_table_name | The name of the new table to which it must be restored to. | Optional | 
| use_latest_restorable_time | &lt;p&gt;Restore the table to the latest possible time. &lt;code&gt;LatestRestorableDateTime&lt;/code&gt; is typically 5 minutes before the current time. &lt;/p&gt; | Optional | 
| billing_mode_override | The billing mode of the restored table. | Optional | 
| global_secondary_index_override_index_name | The name of the global secondary index. The name must be unique among all other indexes on this table. | Optional | 
| projection_non_key_attributes | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | Optional | 
| provisioned_throughput_read_capacity_units | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| provisioned_throughput_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| local_secondary_index_override_index_name | The name of the local secondary index. The name must be unique among all other indexes on this table. | Optional | 
| key_schema_attribute_name | The name of a key attribute. | Optional | 
| key_schema_key_type | The role that this key attribute will assume:  *   HASH - partition key <br/> *   RANGE - sort key <br/>   The partition key of an item is also known as its *hash attribute*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its *range attribute*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | Optional | 
| projection_projection_type | The set of attributes that are projected into the index:  *   KEYS\_ONLY - Only the index and primary keys are projected into the index. <br/> *   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> *   ALL - All of the table attributes are projected into the index. <br/>  | Optional | 
| provisioned_throughput_override_read_capacity_units | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| provisioned_throughput_override_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeName | unknown | A name for the attribute. | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeType | unknown | The data type for the attribute, where:  \*   S - the attribute is of type String <br/> \*   N - the attribute is of type Number <br/> \*   B - the attribute is of type Binary | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions | unknown | An array of AttributeDefinition objects. Each of these objects describes one attribute in the table and index key schema. Each AttributeDefinition object in this array is composed of:  \*   AttributeName - The name of the attribute. <br/> \*   AttributeType - The data type for the attribute. | 
| AWS-DynamoDB.TableDescription.TableName | unknown | The name of the table. | 
| AWS-DynamoDB.TableDescription.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.KeySchema | unknown | The primary key structure for the table. Each KeySchemaElement consists of:  \*   AttributeName - The name of the attribute. <br/> \*   KeyType - The role of the attribute: <br/>	 \+   HASH - partition key <br/>	 \+   RANGE - sort key <br/>	   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  <br/>  For more information about primary keys, see Primary Key in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.TableStatus | unknown | The current state of the table:  \*   CREATING - The table is being created. <br/> \*   UPDATING - The table is being updated. <br/> \*   DELETING - The table is being deleted. <br/> \*   ACTIVE - The table is ready for use. | 
| AWS-DynamoDB.TableDescription.CreationDateTime | unknown | The date and time when the table was created, in UNIX epoch time format. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput | unknown | The provisioned throughput settings for the table, consisting of read and write capacity units, along with data about increases and decreases. | 
| AWS-DynamoDB.TableDescription.TableSizeBytes | unknown | The total size of the specified table, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.ItemCount | unknown | The number of items in the specified table. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.TableArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the table. | 
| AWS-DynamoDB.TableDescription.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.BillingModeSummary | unknown | Contains the details for the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for the local secondary index, consisting of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes | unknown | Represents one or more local secondary indexes on the table. Each index is scoped to a given partition key value. Tables with one or more local secondary indexes are subject to an item collection size limit, where the amount of data within a given item collection cannot exceed 10 GB. Each element is composed of:  \*   IndexName - The name of the local secondary index. <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   IndexSizeBytes - Represents the total size of the index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/> \*   ItemCount - Represents the number of items in the index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexStatus | unknown | The current state of the global secondary index:  \*   CREATING - The index is being created. <br/> \*   UPDATING - The index is being updated. <br/> \*   DELETING - The index is being deleted. <br/> \*   ACTIVE - The index is ready for use. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Backfilling | unknown | Indicates whether the index is currently backfilling. \*Backfilling\* is the process of reading items from the table and determining whether they can be added to the index. \(Not all items will qualify: For example, a partition key cannot have any duplicate values.\) If an item can be added to the index, DynamoDB will do so. After all items have been processed, the backfilling operation is complete and Backfilling is false. You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false.   For indexes that were created during a CreateTable operation, the Backfilling attribute does not appear in the DescribeTable output.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index. For current minimum and maximum provisioned throughput values, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes | unknown | The global secondary indexes, if any, on the table. Each index is scoped to a given partition key value. Each element is composed of:  \*   Backfilling - If true, then the index is currently in the backfilling phase. Backfilling occurs only when a new global secondary index is added to the table. It is the process by which DynamoDB populates the new index with data from the table. \(This attribute does not appear for indexes that were created during a CreateTable operation.\)   You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false. \(This attribute does not appear for indexes that were created during a CreateTable operation.\) <br/> \*   IndexName - The name of the global secondary index. <br/> \*   IndexSizeBytes - The total size of the global secondary index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   IndexStatus - The current status of the global secondary index: <br/>	 \+   CREATING - The index is being created. <br/>	 \+   UPDATING - The index is being updated. <br/>	 \+   DELETING - The index is being deleted. <br/>	 \+   ACTIVE - The index is ready for use. 	  <br/> \*   ItemCount - The number of items in the global secondary index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   ProvisionedThroughput - The provisioned throughput settings for the global secondary index, consisting of read and write capacity units, along with data about increases and decreases.  <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.TableDescription.StreamSpecification | unknown | The current DynamoDB Streams configuration for the table. | 
| AWS-DynamoDB.TableDescription.LatestStreamLabel | unknown | A timestamp, in ISO 8601 format, for this stream. Note that LatestStreamLabel is not a unique identifier for the stream, because it is possible that a stream from another table might have the same timestamp. However, the combination of the following three elements is guaranteed to be unique:  \*  AWS customer ID <br/> \*  Table name <br/> \*   StreamLabel  | 
| AWS-DynamoDB.TableDescription.LatestStreamArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the latest stream for this table. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceBackupArn | unknown | The Amazon Resource Name \(ARN\) of the backup from which the table was restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceTableArn | unknown | The ARN of the source table of the backup that is being restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreDateTime | unknown | Point in time or source backup time. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreInProgress | unknown | Indicates if a restore is in progress or not. | 
| AWS-DynamoDB.TableDescription.RestoreSummary | unknown | Contains details for the restore. | 
| AWS-DynamoDB.TableDescription.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated.   | 
| AWS-DynamoDB.TableDescription.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\).   | 
| AWS-DynamoDB.TableDescription.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.TableDescription.SSEDescription | unknown | The description of the server-side encryption status on the specified table. | 
| AWS-DynamoDB.TableDescription | unknown | Represents the properties of a table. | 


### aws-dynamodb-scan
***
The Scan operation returns one or more items and item attributes by accessing every item in a table or a secondary index. To have DynamoDB return fewer items, you can provide a FilterExpression operation. If the total number of scanned items exceeds the maximum dataset size limit of 1 MB, the scan stops and results are returned to the user as a LastEvaluatedKey value to continue the scan in a subsequent operation. The results also include the number of items exceeding the limit. A scan can result in no table data meeting the filter criteria.  A single Scan operation reads up to the maximum number of items set (if using the Limit parameter) or a maximum of 1 MB of data and then apply any filtering to the results using FilterExpression. If LastEvaluatedKey is present in the response, you need to paginate the result set. For more information, see Paginating the Results in the *Amazon DynamoDB Developer Guide*.   Scan operations proceed sequentially; however, for faster performance on a large table or secondary index, applications can request a parallel Scan operation by providing the Segment and TotalSegments parameters. For more information, see Parallel Scan in the *Amazon DynamoDB Developer Guide*.  Scan uses eventually consistent reads when accessing the data in a table; therefore, the result set might not include the changes to data in the table immediately before the operation began. If you need a consistent copy of the data, as of the time that the Scan begins, you can set the ConsistentRead parameter to true.


#### Base Command

`aws-dynamodb-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table containing the requested items; or, if you provide IndexName, the name of the table to which that index belongs. | Optional | 
| index_name | The name of a secondary index to scan. This index can be any local secondary index or global secondary index. Note that if you use the IndexName parameter, you must also provide TableName. | Optional | 
| attributes_to_get | This is a legacy parameter. Use ProjectionExpression instead. For more information, see AttributesToGet in the *Amazon DynamoDB Developer Guide*. | Optional | 
| select | The attributes to be returned in the result. You can retrieve all item attributes, specific item attributes, the count of matching items, or in the case of an index, some or all of the attributes projected into the index.  *   ALL\_ATTRIBUTES - Returns all of the item attributes from the specified table or index. If you query a local secondary index, then for each matching item in the index, DynamoDB fetches the entire item from the parent table. If the index is configured to project all item attributes, then all of the data can be obtained from the local secondary index, and no fetching is required. <br/> *   ALL\_PROJECTED\_ATTRIBUTES - Allowed only when querying an index. Retrieves all attributes that have been projected into the index. If the index is configured to project all attributes, this return value is equivalent to specifying ALL\_ATTRIBUTES. <br/> *   COUNT - Returns the number of matching items, rather than the matching items themselves. <br/> *   SPECIFIC\_ATTRIBUTES - Returns only the attributes listed in AttributesToGet. This return value is equivalent to specifying AttributesToGet without specifying any value for Select. If you query or scan a local secondary index and request only attributes that are projected into that index, the operation reads only the index and not the table. If any of the requested attributes are not projected into the local secondary index, DynamoDB fetches each of these attributes from the parent table. This extra fetching incurs additional throughput cost and latency. If you query or scan a global secondary index, you can only request attributes that are projected into the index. Global secondary index queries cannot fetch attributes from the parent table. <br/>  If neither Select nor AttributesToGet are specified, DynamoDB defaults to ALL\_ATTRIBUTES when accessing a table, and ALL\_PROJECTED\_ATTRIBUTES when accessing an index. You cannot use both Select and AttributesToGet together in a single request, unless the value for Select is SPECIFIC\_ATTRIBUTES. (This usage is equivalent to specifying AttributesToGet without any value for Select.)  If you use the ProjectionExpression parameter, then the value for Select can only be SPECIFIC\_ATTRIBUTES. Any other value for Select will return an error.  | Optional | 
| scan_filter | This is a legacy parameter. Use FilterExpression instead. For more information, see ScanFilter in the *Amazon DynamoDB Developer Guide*. | Optional | 
| conditional_operator | This is a legacy parameter. Use FilterExpression instead. For more information, see ConditionalOperator in the *Amazon DynamoDB Developer Guide*. | Optional | 
| exclusive_start_key | The primary key of the first item that this operation will evaluate. Use the value that was returned for LastEvaluatedKey in the previous operation. The data type for ExclusiveStartKey must be String, Number or Binary. No set data types are allowed. In a parallel scan, a Scan request that includes ExclusiveStartKey must specify the same segment whose previous Scan returned the corresponding value of LastEvaluatedKey. | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| projection_expression | A string that identifies one or more attributes to retrieve from the specified table or index. These attributes can include scalars, sets, or elements of a JSON document. The attributes in the expression must be separated by commas. If no attribute names are specified, then all attributes will be returned. If any of the requested attributes are not found, they will not appear in the result. For more information, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| filter_expression | A string that contains conditions that DynamoDB applies after the Scan operation, but before the data is returned to you. Items that do not satisfy the FilterExpression criteria are not returned.  A FilterExpression is applied after the items have already been read; the process of filtering does not consume any additional read capacity units.  For more information, see Filter Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_names | One or more substitution tokens for attribute names in an expression. The following are some use cases for using ExpressionAttributeNames:  *  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/> *  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/> *  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name:  *   Percentile  <br/>  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*). To work around this, you could specify the following for ExpressionAttributeNames:  *   {"#P":"Percentile"}  <br/>  You could then use this substitution in an expression, as in this example:  *   #P = :val  <br/>   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information on expression attribute names, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_values | One or more values that can be substituted in an expression. Use the **:** (colon) character in an expression to dereference an attribute value. For example, suppose that you wanted to check whether the value of the ProductStatus attribute was one of the following:   Available \| Backordered \| Discontinued  You would first need to specify ExpressionAttributeValues as follows:  { ":avail":{"S":"Available"}, ":back":{"S":"Backordered"}, ":disc":{"S":"Discontinued"} }  You could then use these values in an expression, such as this:  ProductStatus IN (:avail, :back, :disc)  For more information on expression attribute values, see Condition Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| consistent_read | &lt;p&gt;A Boolean value that determines the read consistency model during the scan:&lt;/p&gt; &lt;ul&gt; &lt;li&gt; &lt;p&gt;If &lt;code&gt;ConsistentRead&lt;/code&gt; is &lt;code&gt;false&lt;/code&gt;, then the data returned from &lt;code&gt;Scan&lt;/code&gt; might not contain the results from other recently completed write operations (&lt;code&gt;PutItem&lt;/code&gt;, &lt;code&gt;UpdateItem&lt;/code&gt;, or &lt;code&gt;DeleteItem&lt;/code&gt;).&lt;/p&gt; &lt;/li&gt; &lt;li&gt; &lt;p&gt;If &lt;code&gt;ConsistentRead&lt;/code&gt; is &lt;code&gt;true&lt;/code&gt;, then all of the write operations that completed before the &lt;code&gt;Scan&lt;/code&gt; began are guaranteed to be contained in the &lt;code&gt;Scan&lt;/code&gt; response.&lt;/p&gt; &lt;/li&gt; &lt;/ul&gt; &lt;p&gt;The default setting for &lt;code&gt;ConsistentRead&lt;/code&gt; is &lt;code&gt;false&lt;/code&gt;.&lt;/p&gt; &lt;p&gt;The &lt;code&gt;ConsistentRead&lt;/code&gt; parameter is not supported on global secondary indexes. If you scan a global secondary index with &lt;code&gt;ConsistentRead&lt;/code&gt; set to true, you will receive a &lt;code&gt;ValidationException&lt;/code&gt;.&lt;/p&gt; | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Items | unknown | An array of item attributes that match the scan criteria. Each element in this array consists of an attribute name and the value for that attribute. | 
| AWS-DynamoDB.Count | unknown | The number of items in the response. If you set ScanFilter in the request, then Count is the number of items returned after the filter was applied, and ScannedCount is the number of matching items before the filter was applied. If you did not use a filter in the request, then Count is the same as ScannedCount. | 
| AWS-DynamoDB.ScannedCount | unknown | The number of items evaluated, before any ScanFilter is applied. A high ScannedCount value with few, or no, Count results indicates an inefficient Scan operation. For more information, see Count and ScannedCount in the \*Amazon DynamoDB Developer Guide\*. If you did not use a filter in the request, then ScannedCount is the same as Count. | 
| AWS-DynamoDB.LastEvaluatedKey | unknown | The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request. If LastEvaluatedKey is empty, then the "last page" of results has been processed and there is no more data to be retrieved. If LastEvaluatedKey is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when LastEvaluatedKey is empty. | 
| AWS-DynamoDB.ConsumedCapacity.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity | unknown | The capacity units consumed by the Scan operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. ConsumedCapacity is only returned if the ReturnConsumedCapacity parameter was specified. For more information, see Provisioned Throughput in the \*Amazon DynamoDB Developer Guide\*. | 


### aws-dynamodb-tag-resource
***
Associate a set of tags with an Amazon DynamoDB resource. You can then activate these user-defined tags so that they appear on the Billing and Cost Management console for cost allocation tracking. You can call TagResource up to five times per second, per account.  For an overview on tagging DynamoDB resources, see Tagging for DynamoDB in the *Amazon DynamoDB Developer Guide*.


#### Base Command

`aws-dynamodb-tag-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | Identifies the Amazon DynamoDB resource to which tags should be added. This value is an Amazon Resource Name (ARN). | Optional | 
| tag_key | The Tags key identifier. | Optional | 
| tag_value | The Tags value identifier. | Optional | 
| tags | List of Tags separated by Key Value. For example: "key=key1,value=value1;key=key2,value=value2" | Optional | 


#### Context Output

There is no context output for this command.


### aws-dynamodb-transact-get-items
***
 TransactGetItems is a synchronous operation that atomically retrieves multiple items from one or more tables (but not from indexes) in a single account and Region. A TransactGetItems call can contain up to 25 TransactGetItem objects, each of which contains a Get structure that specifies an item to retrieve from a table in the account and Region. A call to TransactGetItems cannot retrieve items from tables in more than one AWS account or Region. The aggregate size of the items in the transaction cannot exceed 4 MB. DynamoDB rejects the entire TransactGetItems request if any of the following is true:  *  A conflicting operation is in the process of updating an item to be read. 
 *  There is insufficient provisioned capacity for the transaction to be completed. 
 *  There is a user error, such as an invalid data format. 
 *  The aggregate size of the items in the transaction cannot exceed 4 MB. 
 


#### Base Command

`aws-dynamodb-transact-get-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| get_key | A map of attribute names to AttributeValue objects that specifies the primary key of the item to retrieve. | Optional | 
| get_table_name | The name of the table from which to retrieve the specified item. | Optional | 
| get_projection_expression | A string that identifies one or more attributes of the specified item to retrieve from the table. The attributes in the expression must be separated by commas. If no attribute names are specified, then all attributes of the specified item are returned. If any of the requested attributes are not found, they do not appear in the result. | Optional | 
| get_expression_attribute_names | One or more substitution tokens for attribute names in the ProjectionExpression parameter. | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.docs | unknown | If the \*ReturnConsumedCapacity\* value was TOTAL, this is an array of ConsumedCapacity objects, one for each table addressed by TransactGetItem objects in the \*TransactItems\* parameter. These ConsumedCapacity objects report the read-capacity units consumed by the TransactGetItems call in that table. | 
| AWS-DynamoDB.Responses.Item | unknown | Map of attribute data consisting of the data type and attribute value. | 
| AWS-DynamoDB.Responses | unknown | An ordered array of up to 25 ItemResponse objects, each of which corresponds to the TransactGetItem object in the same position in the \*TransactItems\* array. Each ItemResponse object contains a Map of the name-value pairs that are the projected attributes of the requested item. If a requested item could not be retrieved, the corresponding ItemResponse object is Null, or if the requested item has no projected attributes, the corresponding ItemResponse object is an empty Map.  | 


### aws-dynamodb-transact-write-items
***
 TransactWriteItems is a synchronous write operation that groups up to 25 action requests. These actions can target items in different tables, but not in different AWS accounts or Regions, and no two actions can target the same item. For example, you cannot both ConditionCheck and Update the same item. The aggregate size of the items in the transaction cannot exceed 4 MB. The actions are completed atomically so that either all of them succeed, or all of them fail. They are defined by the following objects:  *   Put — Initiates a PutItem operation to write a new item. This structure specifies the primary key of the item to be written, the name of the table to write it in, an optional condition expression that must be satisfied for the write to succeed, a list of the item's attributes, and a field indicating whether to retrieve the item's attributes if the condition is not met. 
 *   Update — Initiates an UpdateItem operation to update an existing item. This structure specifies the primary key of the item to be updated, the name of the table where it resides, an optional condition expression that must be satisfied for the update to succeed, an expression that defines one or more attributes to be updated, and a field indicating whether to retrieve the item's attributes if the condition is not met. 
 *   Delete — Initiates a DeleteItem operation to delete an existing item. This structure specifies the primary key of the item to be deleted, the name of the table where it resides, an optional condition expression that must be satisfied for the deletion to succeed, and a field indicating whether to retrieve the item's attributes if the condition is not met. 
 *   ConditionCheck — Applies a condition to an item that is not being modified by the transaction. This structure specifies the primary key of the item to be checked, the name of the table where it resides, a condition expression that must be satisfied for the transaction to succeed, and a field indicating whether to retrieve the item's attributes if the condition is not met. 
  DynamoDB rejects the entire TransactWriteItems request if any of the following is true:  *  A condition in one of the condition expressions is not met. 
 *  An ongoing operation is in the process of updating the same item. 
 *  There is insufficient provisioned capacity for the transaction to be completed. 
 *  An item size becomes too large (bigger than 400 KB), a local secondary index (LSI) becomes too large, or a similar validation error occurs because of changes made by the transaction. 
 *  The aggregate size of the items in the transaction exceeds 4 MB. 
 *  There is a user error, such as an invalid data format. 
 


#### Base Command

`aws-dynamodb-transact-write-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| condition_check_key | The primary key of the item to be checked. Each element consists of an attribute name and a value for that attribute. | Optional | 
| condition_check_table_name | Name of the table for the check item request. | Optional | 
| condition_check_condition_expression | A condition that must be satisfied in order for a conditional update to succeed. | Optional | 
| condition_check_expression_attribute_names | One or more substitution tokens for attribute names in an expression. | Optional | 
| condition_check_expression_attribute_values | One or more values that can be substituted in an expression. | Optional | 
| condition_check_return_values_on_condition_check_failure | Use ReturnValuesOnConditionCheckFailure to get the item attributes if the ConditionCheck condition fails. For ReturnValuesOnConditionCheckFailure, the valid values are: NONE and ALL\_OLD. | Optional | 
| put_item | A map of attribute name to attribute values, representing the primary key of the item to be written by PutItem. All of the table's primary key attributes must be specified, and their data types must match those of the table's key schema. If any attributes are present in the item that are part of an index key schema for the table, their types must match the index key schema.  | Optional | 
| put_table_name | Name of the table in which to write the item. | Optional | 
| put_condition_expression | A condition that must be satisfied in order for a conditional update to succeed. | Optional | 
| put_expression_attribute_names | One or more substitution tokens for attribute names in an expression. | Optional | 
| put_expression_attribute_values | One or more values that can be substituted in an expression. | Optional | 
| put_return_values_on_condition_check_failure | Use ReturnValuesOnConditionCheckFailure to get the item attributes if the Put condition fails. For ReturnValuesOnConditionCheckFailure, the valid values are: NONE and ALL\_OLD. | Optional | 
| delete_key | The primary key of the item to be deleted. Each element consists of an attribute name and a value for that attribute. | Optional | 
| delete_table_name | Name of the table in which the item to be deleted resides. | Optional | 
| delete_condition_expression | A condition that must be satisfied in order for a conditional delete to succeed. | Optional | 
| delete_expression_attribute_names | One or more substitution tokens for attribute names in an expression. | Optional | 
| delete_expression_attribute_values | One or more values that can be substituted in an expression. | Optional | 
| delete_return_values_on_condition_check_failure | Use ReturnValuesOnConditionCheckFailure to get the item attributes if the Delete condition fails. For ReturnValuesOnConditionCheckFailure, the valid values are: NONE and ALL\_OLD. | Optional | 
| update_key | The primary key of the item to be updated. Each element consists of an attribute name and a value for that attribute. | Optional | 
| update_update_expression | An expression that defines one or more attributes to be updated, the action to be performed on them, and new value(s) for them. | Optional | 
| update_table_name | Name of the table for the UpdateItem request. | Optional | 
| update_condition_expression | A condition that must be satisfied in order for a conditional update to succeed. | Optional | 
| update_expression_attribute_names | One or more substitution tokens for attribute names in an expression. | Optional | 
| update_expression_attribute_values | One or more values that can be substituted in an expression. | Optional | 
| update_return_values_on_condition_check_failure | Use ReturnValuesOnConditionCheckFailure to get the item attributes if the Update condition fails. For ReturnValuesOnConditionCheckFailure, the valid values are: NONE, ALL\_OLD, UPDATED\_OLD, ALL\_NEW, UPDATED\_NEW. | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| return_item_collection_metrics | Determines whether item collection metrics are returned. If set to SIZE, the response includes statistics about item collections (if any), that were modified during the operation and are returned in the response. If set to NONE (the default), no statistics are returned.  | Optional | 
| client_request_token | Providing a ClientRequestToken makes the call to TransactWriteItems idempotent, meaning that multiple identical calls have the same effect as one single call. Although multiple identical calls using the same client request token produce the same result on the server (no side effects), the responses to the calls might not be the same. If the ReturnConsumedCapacity&gt; parameter is set, then the initial TransactWriteItems call returns the amount of write capacity units consumed in making the changes. Subsequent TransactWriteItems calls with the same client token return the number of read capacity units consumed in reading the item. A client request token is valid for 10 minutes after the first request that uses it is completed. After 10 minutes, any request with the same client token is treated as a new request. Do not resubmit the same request with the same client token for more than 10 minutes, or the result might not be idempotent. If you submit a request with the same client token but a change in other parameters within the 10-minute idempotency window, DynamoDB returns an IdempotentParameterMismatch exception. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.docs | unknown | The capacity units consumed by the entire TransactWriteItems operation. The values of the list are ordered according to the ordering of the TransactItems request parameter.  | 
| AWS-DynamoDB.ItemCollectionMetrics | unknown | A list of tables that were processed by TransactWriteItems and, for each table, information about any item collections that were affected by individual UpdateItem, PutItem, or DeleteItem operations.  | 


### aws-dynamodb-untag-resource
***
Removes the association of tags from an Amazon DynamoDB resource. You can call UntagResource up to five times per second, per account.  For an overview on tagging DynamoDB resources, see Tagging for DynamoDB in the *Amazon DynamoDB Developer Guide*.


#### Base Command

`aws-dynamodb-untag-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| resource_arn | The DynamoDB resource that the tags will be removed from. This value is an Amazon Resource Name (ARN). | Optional | 
| tag_keys | A list of tag keys. Existing tags of the resource whose keys are members of this list will be removed from the DynamoDB resource. | Optional | 


#### Context Output

There is no context output for this command.


### aws-dynamodb-update-continuous-backups
***
 UpdateContinuousBackups enables or disables point in time recovery for the specified table. A successful UpdateContinuousBackups call returns the current ContinuousBackupsDescription. Continuous backups are ENABLED on all tables at table creation. If point in time recovery is enabled, PointInTimeRecoveryStatus will be set to ENABLED.  Once continuous backups and point in time recovery are enabled, you can restore to any point in time within EarliestRestorableDateTime and LatestRestorableDateTime.   LatestRestorableDateTime is typically 5 minutes before the current time. You can restore your table to any point in time during the last 35 days. 


#### Base Command

`aws-dynamodb-update-continuous-backups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table. | Optional | 
| point_in_time_recovery_specification_point_in_time_recovery_enabled | &lt;p&gt;Indicates whether point in time recovery is enabled (true) or disabled (false) on the table.&lt;/p&gt; | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.ContinuousBackupsDescription.ContinuousBackupsStatus | unknown |  ContinuousBackupsStatus can be one of the following states: ENABLED, DISABLED | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus | unknown | The current state of point in time recovery:  \*   ENABLING - Point in time recovery is being enabled. <br/> \*   ENABLED - Point in time recovery is enabled. <br/> \*   DISABLED - Point in time recovery is disabled. | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription.EarliestRestorableDateTime | unknown | Specifies the earliest point in time you can restore your table to. You can restore your table to any point in time during the last 35 days.  | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription.LatestRestorableDateTime | unknown |  LatestRestorableDateTime is typically 5 minutes before the current time.  | 
| AWS-DynamoDB.ContinuousBackupsDescription.PointInTimeRecoveryDescription | unknown | The description of the point in time recovery settings applied to the table. | 
| AWS-DynamoDB.ContinuousBackupsDescription | unknown | Represents the continuous backups and point in time recovery settings on the table. | 


### aws-dynamodb-update-global-table
***
Adds or removes replicas in the specified global table. The global table must already exist to be able to use this operation. Any replica to be added must be empty, have the same name as the global table, have the same key schema, have DynamoDB Streams enabled, and have the same provisioned and maximum write capacity units.  Although you can use UpdateGlobalTable to add replicas and remove replicas in a single request, for simplicity we recommend that you issue separate requests for adding or removing replicas.   If global secondary indexes are specified, then the following conditions must also be met:   *   The global secondary indexes must have the same name.  
 *   The global secondary indexes must have the same hash key and sort key (if present).  
 *   The global secondary indexes must have the same provisioned and maximum write capacity units.  
 


#### Base Command

`aws-dynamodb-update-global-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| global_table_name | The global table name. | Optional | 
| create_region_name | The Region of the replica to be added. | Optional | 
| delete_region_name | The Region of the replica to be removed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.GlobalTableDescription.ReplicationGroup.RegionName | unknown | The name of the Region. | 
| AWS-DynamoDB.GlobalTableDescription.ReplicationGroup | unknown | The Regions where the global table has replicas. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableArn | unknown | The unique identifier of the global table. | 
| AWS-DynamoDB.GlobalTableDescription.CreationDateTime | unknown | The creation time of the global table. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableStatus | unknown | The current state of the global table:  \*   CREATING - The global table is being created. <br/> \*   UPDATING - The global table is being updated. <br/> \*   DELETING - The global table is being deleted. <br/> \*   ACTIVE - The global table is ready for use. | 
| AWS-DynamoDB.GlobalTableDescription.GlobalTableName | unknown | The global table name. | 
| AWS-DynamoDB.GlobalTableDescription | unknown | Contains the details of the global table. | 


### aws-dynamodb-update-global-table-settings
***
Updates settings for a global table.


#### Base Command

`aws-dynamodb-update-global-table-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| global_table_name | The name of the global table | Optional | 
| global_table_billing_mode | The billing mode of the global table. If GlobalTableBillingMode is not specified, the global table defaults to PROVISIONED capacity billing mode.  *   PROVISIONED - We recommend using PROVISIONED for predictable workloads. PROVISIONED sets the billing mode to Provisioned Mode. <br/> *   PAY\_PER\_REQUEST - We recommend using PAY\_PER\_REQUEST for unpredictable workloads. PAY\_PER\_REQUEST sets the billing mode to On-Demand Mode.  <br/>  | Optional | 
| global_table_provisioned_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException.  | Optional | 
| global_table_provisioned_write_capacity_auto_scaling_settings_update_minimum_units | The minimum capacity units that a global table or global secondary index should be scaled down to. | Optional | 
| global_table_provisioned_write_capacity_auto_scaling_settings_update_maximum_units | The maximum capacity units that a global table or global secondary index should be scaled up to. | Optional | 
| global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled | &lt;p&gt;Disabled auto scaling for this global table or global secondary index.&lt;/p&gt; | Optional | 
| global_table_provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn | Role ARN used for configuring auto scaling policy. | Optional | 
| index_name | The name of the global secondary index. The name must be unique among all other indexes on this table. | Optional | 
| provisioned_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException.  | Optional | 
| provisioned_write_capacity_auto_scaling_settings_update_minimum_units | The minimum capacity units that a global table or global secondary index should be scaled down to. | Optional | 
| provisioned_write_capacity_auto_scaling_settings_update_maximum_units | The maximum capacity units that a global table or global secondary index should be scaled up to. | Optional | 
| provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_disabled | &lt;p&gt;Disabled auto scaling for this global table or global secondary index.&lt;/p&gt; | Optional | 
| provisioned_write_capacity_auto_scaling_settings_update_auto_scaling_role_arn | Role ARN used for configuring auto scaling policy. | Optional | 
| scaling_policy_update_policy_name | The name of the scaling policy. | Optional | 
| target_tracking_scaling_policy_configuration_disable_scale_in | &lt;p&gt;Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false.&lt;/p&gt; | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.GlobalTableName | unknown | The name of the global table. | 
| AWS-DynamoDB.ReplicaSettings.RegionName | unknown | The Region name of the replica. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaStatus | unknown | The current state of the Region:  \*   CREATING - The Region is being created. <br/> \*   UPDATING - The Region is being updated. <br/> \*   DELETING - The Region is being deleted. <br/> \*   ACTIVE - The Region is ready for use. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaBillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaBillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaBillingModeSummary | unknown | The read/write capacity mode of the replica. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedReadCapacityAutoScalingSettings | unknown | Auto scaling settings for a global table replica's read capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaProvisionedWriteCapacityAutoScalingSettings | unknown | Auto scaling settings for a global table replica's write capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.IndexName | unknown | The name of the global secondary index. The name must be unique among all other indexes on this table. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.IndexStatus | unknown |  The current status of the global secondary index:  \*   CREATING - The global secondary index is being created. <br/> \*   UPDATING - The global secondary index is being updated. <br/> \*   DELETING - The global secondary index is being deleted. <br/> \*   ACTIVE - The global secondary index is ready for use. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedReadCapacityAutoScalingSettings | unknown | Auto scaling settings for a global secondary index replica's read capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.MinimumUnits | unknown | The minimum capacity units that a global table or global secondary index should be scaled down to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.MaximumUnits | unknown | The maximum capacity units that a global table or global secondary index should be scaled up to. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.AutoScalingDisabled | unknown | Disabled auto scaling for this global table or global secondary index. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.AutoScalingRoleArn | unknown | Role ARN used for configuring the auto scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.PolicyName | unknown | The name of the scaling policy. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.DisableScaleIn | unknown | Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. The default value is false. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleInCooldown | unknown | The amount of time, in seconds, after a scale in activity completes before another scale in activity can start. The cooldown period is used to block subsequent scale in requests until it has expired. You should scale in conservatively to protect your application's availability. However, if another alarm triggers a scale out policy during the cooldown period after a scale-in, application auto scaling scales out your scalable target immediately.  | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.ScaleOutCooldown | unknown | The amount of time, in seconds, after a scale out activity completes before another scale out activity can start. While the cooldown period is in effect, the capacity that has been added by the previous scale out event that initiated the cooldown is calculated as part of the desired capacity for the next scale out. You should continuously \(but not excessively\) scale out. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration.TargetValue | unknown | The target value for the metric. The range is 8.515920e-109 to 1.174271e\+108 \(Base 10\) or 2e-360 to 2e360 \(Base 2\). | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies.TargetTrackingScalingPolicyConfiguration | unknown | Represents a target tracking scaling policy configuration. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings.ScalingPolicies | unknown | Information about the scaling policies. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings.ProvisionedWriteCapacityAutoScalingSettings | unknown | Auto scaling settings for a global secondary index replica's write capacity units. | 
| AWS-DynamoDB.ReplicaSettings.ReplicaGlobalSecondaryIndexSettings | unknown | Replica global secondary index settings for the global table. | 
| AWS-DynamoDB.ReplicaSettings | unknown | The Region-specific settings for the global table. | 


### aws-dynamodb-update-item
***
Edits an existing item's attributes, or adds a new item to the table if it does not already exist. You can put, delete, or add attribute values. You can also perform a conditional update on an existing item (insert a new attribute name-value pair if it doesn't exist, or replace an existing name-value pair if it has certain expected attribute values). You can also return the item's attribute values in the same UpdateItem operation using the ReturnValues parameter.


#### Base Command

`aws-dynamodb-update-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table containing the item to update. | Optional | 
| key | The primary key of the item to be updated. Each element consists of an attribute name and a value for that attribute. For the primary key, you must provide all of the attributes. For example, with a simple primary key, you only need to provide a value for the partition key. For a composite primary key, you must provide values for both the partition key and the sort key. | Optional | 
| attribute_updates | This is a legacy parameter. Use UpdateExpression instead. For more information, see AttributeUpdates in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expected | This is a legacy parameter. Use ConditionExpression instead. For more information, see Expected in the *Amazon DynamoDB Developer Guide*. | Optional | 
| conditional_operator | This is a legacy parameter. Use ConditionExpression instead. For more information, see ConditionalOperator in the *Amazon DynamoDB Developer Guide*. | Optional | 
| return_values | Use ReturnValues if you want to get the item attributes as they appear before or after they are updated. For UpdateItem, the valid values are:  *   NONE - If ReturnValues is not specified, or if its value is NONE, then nothing is returned. (This setting is the default for ReturnValues.) <br/> *   ALL\_OLD - Returns all of the attributes of the item, as they appeared before the UpdateItem operation. <br/> *   UPDATED\_OLD - Returns only the updated attributes, as they appeared before the UpdateItem operation. <br/> *   ALL\_NEW - Returns all of the attributes of the item, as they appear after the UpdateItem operation. <br/> *   UPDATED\_NEW - Returns only the updated attributes, as they appear after the UpdateItem operation. <br/>  There is no additional cost associated with requesting a return value aside from the small network and processing overhead of receiving a larger response. No read capacity units are consumed. The values returned are strongly consistent. | Optional | 
| return_consumed_capacity | A value of TOTAL causes consumed capacity information to be returned, and a value of NONE prevents that information from being returned. No other value is valid. | Optional | 
| return_item_collection_metrics | Determines whether item collection metrics are returned. If set to SIZE, the response includes statistics about item collections, if any, that were modified during the operation are returned in the response. If set to NONE (the default), no statistics are returned. | Optional | 
| update_expression | An expression that defines one or more attributes to be updated, the action to be performed on them, and new values for them. The following action values are available for UpdateExpression.  *   SET - Adds one or more attributes and values to an item. If any of these attributes already exist, they are replaced by the new values. You can also use SET to add or subtract from an attribute that is of type Number. For example: SET myNum = myNum + :val   SET supports the following functions: <br/>	 +   if\_not\_exists (path, operand) - if the item does not contain an attribute at the specified path, then if\_not\_exists evaluates to operand; otherwise, it evaluates to path. You can use this function to avoid overwriting an attribute that may already be present in the item. <br/>	 +   list\_append (operand, operand) - evaluates to a list with a new element added to it. You can append the new element to the start or the end of the list by reversing the order of the operands. <br/>	  These function names are case-sensitive. <br/> *   REMOVE - Removes one or more attributes from an item. <br/> *   ADD - Adds the specified value to the item, if the attribute does not already exist. If the attribute does exist, then the behavior of ADD depends on the data type of the attribute: <br/>	 +  If the existing attribute is a number, and if Value is also a number, then Value is mathematically added to the existing attribute. If Value is a negative number, then it is subtracted from the existing attribute.  If you use ADD to increment or decrement a number value for an item that doesn't exist before the update, DynamoDB uses 0 as the initial value. Similarly, if you use ADD for an existing item to increment or decrement an attribute value that doesn't exist before the update, DynamoDB uses 0 as the initial value. For example, suppose that the item you want to update doesn't have an attribute named itemcount, but you decide to ADD the number 3 to this attribute anyway. DynamoDB will create the itemcount attribute, set its initial value to 0, and finally add 3 to it. The result will be a new itemcount attribute in the item, with a value of 3.  <br/>	 +  If the existing data type is a set and if Value is also a set, then Value is added to the existing set. For example, if the attribute value is the set [1,2], and the ADD action specified [3], then the final attribute value is [1,2,3]. An error occurs if an ADD action is specified for a set attribute and the attribute type specified does not match the existing set type.  Both sets must have the same primitive data type. For example, if the existing data type is a set of strings, the Value must also be a set of strings. <br/>	   The ADD action only supports Number and set data types. In addition, ADD can only be used on top-level attributes, not nested attributes.  <br/> *   DELETE - Deletes an element from a set. If a set of values is specified, then those values are subtracted from the old set. For example, if the attribute value was the set [a,b,c] and the DELETE action specifies [a,c], then the final attribute value is [b]. Specifying an empty set is an error.  The DELETE action only supports set data types. In addition, DELETE can only be used on top-level attributes, not nested attributes.  <br/>  You can have many actions in a single expression, such as the following: SET a=:value1, b=:value2 DELETE :value3, :value4, :value5  For more information on update expressions, see Modifying Items and Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| condition_expression | A condition that must be satisfied in order for a conditional update to succeed. An expression can contain any of the following:  *  Functions: attribute\_exists \| attribute\_not\_exists \| attribute\_type \| contains \| begins\_with \| size  These function names are case-sensitive. <br/> *  Comparison operators: = \| &lt;&gt; \| &lt; \| &gt; \| &lt;= \| &gt;= \| BETWEEN \| IN   <br/> *   Logical operators: AND \| OR \| NOT  <br/>  For more information about condition expressions, see Specifying Conditions in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_names | One or more substitution tokens for attribute names in an expression. The following are some use cases for using ExpressionAttributeNames:  *  To access an attribute whose name conflicts with a DynamoDB reserved word. <br/> *  To create a placeholder for repeating occurrences of an attribute name in an expression. <br/> *  To prevent special characters in an attribute name from being misinterpreted in an expression. <br/>  Use the **#** character in an expression to dereference an attribute name. For example, consider the following attribute name:  *   Percentile  <br/>  The name of this attribute conflicts with a reserved word, so it cannot be used directly in an expression. (For the complete list of reserved words, see Reserved Words in the *Amazon DynamoDB Developer Guide*.) To work around this, you could specify the following for ExpressionAttributeNames:  *   {"#P":"Percentile"}  <br/>  You could then use this substitution in an expression, as in this example:  *   #P = :val  <br/>   Tokens that begin with the **:** character are *expression attribute values*, which are placeholders for the actual value at runtime.  For more information about expression attribute names, see Specifying Item Attributes in the *Amazon DynamoDB Developer Guide*. | Optional | 
| expression_attribute_values | One or more values that can be substituted in an expression. Use the **:** (colon) character in an expression to dereference an attribute value. For example, suppose that you wanted to check whether the value of the ProductStatus attribute was one of the following:   Available \| Backordered \| Discontinued  You would first need to specify ExpressionAttributeValues as follows:  { ":avail":{"S":"Available"}, ":back":{"S":"Backordered"}, ":disc":{"S":"Discontinued"} }  You could then use these values in an expression, such as this:  ProductStatus IN (:avail, :back, :disc)  For more information on expression attribute values, see Condition Expressions in the *Amazon DynamoDB Developer Guide*. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.Attributes | unknown | A map of attribute values as they appear before or after the UpdateItem operation, as determined by the ReturnValues parameter. The Attributes map is only present if ReturnValues was specified as something other than NONE in the request. Each element represents one attribute. | 
| AWS-DynamoDB.ConsumedCapacity.TableName | unknown | The name of the table that was affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.CapacityUnits | unknown | The total number of capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.ReadCapacityUnits | unknown | The total number of read capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.WriteCapacityUnits | unknown | The total number of write capacity units consumed by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.Table.ReadCapacityUnits | unknown | The total number of read capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.WriteCapacityUnits | unknown | The total number of write capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table.CapacityUnits | unknown | The total number of capacity units consumed on a table or an index. | 
| AWS-DynamoDB.ConsumedCapacity.Table | unknown | The amount of throughput consumed on the table affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.LocalSecondaryIndexes | unknown | The amount of throughput consumed on each local index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity.GlobalSecondaryIndexes | unknown | The amount of throughput consumed on each global index affected by the operation. | 
| AWS-DynamoDB.ConsumedCapacity | unknown | The capacity units consumed by the UpdateItem operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. ConsumedCapacity is only returned if the ReturnConsumedCapacity parameter was specified. For more information, see Provisioned Throughput in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.ItemCollectionMetrics.ItemCollectionKey | unknown | The partition key value of the item collection. This value is the same as the partition key value of the item. | 
| AWS-DynamoDB.ItemCollectionMetrics.SizeEstimateRangeGB | unknown | An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 
| AWS-DynamoDB.ItemCollectionMetrics | unknown | Information about item collections, if any, that were affected by the UpdateItem operation. ItemCollectionMetrics is only returned if the ReturnItemCollectionMetrics parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response. Each ItemCollectionMetrics element consists of:  \*   ItemCollectionKey - The partition key value of the item collection. This is the same as the partition key value of the item itself. <br/> \*   SizeEstimateRangeGB - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit. The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate. | 


### aws-dynamodb-update-table
***
Modifies the provisioned throughput settings, global secondary indexes, or DynamoDB Streams settings for a given table. You can only perform one of the following operations at once:  *  Modify the provisioned throughput settings of the table. 
 *  Enable or disable DynamoDB Streams on the table. 
 *  Remove a global secondary index from the table. 
 *  Create a new global secondary index on the table. After the index begins backfilling, you can use UpdateTable to perform other operations. 
   UpdateTable is an asynchronous operation; while it is executing, the table status changes from ACTIVE to UPDATING. While it is UPDATING, you cannot issue another UpdateTable request. When the table returns to the ACTIVE state, the UpdateTable operation is complete.


#### Base Command

`aws-dynamodb-update-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| attribute_definitions_attribute_name | A name for the attribute. | Optional | 
| attribute_definitions_attribute_type | The data type for the attribute, where:  *   S - the attribute is of type String <br/> *   N - the attribute is of type Number <br/> *   B - the attribute is of type Binary <br/>  | Optional | 
| table_name | The name of the table to be updated. | Optional | 
| billing_mode | Controls how you are charged for read and write throughput and how you manage capacity. When switching from pay-per-request to provisioned capacity, initial provisioned capacity values must be set. The initial provisioned capacity values are estimated based on the consumed read and write capacity of your table and global secondary indexes over the past 30 minutes.  *   PROVISIONED - We recommend using PROVISIONED for predictable workloads. PROVISIONED sets the billing mode to Provisioned Mode. <br/> *   PAY\_PER\_REQUEST - We recommend using PAY\_PER\_REQUEST for unpredictable workloads. PAY\_PER\_REQUEST sets the billing mode to On-Demand Mode.  <br/>  | Optional | 
| provisioned_throughput_read_capacity_units | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| update_index_name | The name of the global secondary index to be updated. | Optional | 
| create_index_name | The name of the global secondary index to be created. | Optional | 
| key_schema_attribute_name | The name of a key attribute. | Optional | 
| key_schema_key_type | The role that this key attribute will assume:  *   HASH - partition key <br/> *   RANGE - sort key <br/>   The partition key of an item is also known as its *hash attribute*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its *range attribute*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | Optional | 
| projection_projection_type | The set of attributes that are projected into the index:  *   KEYS\_ONLY - Only the index and primary keys are projected into the index. <br/> *   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> *   ALL - All of the table attributes are projected into the index. <br/>  | Optional | 
| projection_non_key_attributes | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | Optional | 
| provisioned_throughput_write_capacity_units | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. For more information, see Specifying Read and Write Requirements in the *Amazon DynamoDB Developer Guide*. If read/write capacity mode is PAY\_PER\_REQUEST the value is set to 0. | Optional | 
| delete_index_name | The name of the global secondary index to be deleted. | Optional | 
| stream_specification_stream_enabled | &lt;p&gt;Indicates whether DynamoDB Streams is enabled (true) or disabled (false) on the table.&lt;/p&gt; | Optional | 
| stream_specification_stream_view_type |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  *   KEYS\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> *   NEW\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> *   OLD\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> *   NEW\_AND\_OLD\_IMAGES - Both the new and the old item images of the item are written to the stream. <br/>  | Optional | 
| sse_specification_enabled | &lt;p&gt;Indicates whether server-side encryption is done using an AWS managed CMK or an AWS owned CMK. If enabled (true), server-side encryption type is set to &lt;code&gt;KMS&lt;/code&gt; and an AWS managed CMK is used (AWS KMS charges apply). If disabled (false) or not specified, server-side encryption is set to AWS owned CMK.&lt;/p&gt; | Optional | 
| sse_specification_sse_type | Server-side encryption type. The only supported value is:  *   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS (AWS KMS charges apply). <br/>  | Optional | 
| sse_specification_kms_master_key_id | The KMS customer master key (CMK) that should be used for the AWS KMS encryption. To specify a CMK, use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. Note that you should only provide this parameter if the key is different from the default DynamoDB customer master key alias/aws/dynamodb. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeName | unknown | A name for the attribute. | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions.AttributeType | unknown | The data type for the attribute, where:  \*   S - the attribute is of type String <br/> \*   N - the attribute is of type Number <br/> \*   B - the attribute is of type Binary | 
| AWS-DynamoDB.TableDescription.AttributeDefinitions | unknown | An array of AttributeDefinition objects. Each of these objects describes one attribute in the table and index key schema. Each AttributeDefinition object in this array is composed of:  \*   AttributeName - The name of the attribute. <br/> \*   AttributeType - The data type for the attribute. | 
| AWS-DynamoDB.TableDescription.TableName | unknown | The name of the table. | 
| AWS-DynamoDB.TableDescription.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.KeySchema | unknown | The primary key structure for the table. Each KeySchemaElement consists of:  \*   AttributeName - The name of the attribute. <br/> \*   KeyType - The role of the attribute: <br/>	 \+   HASH - partition key <br/>	 \+   RANGE - sort key <br/>	   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  <br/>  For more information about primary keys, see Primary Key in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.TableStatus | unknown | The current state of the table:  \*   CREATING - The table is being created. <br/> \*   UPDATING - The table is being updated. <br/> \*   DELETING - The table is being deleted. <br/> \*   ACTIVE - The table is ready for use. | 
| AWS-DynamoDB.TableDescription.CreationDateTime | unknown | The date and time when the table was created, in UNIX epoch time format. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.ProvisionedThroughput | unknown | The provisioned throughput settings for the table, consisting of read and write capacity units, along with data about increases and decreases. | 
| AWS-DynamoDB.TableDescription.TableSizeBytes | unknown | The total size of the specified table, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.ItemCount | unknown | The number of items in the specified table. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.TableArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the table. | 
| AWS-DynamoDB.TableDescription.TableId | unknown | Unique identifier for the table for which the backup was created.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.BillingMode | unknown | Controls how you are charged for read and write throughput and how you manage capacity. This setting can be changed later.  \*   PROVISIONED - Sets the read/write capacity mode to PROVISIONED. We recommend using PROVISIONED for predictable workloads. <br/> \*   PAY\\_PER\\_REQUEST - Sets the read/write capacity mode to PAY\\_PER\\_REQUEST. We recommend using PAY\\_PER\\_REQUEST for unpredictable workloads.  | 
| AWS-DynamoDB.TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime | unknown | Represents the time when PAY\\_PER\\_REQUEST was last set as the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.BillingModeSummary | unknown | Contains the details for the read/write capacity mode. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexName | unknown | Represents the name of the local secondary index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.KeySchema | unknown | The complete key schema for the local secondary index, consisting of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.LocalSecondaryIndexes | unknown | Represents one or more local secondary indexes on the table. Each index is scoped to a given partition key value. Tables with one or more local secondary indexes are subject to an item collection size limit, where the amount of data within a given item collection cannot exceed 10 GB. Each element is composed of:  \*   IndexName - The name of the local secondary index. <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   IndexSizeBytes - Represents the total size of the index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/> \*   ItemCount - Represents the number of items in the index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexName | unknown | The name of the global secondary index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.AttributeName | unknown | The name of a key attribute. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema.KeyType | unknown | The role that this key attribute will assume:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.KeySchema | unknown | The complete key schema for a global secondary index, which consists of one or more pairs of attribute names and key types:  \*   HASH - partition key <br/> \*   RANGE - sort key <br/>   The partition key of an item is also known as its \*hash attribute\*. The term "hash attribute" derives from DynamoDB's usage of an internal hash function to evenly distribute data items across partitions, based on their partition key values. The sort key of an item is also known as its \*range attribute\*. The term "range attribute" derives from the way DynamoDB stores items with the same partition key physically close together, in sorted order by the sort key value.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.ProjectionType | unknown | The set of attributes that are projected into the index:  \*   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/> \*   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/> \*   ALL - All of the table attributes are projected into the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection.NonKeyAttributes | unknown | Represents the non-key attribute names which will be projected into the index. For local secondary indexes, the total count of NonKeyAttributes summed across all of the local secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Projection | unknown | Represents attributes that are copied \(projected\) from the table into the global secondary index. These are in addition to the primary key attributes and index key attributes, which are automatically projected.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexStatus | unknown | The current state of the global secondary index:  \*   CREATING - The index is being created. <br/> \*   UPDATING - The index is being updated. <br/> \*   DELETING - The index is being deleted. <br/> \*   ACTIVE - The index is ready for use.   | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.Backfilling | unknown | Indicates whether the index is currently backfilling. \*Backfilling\* is the process of reading items from the table and determining whether they can be added to the index. \(Not all items will qualify: For example, a partition key cannot have any duplicate values.\) If an item can be added to the index, DynamoDB will do so. After all items have been processed, the backfilling operation is complete and Backfilling is false. You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false.   For indexes that were created during a CreateTable operation, the Backfilling attribute does not appear in the DescribeTable output.  | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastIncreaseDateTime | unknown | The date and time of the last provisioned throughput increase for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.LastDecreaseDateTime | unknown | The date and time of the last provisioned throughput decrease for this table. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.NumberOfDecreasesToday | unknown | The number of provisioned throughput decreases for this table during this UTC calendar day. For current maximums on provisioned throughput decreases, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.ReadCapacityUnits | unknown | The maximum number of strongly consistent reads consumed per second before DynamoDB returns a ThrottlingException. Eventually consistent reads require less effort than strongly consistent reads, so a setting of 50 ReadCapacityUnits per second provides 100 eventually consistent ReadCapacityUnits per second. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput.WriteCapacityUnits | unknown | The maximum number of writes consumed per second before DynamoDB returns a ThrottlingException. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ProvisionedThroughput | unknown | Represents the provisioned throughput settings for the specified global secondary index. For current minimum and maximum provisioned throughput values, see Limits in the \*Amazon DynamoDB Developer Guide\*. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexSizeBytes | unknown | The total size of the specified index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.ItemCount | unknown | The number of items in the specified index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes.IndexArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the index. | 
| AWS-DynamoDB.TableDescription.GlobalSecondaryIndexes | unknown | The global secondary indexes, if any, on the table. Each index is scoped to a given partition key value. Each element is composed of:  \*   Backfilling - If true, then the index is currently in the backfilling phase. Backfilling occurs only when a new global secondary index is added to the table. It is the process by which DynamoDB populates the new index with data from the table. \(This attribute does not appear for indexes that were created during a CreateTable operation.\)   You can delete an index that is being created during the Backfilling phase when IndexStatus is set to CREATING and Backfilling is true. You can't delete the index that is being created when IndexStatus is set to CREATING and Backfilling is false. \(This attribute does not appear for indexes that were created during a CreateTable operation.\) <br/> \*   IndexName - The name of the global secondary index. <br/> \*   IndexSizeBytes - The total size of the global secondary index, in bytes. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   IndexStatus - The current status of the global secondary index: <br/>	 \+   CREATING - The index is being created. <br/>	 \+   UPDATING - The index is being updated. <br/>	 \+   DELETING - The index is being deleted. <br/>	 \+   ACTIVE - The index is ready for use. <br/> \*   ItemCount - The number of items in the global secondary index. DynamoDB updates this value approximately every six hours. Recent changes might not be reflected in this value.  <br/> \*   KeySchema - Specifies the complete index key schema. The attribute names in the key schema must be between 1 and 255 characters \(inclusive\). The key schema must begin with the same partition key as the table. <br/> \*   Projection - Specifies attributes that are copied \(projected\) from the table into the index. These are in addition to the primary key attributes and index key attributes, which are automatically projected. Each attribute specification is composed of: <br/>	 \+   ProjectionType - One of the following: <br/>		 -   KEYS\\_ONLY - Only the index and primary keys are projected into the index. <br/>		 -   INCLUDE - Only the specified table attributes are projected into the index. The list of projected attributes is in NonKeyAttributes. <br/>		 -   ALL - All of the table attributes are projected into the index. 		  <br/>	 \+   NonKeyAttributes - A list of one or more non-key attribute names that are projected into the secondary index. The total count of attributes provided in NonKeyAttributes, summed across all of the secondary indexes, must not exceed 20. If you project the same attribute into two different indexes, this counts as two distinct attributes when determining the total. 	  <br/> \*   ProvisionedThroughput - The provisioned throughput settings for the global secondary index, consisting of read and write capacity units, along with data about increases and decreases.  <br/>  If the table is in the DELETING state, no information about indexes will be returned. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamEnabled | unknown | Indicates whether DynamoDB Streams is enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.TableDescription.StreamSpecification.StreamViewType | unknown |  When an item in the table is modified, StreamViewType determines what information is written to the stream for this table. Valid values for StreamViewType are:  \*   KEYS\\_ONLY - Only the key attributes of the modified item are written to the stream. <br/> \*   NEW\\_IMAGE - The entire item, as it appears after it was modified, is written to the stream. <br/> \*   OLD\\_IMAGE - The entire item, as it appeared before it was modified, is written to the stream. <br/> \*   NEW\\_AND\\_OLD\\_IMAGES - Both the new and the old item images of the item are written to the stream. | 
| AWS-DynamoDB.TableDescription.StreamSpecification | unknown | The current DynamoDB Streams configuration for the table. | 
| AWS-DynamoDB.TableDescription.LatestStreamLabel | unknown | A timestamp, in ISO 8601 format, for this stream. Note that LatestStreamLabel is not a unique identifier for the stream, because it is possible that a stream from another table might have the same timestamp. However, the combination of the following three elements is guaranteed to be unique:  \*  AWS customer ID <br/> \*  Table name <br/> \*   StreamLabel    | 
| AWS-DynamoDB.TableDescription.LatestStreamArn | unknown | The Amazon Resource Name \(ARN\) that uniquely identifies the latest stream for this table. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceBackupArn | unknown | The Amazon Resource Name \(ARN\) of the backup from which the table was restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.SourceTableArn | unknown | The ARN of the source table of the backup that is being restored. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreDateTime | unknown | Point in time or source backup time. | 
| AWS-DynamoDB.TableDescription.RestoreSummary.RestoreInProgress | unknown | Indicates if a restore is in progress or not. | 
| AWS-DynamoDB.TableDescription.RestoreSummary | unknown | Contains details for the restore. | 
| AWS-DynamoDB.TableDescription.SSEDescription.Status | unknown | Represents the current state of server-side encryption. The only supported values are:  \*   ENABLED - Server-side encryption is enabled. <br/> \*   UPDATING - Server-side encryption is being updated.   | 
| AWS-DynamoDB.TableDescription.SSEDescription.SSEType | unknown | Server-side encryption type. The only supported value is:  \*   KMS - Server-side encryption that uses AWS Key Management Service. The key is stored in your account and is managed by AWS KMS \(AWS KMS charges apply\).   | 
| AWS-DynamoDB.TableDescription.SSEDescription.KMSMasterKeyArn | unknown | The KMS customer master key \(CMK\) ARN used for the AWS KMS encryption. | 
| AWS-DynamoDB.TableDescription.SSEDescription | unknown | The description of the server-side encryption status on the specified table. | 
| AWS-DynamoDB.TableDescription | unknown | Represents the properties of the table. | 


### aws-dynamodb-update-time-to-live
***
The UpdateTimeToLive method enables or disables Time to Live (TTL) for the specified table. A successful UpdateTimeToLive call returns the current TimeToLiveSpecification. It can take up to one hour for the change to fully process. Any additional UpdateTimeToLive calls for the same table during this one hour duration result in a ValidationException.  TTL compares the current time in epoch time format to the time stored in the TTL attribute of an item. If the epoch time value stored in the attribute is less than the current time, the item is marked as expired and subsequently deleted.   The epoch time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970 UTC.   DynamoDB deletes expired items on a best-effort basis to ensure availability of throughput for other data operations.   DynamoDB typically deletes expired items within two days of expiration. The exact duration within which an item gets deleted after expiration is specific to the nature of the workload. Items that have expired and not been deleted will still show up in reads, queries, and scans.  As items are deleted, they are removed from any local secondary index and global secondary index immediately in the same eventually consistent way as a standard delete operation. For more information, see Time To Live in the Amazon DynamoDB Developer Guide. 


#### Base Command

`aws-dynamodb-update-time-to-live`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.  | Optional | 
| raw_json | Override arguments and send a formatted JSON file. | Optional | 
| table_name | The name of the table to be configured. | Optional | 
| time_to_live_specification_enabled | &lt;p&gt;Indicates whether TTL is to be enabled (true) or disabled (false) on the table.&lt;/p&gt; | Optional | 
| time_to_live_specification_attribute_name | The name of the TTL attribute used to store the expiration time for items in the table. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS-DynamoDB.TimeToLiveSpecification.Enabled | unknown | Indicates whether TTL is to be enabled \(true\) or disabled \(false\) on the table. | 
| AWS-DynamoDB.TimeToLiveSpecification.AttributeName | unknown | The name of the TTL attribute used to store the expiration time for items in the table. | 
| AWS-DynamoDB.TimeToLiveSpecification | unknown | Represents the output of an UpdateTimeToLive operation. | 