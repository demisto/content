# Azure Storage Table
Create and Manage Azure Storage Tables and Entities.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Table

## Configure Azure Storage Table on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Storage Table.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Storage account name | True |
    | Account SAS Token | True |
    | Use system proxy | False |
    | Trust any certificate | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-storage-table-table-create
***
Creates a new table in a storage account.


#### Base Command

`azure-storage-table-table-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Table.TableName | String | Table name. | 


#### Command Example
```!azure-storage-table-table-create table_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageTable": {
        "Table": {
            "TableName": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Table:
>|Table Name|
>|---|
>| xsoar |


### azure-storage-table-table-delete
***
Delete the specified table and any data it contains.


#### Base Command

`azure-storage-table-table-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-table-delete table_name="xsoar"```

#### Human Readable Output

>Table xsoar successfully deleted.

### azure-storage-table-table-query
***
List tables under the specified account.


#### Base Command

`azure-storage-table-table-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of Tables to retrieve. Default is 50. Default is 50. | Optional | 
| filter | Filter Tables Query expression. <br/>Information about Query expression structure can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/querying-tables-and-entities#constructing-filter-strings. | Optional | 
| page | Page Number.  Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Table.TableName | String | Table name. | 


#### Command Example
```!azure-storage-table-table-query filter="TableName%20eq%20'xsoar'"```

#### Context Example
```json
{
    "AzureStorageTable": {
        "Table": {
            "TableName": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Tables List:
> Current page size: 50
> Showing page 1 out others that may exist
>|Table Name|
>|---|
>| xsoar |


### azure-storage-table-entity-insert
***
Insert a new entity into a table.


#### Base Command

`azure-storage-table-entity-insert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Required | 
| row_key | Unique identifier for an entity within a given partition. | Required | 
| entity_fields | Entity records in JSON format: { "Key1": Value1, "Key2": Value2}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Entity.PartitionKey | String | Entity partition key. | 
| AzureStorageTable.Entity.RowKey | String | Entity row key. | 
| AzureStorageTable.Entity.Timestamp | Date | Entity last update UTC time. | 
| AzureStorageTable.Entity.table_name | String | Table Name. | 


#### Command Example
```!azure-storage-table-entity-insert table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row" entity_fields=`{"Age":20}````

#### Context Example
```json
{
    "AzureStorageTable": {
        "Entity": {
            "Age": 20,
            "PartitionKey": "xsoar-partition",
            "RowKey": "xsoar-row",
            "Timestamp": "2021-08-29T09:25:12",
            "table_name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Entity Fields:
>|Age|Partition Key|Row Key|Timestamp|Table _ Name|
>|---|---|---|---|---|
>| 20 | xsoar-partition | xsoar-row | 2021-08-29T09:25:12 | xsoar |


### azure-storage-table-entity-update
***
Update an existing entity in a table.The Update Entity command does not replace the existing entity.


#### Base Command

`azure-storage-table-entity-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Required | 
| row_key | Unique identifier for an entity within a given partition. | Required | 
| entity_fields | Entity records in JSON format: { "Key1": Value1, "Key2": Value2}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-entity-update table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row" entity_fields=`{"Address":"New York"}````

#### Human Readable Output

>Entity in xsoar table successfully updated.

### azure-storage-table-entity-replace
***
Replace an existing entity in a table.The Replace Entity command replace the entire entity and can be used to remove properties.


#### Base Command

`azure-storage-table-entity-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Required | 
| row_key | Unique identifier for an entity within a given partition. | Required | 
| entity_fields | Entity records in JSON format: { "Key1": Value1, "Key2": Value2}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-entity-replace table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row" entity_fields=`{"City": "TLV" }````

#### Human Readable Output

>Entity in xsoar table successfully replaced.

### azure-storage-table-entity-query
***
Query Entities in a table.


#### Base Command

`azure-storage-table-entity-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Optional | 
| row_key | Unique identifier for an entity within a given partition. | Optional | 
| filter | Filter Entities query expression.<br/>Information about Query expression structure can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/querying-tables-and-entities#constructing-filter-strings. | Optional | 
| select | Comma-separated Entity properties to return. | Optional | 
| limit | Number of entities to retrieve. Default is 50.<br/>This argument is unusable when 'partition_key' is provided. Default is 50. | Optional | 
| page | Page number. Default is 1.<br/>This argument is unusable when 'partition_key' is provided. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Entity.table_name | String | Table Name. | 


#### Command Example
```!azure-storage-table-entity-query table_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageTable": {
        "Entity": [
            {
                "Address": "New York",
                "City": "TLV",
                "PartitionKey": "xsoar-partition",
                "RowKey": "xsoar-row",
                "Timestamp": "2021-08-29T09:25:19",
                "table_name": "xsoar"
            }
        ]
    }
}
```

#### Human Readable Output

>### Entity Fields:
> Current page size: 50
> Showing page 1 out others that may exist
>|Address|City|Partition Key|Row Key|Timestamp|Table _ Name|
>|---|---|---|---|---|---|
>| New York | TLV | xsoar-partition | xsoar-row | 2021-08-29T09:25:19 | xsoar |


### azure-storage-table-entity-delete
***
Delete an existing entity in a table.


#### Base Command

`azure-storage-table-entity-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Required | 
| row_key | Unique identifier for an entity within a given partition. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-entity-delete table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row"```

#### Human Readable Output

>Entity in xsoar table successfully deleted.
