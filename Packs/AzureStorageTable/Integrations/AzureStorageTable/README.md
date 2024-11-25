# Azure Storage Table 
Create and Manage Azure Storage Tables and Entities.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Table

## Configure Azure Storage Table in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Storage account name | True |
| Account SAS Token | False |
| Use Azure Managed Identities | False |
| Azure Managed Identities Client ID | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |


## Shared Access Signatures (SAS) Permissions
In order to use the integration use-cases, 
please make sure your SAS token contains the following permissions:
  1. 'Table' service.
  2. 'Service' and 'Object' resource types.
  3. 'Read', 'Write', 'Delete', 'List', 'Create', 'Add', 'Update' and 'Immutable storage' permissions.

* Review and select "Generate".
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-storage-table-create
***
Creates a new table in a storage account.


#### Base Command

`azure-storage-table-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the new table to create. Rules for naming tables can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/understanding-the-table-service-data-model. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Table.name | String | Table name. | 


#### Command Example
```!azure-storage-table-create table_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageTable": {
        "Table": {
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>Table xsoar successfully created.

### azure-storage-table-delete
***
Delete the specified table and any data it contains.


#### Base Command

`azure-storage-table-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | The name of the table to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-delete table_name="xsoar"```

#### Human Readable Output

>Table xsoar successfully deleted.

### azure-storage-table-query
***
List tables under the specified account.


#### Base Command

`azure-storage-table-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of Tables to retrieve. Default is 50. Default is 50. | Optional | 
| filter | Filter Tables Query expression. <br/>Information about Query expression structure can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/querying-tables-and-entities#constructing-filter-strings. | Optional | 
| page | Page Number.  Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Table.name | String | Table name. | 


#### Command Example
```!azure-storage-table-query filter="TableName%20eq%20'xsoar'"```

#### Context Example
```json
{
    "AzureStorageTable": {
        "Table": {
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Tables List:
> Current page size: 50
> Showing page 1 out others that may exist
>|Name|
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
| entity_fields | Entity fields in JSON format: { "Key1": Value1, "Key2": Value2}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Table.Entity.PartitionKey | String | Entity partition key. | 
| AzureStorageTable.Table.Entity.RowKey | String | Entity row key. | 
| AzureStorageTable.Table.Entity.Timestamp | Date | Entity last update UTC time. | 
| AzureStorageTable.Table.name | String | Entity table name. | 


#### Command Example
```!azure-storage-table-entity-insert table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row" entity_fields=`{"Age":20}````

#### Context Example
```json
{
    "AzureStorageTable": {
        "Table": {
            "Entity": [
                {
                    "Age": 20,
                    "PartitionKey": "xsoar-partition",
                    "RowKey": "xsoar-row",
                    "Timestamp": "2021-11-28T13:23:18"
                }
            ],
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Entity Fields for xsoar Table:
>|Age|Partition Key|Row Key|Timestamp|
>|---|---|---|---|
>| 20 | xsoar-partition | xsoar-row | 2021-11-28T13:23:18 |


### azure-storage-table-entity-update
***
Update an existing entity in a table. The Update Entity command does not replace the existing entity.


#### Base Command

`azure-storage-table-entity-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Entity table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Required | 
| row_key | Unique identifier for an entity within a given partition. | Required | 
| entity_fields | Entity fields in JSON format: { "Key1": Value1, "Key2": Value2}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-entity-update table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row" entity_fields=`{"Address":"New York"}````

#### Human Readable Output

>Entity in xsoar table successfully updated.

### azure-storage-table-entity-replace
***
Replace an existing entity in a table. The Replace Entity command replace the entire entity and can be used to remove properties.


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
| table_name | Entity table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. If specified, 'row_key' argument must also be specified. | Optional | 
| row_key | Unique identifier for an entity within a given partition. If specified, 'partition_key' argument must also be specified. | Optional | 
| filter | Filter Entities query expression.<br/>Information about Query expression structure can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/querying-tables-and-entities#constructing-filter-strings. | Optional | 
| select | Comma-separated Entity properties to return. If not specified - all fields will be retrieved. | Optional | 
| limit | Number of entities to retrieve. Default is 50.<br/>This argument is will be ignored when 'partition_key' or 'row_key' arguments are provided. Default is 50. | Optional | 
| page | Page number. Default is 1.<br/>This argument is will be ignored when 'partition_key' or 'row_key' arguments are provided. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageTable.Table.name | String | Entity table Name. | 


#### Command Example
```!azure-storage-table-entity-query table_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageTable": {
        "Table": {
            "Entity": [
                {
                    "Address": "New York",
                    "City": "TLV",
                    "PartitionKey": "xsoar-partition",
                    "RowKey": "xsoar-row",
                    "Timestamp": "2021-11-28T13:23:27"
                }
            ],
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Entity Fields for xsoar table:
> Current page size: 50
> Showing page 1 out others that may exist
>|Address|City|Partition Key|Row Key|Timestamp|
>|---|---|---|---|---|
>| New York | TLV | xsoar-partition | xsoar-row | 2021-11-28T13:23:27 |


### azure-storage-table-entity-delete
***
Delete an existing entity in a table.


#### Base Command

`azure-storage-table-entity-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_name | Entity table name. | Required | 
| partition_key | Unique identifier for the partition within a given table. | Required | 
| row_key | Unique identifier for an entity within a given partition. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-table-entity-delete table_name="xsoar" partition_key="xsoar-partition" row_key="xsoar-row"```

#### Human Readable Output

>Entity in xsoar table successfully deleted.