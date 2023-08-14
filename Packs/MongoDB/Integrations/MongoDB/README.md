## Overview
---

Use MongoDB to search and query entries
This integration was integrated and tested with version v4.2.3 of MongoDB
## Configure MongoDB on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for MongoDB.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Username__
    * __Server URLs with port (host1.com:27017,host2.com:27017)__
    * __Database__
    * __Trust any certificate (not secure)__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. mongodb-get-entry-by-id
2. mongodb-query
3. mongodb-insert
4. mongodb-update
5. mongodb-delete
6. mongodb-list-collections
7. mongodb-create-collection
8. mongodb-drop-collection
9. mongodb-pipeline-query
### 1. mongodb-get-entry-by-id
---
Get an entry from database by ID
##### Required Permissions
`find` permission.
##### Base Command

`mongodb-get-entry-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of the collection do get entry from. | Required | 
| object_id | An ObjectID to get. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry._id | String | ID of entry | 
| MongoDB.Entry.collection | String | Collection name |


##### Command Example
```!mongodb-get-entry-by-id collection=test object_id=5e444002d661d4fc62442f39```

##### Context Example
```json
{
    "MongoDB": [
        {
            "test": true, 
            "_id": "5e444002d661d4fc62442f39"
        } 
    ]
}
```

##### Human Readable Output
> Total of 0 found in MongoDB collection 'test':
>**No entries.**


### 2. mongodb-query
---
Searches for items by using the specified JSON query. Search by regex is supported.
##### Required Permissions
`find` permission.
##### Base Command

`mongodb-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of the collection do query from. | Required | 
| query | A JSON query to search for in the collection, in the format of: `{"key": "value"}`. e.g {"_id": "mongodbid"}. Supports search by regex using the following query=`"{ "field": { "$regex": "search_option" } }"`. For example: query=`"{ "year": { "$regex": "2.*" } }"` - will query all entries such that their "year" field contains the number 2, query=`"{ "color": { "$regex": "Re.*", "$options": "i" } }"`: case insensitive search - will query all entries at the collection, where their "color" field contains the string "Re".| Required |
| sort | Sorting order for the query results. Use the format "field1:asc,field2:desc". | Optional|


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry._id | String | ID of entry from query | 
| MongoDB.Entry.collection | String | Collection name |

##### Command Example
```!mongodb-query collection=test query=`{"test": true}```

##### Context Example
```json
{
    "MongoDB": [
        {
            "test": true, 
            "_id": "5e454023a14c0fb64ca2fd7f"
        }, 
        {
            "test": true, 
            "_id": "5e454024a14c0fb64ca2fd80"
        }, 
        {
            "test": true, 
            "_id": "5e454024a14c0fb64ca2fd81"
        }
    ]
}
```

##### Human Readable Output
> Total of 2 found in MongoDB collection 'test' with query: {"test": true}:
>|_id|
>|---|
>| 5e454023a14c0fb64ca2fd7f |
>| 5e454024a14c0fb64ca2fd80 |


### 3. mongodb-insert
---
Inserts an entry to the database
##### Required Permissions
`insert` permission.
##### Base Command

`mongodb-insert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of the collection to insert entry from. | Required | 
| entry | Entry JSON formatted. can include `_id` argument or not. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry._id | String | ID of entry from query. | 
| MongoDB.Entry.collection | String | Collection name |

##### Command Example
```!mongodb-insert collection=testCollection entry=`{"test": true}`\```

##### Context Example
```json
{
    "MongoDB": [
        {
            "_id": "5e45403c7bc040c2a989007a"
        }
    ]
}
```

##### Human Readable Output
>MongoDB: Successfully entered 1 entry to the 'testCollection' collection.
>|_id|
>|---|
>| 5e45403c7bc040c2a989007a |


### 4. mongodb-update
---
Updates an entry in a collection
##### Required Permissions
`update` permission.
##### Base Command

`mongodb-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of the collection to update entry to. | Required | 
| filter | A query that matches the document to update. | Required | 
| update | You can use Update Operators or Aggregation Pipeline. Check documentation for further information. | Required | 
| update_one | Update only one entry. if true, will set all found entries. | Optional | 
| upsert | Update entries in a collection that matches the query or create a new entry if no entires match the query. Default is false. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-update collection=test filter=`{"test": true}` update=`{"$set": {"test": false}}` ```

##### Human Readable Output
>MongoDB: Total of 1 entries has been modified.

If an entry was created and inserted using the *upset* argument:

>MongoDB: A new entry was inserted to the collection.


### 5. mongodb-delete
---
Deletes an entry from the database
##### Required Permissions
`remove` permission.
##### Base Command

`mongodb-delete`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of the collection to delete entry from. | Required | 
| filter | A query that matches the document to delete. | Required | 
| delete_one | Delete only one entry from the database. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-delete collection=test filter=`{"test": true}` delete_one=true```

##### Human Readable Output
>MongoDB: Delete 1 entries.

### 6. mongodb-list-collections
---
Lists all collections in database
##### Required Permissions
`find` permission.
##### Base Command

`mongodb-list-collections`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Collection.Name | String | Name of the collection | 


##### Command Example
```!mongodb-list-collections```

##### Context Example
```json
{
    "MongoDB.Collection": [
        {
            "Name": "collectionToDelete"
        }, 
        {
            "Name": "testCollection"
        }, 
        {
            "Name": "test"
        }
    ]
}
```

##### Human Readable Output
>MongoDB: All collections in database:
>|Collection|
>|---|
>| collectionToDelete |
>| testCollection |
>| test |


### 7. mongodb-create-collection
---
Creates a collection
##### Required Permissions
`createCollection` permission.
##### Base Command

`mongodb-create-collection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of collection to create. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-create-collection collection=testCollection```

##### Human Readable Output
>MongoDB: Collection 'testCollection' has been successfully created.

### 8. mongodb-drop-collection
---
Drops a collection from the database
##### Required Permissions
`dropCollection` permission or above.
##### Base Command

`mongodb-drop-collection`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of collection to be dropped | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-drop-collection collection=collectionToDelete```

##### Human Readable Output
>MongoDB: Collection 'collectionToDelete` has been dropped.

### 9. mongodb-pipeline-query
***
Searches for items by the specified JSON pipleline query.


#### Base Command

`mongodb-pipeline-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | Name of the collection to query. | Required | 
| pipeline | A JSON pipeline query to search by in the collection. Pipeline query should by list of dictionaries. For example: [{"key1": "value1"}, {"key2": "value2"}]. | Required | 
| limit | Limits the number of results returned from MongoDB. Default is 50. | Optional | 
| offset | Offset to the first result returned from MongoDB. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MongoDB.Entry._id | String | The ID of entry from the query. | 
| MongoDB.Entry.collection | String | The collection of which the entry belongs to. | 


#### Command Example
```!mongodb-pipeline-query collection=test_collection pipeline="[{\"$match\": {\"title\": \"test_title\"}}]"```

#### Context Example
```json
{
    "MongoDB": {
        "Entry": [
            {
                "_id": "602e624e8be6cb93eb795695",
                "collection": "test_collection",
                "color": "red",
                "title": "test_title",
                "year": "2019"
            },
            {
                "_id": "602e62598be6cb93eb795697",
                "collection": "test_collection",
                "color": "green",
                "title": "test_title",
                "year": "2020"
            },
            {
                "_id": "602e62698be6cb93eb795699",
                "collection": "test_collection",
                "color": "yellow",
                "title": "test_title",
                "year": "2018"
            }
        ]
    }
}
```

#### Human Readable Output

>Total of 3 entries were found in MongoDB collection `test_collection` with pipeline: [{"$match": {"title": "test_title"}}]:
>|_id|
>|---|
>| 602e624e8be6cb93eb795695 |
>| 602e62598be6cb93eb795697 |
>| 602e62698be6cb93eb795699 |

### 10. mongodb-bulk-update
---
Bulk updates entries in a collection.
##### Required Permissions
`update` permission.
##### Base Command

`mongodb-bulk-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | The name of the collection in which to update entries. | Required | 
| filter | A comma-separated list of queries that match the documents to update, in the format:  ``` `[{"key1": "value1"},{"key2": "value2"}]` ```. This list must match the comma-separated list of the update argument by order and size. | Required | 
| update | A comma-separated list of content with which to update entries, in the format: ``` `[{"$set": {"key1": "value1"}},{"$set": {"key2": "value2"}}]` ```. You can use Update Operators or Aggregation Pipeline. This list must match the comma-separated list of the filter argument by order and size. | Required | 
| update_one | Whether to update a single entry per query. If true, will set only the first found entry, If false, will set all found entries. This argument will effect all the provided queries. Default is true. | Optional | 
| upsert | Will create a new entry if no entires match the provided queries (per query). This argument will effect all the provided queries. Default is false. | Optional |


##### Context Output

There is no context output for this command.

##### Command Example
```!mongodb-update collection=test filter=`[{"Name": "dummy1"},{"$and": [{"value": 1, "another_value":0}]}]` update=`[{"$set": {"test": false}},{"$set": {"test": true}}]` upsert=true ```
##### Human Readable Output
>MongoDB: Total of 1 entries has been modified.
>MongoDB: Total of 1 entries has been inserted.

## Additional Information
---
* a guide on how to use the `filter` and `query` argument can be found [here](https://docs.mongodb.com/manual/reference/operator/aggregation/filter/)
* a guide on how to use the `update` argument can be found [here](https://docs.mongodb.com/manual/reference/operator/update/)
## Known Limitations
---
The `test` button is trying to list collections. If the user has no `find` permission it will fail.
