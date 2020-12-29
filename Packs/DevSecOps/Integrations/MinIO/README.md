An Integration with MinIO Object Storage
This integration was integrated and tested with version xx of MinIO.
## Configure MinIO on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MinIO.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | server | Server Name or Address \(e.g. 192.168.20.20\) | True |
    | port | Port Number | True |
    | access_key | Access Key | True |
    | access_secret | Access Secret | True |
    | ssl | Connect over SSL | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### minio-make-bucket
***
Create a new bucket.


#### Base Command

`minio-make-bucket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Bucket Name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Buckets.bucket | Unknown | MinIO Bucket Name | 
| MinIO.Buckets.status | Unknown | MinIO Bucket Status | 


#### Command Example
``` ```

#### Human Readable Output



### minio-remove-bucket
***
Remove an existing bucket.


#### Base Command

`minio-remove-bucket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Bucket Name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Buckets.bucket | Unknown | MinIO Bucket Name | 
| MinIO.Buckets.status | Unknown | MinIO Bucket Status | 


#### Command Example
``` ```

#### Human Readable Output



### minio-list-buckets
***
List All MinIO Buckets


#### Base Command

`minio-list-buckets`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Buckets | Unknown | MinIO Buckets | 


#### Command Example
``` ```

#### Human Readable Output



### minio-list-objects
***
Lists object information of a bucket.


#### Base Command

`minio-list-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Name of the bucket. | Required | 
| prefix | Object name starts with prefix. | Optional | 
| start_after | List objects after this key name. | Optional | 
| include_user_meta | MinIO specific flag to control to include user metadata. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Objects | Unknown | MinIO Objects | 


#### Command Example
``` ```

#### Human Readable Output



### minio-get-object
***
Gets data from offset to length of an object.


#### Base Command

`minio-get-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. | Required | 
| name | Object Name. | Required | 
| offset | Start byte position of object data. | Optional | 
| length | Number of bytes of object data from offset. Possible values are: . | Optional | 
| request_headers | Any additional headers to be added with GET request. | Optional | 
| extra_query_params | Extra query parameters for advanced usage. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### minio-stat-object
***
Get object information and metadata of an object.


#### Base Command

`minio-stat-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. | Required | 
| name | Object Name. | Required | 
| extra_query_params | Extra query parameters for advanced usage. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### minio-remove-object
***
Remove an object.


#### Base Command

`minio-remove-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. | Required | 
| name | Object Name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Objects.name | Unknown | Object Name | 
| MinIO.Objects.status | Unknown | Object Status | 


#### Command Example
``` ```

#### Human Readable Output



### minio-fput-object
***
Uploads data from a file to an object in a bucket.


#### Base Command

`minio-fput-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. Possible values are: . | Required | 
| entry_id | File Entry ID. | Required | 
| content_type | File Type. | Optional | 
| metadata | Any additional metadata to be uploaded along with your PUT request. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### minio-put-object
***
Uploads data from a stream to an object in a bucket.


#### Base Command

`minio-put-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. Possible values are: . | Required | 
| data | Contains object data. | Required | 
| name | Object name in the bucket. | Required | 
| content_type | File Type. | Optional | 
| metadata | Any additional metadata to be uploaded along with your PUT request. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


