An Integration with MinIO Object Storage
This integration was integrated and tested with RELEASE.2020-12 of MinIO.
## Configure MinIO in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server Name or Address \(e.g. 8.8.8.8\) | True |
| port | Port Number | True |
| access_key | Access Key | True |
| access_secret | Access Secret | True |
| ssl | Connect over SSL | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
```!minio-make-bucket name="test20"```

#### Context Example
```json
{
    "MinIO": {
        "Buckets": {
            "bucket": "test20",
            "status": "created"
        }
    }
}
```

#### Human Readable Output

>### Results
>|bucket|status|
>|---|---|
>| test20 | created |


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
```!minio-remove-bucket name="test20"```

#### Context Example
```json
{
    "MinIO": {
        "Buckets": {
            "bucket": "test20",
            "status": "removed"
        }
    }
}
```

#### Human Readable Output

>### Results
>|bucket|status|
>|---|---|
>| test20 | removed |


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
```!minio-list-buckets```

#### Context Example
```json
{
    "MinIO": {
        "Buckets": [
            {
                "bucket": "opencti-bucket",
                "creation_date": "2020-12-18 17:06:04.887000+00:00"
            },
            {
                "bucket": "test1",
                "creation_date": "2020-12-29 10:54:39.996000+00:00"
            },
            {
                "bucket": "test10",
                "creation_date": "2020-12-29 10:45:46.962000+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|bucket|creation_date|
>|---|---|
>| opencti-bucket | 2020-12-18 17:06:04.887000+00:00 |
>| test1 | 2020-12-29 10:54:39.996000+00:00 |
>| test10 | 2020-12-29 10:45:46.962000+00:00 |


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
```!minio-list-objects bucket_name="test10"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": [
            {
                "bucket": "test10",
                "etag": "4be6f1e4bda138a555416b866a90530c",
                "is_dir": false,
                "last_modified": "2020-12-29 10:46:04.387000+00:00",
                "object": "MINIO_wordmark.png",
                "size": 11496
            },
            {
                "bucket": "test10",
                "etag": "c4e3802707693c8df821b37c91c0cfd8",
                "is_dir": false,
                "last_modified": "2020-12-30 06:10:37.886000+00:00",
                "object": "test.txt",
                "size": 9
            },
            {
                "bucket": "test10",
                "etag": "7a6add52bec4ca39eedeea16927c92e3",
                "is_dir": false,
                "last_modified": "2020-12-30 06:12:33.487000+00:00",
                "object": "test.yml",
                "size": 34960
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|bucket|etag|is_dir|last_modified|object|size|
>|---|---|---|---|---|---|
>| test10 | 4be6f1e4bda138a555416b866a90530c | false | 2020-12-29 10:46:04.387000+00:00 | MINIO_wordmark.png | 11496 |
>| test10 | c4e3802707693c8df821b37c91c0cfd8 | false | 2020-12-30 06:10:37.886000+00:00 | test.txt | 9 |
>| test10 | 7a6add52bec4ca39eedeea16927c92e3 | false | 2020-12-30 06:12:33.487000+00:00 | test.yml | 34960 |


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
```!minio-get-object bucket_name="test10" name="MINIO_wordmark.png"```

#### Context Example
```json
{
    "File": {
        "EntryID": "399@58b146a9-f748-4f65-8846-a1d63c7e77f4",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "4be6f1e4bda138a555416b866a90530c",
        "Name": "MINIO_wordmark.png",
        "SHA1": "568f64faee0471c811e6ef5234428751236f9ad2",
        "SHA256": "d53ad84d5c44a6991b0b6109703aff663d5d016ee93762eaf46624144f1c6fc5",
        "SHA512": "8d5ba7577cd2a98c0a973997978c31700996d54dd76e332a108fdb5a4694e55c7c172c8bae1d1189810b4d766bbffa52c6f1acb599c5679666a4e8368241a710",
        "SSDeep": "192:DBfcNvyaPaOjCOSXA/DA47c6qurTlvUnHjXoRBVaYuKY7BF019UtNB2KBlloHfoe:iB1PaO7SXA/DA47LqqToD6TaYufAcJNq",
        "Size": 11496,
        "Type": "PNG image data, 2401 x 362, 8-bit colormap, non-interlaced"
    }
}
```

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
```!minio-stat-object bucket_name="test10" name="test.txt"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test10",
            "content-type": "application/octet-stream",
            "etag": "\"c4e3802707693c8df821b37c91c0cfd8\"",
            "object": "test.txt",
            "size": 9
        }
    }
}
```

#### Human Readable Output

>### Results
>|bucket|content-type|etag|object|size|
>|---|---|---|---|---|
>| test10 | application/octet-stream | "c4e3802707693c8df821b37c91c0cfd8" | test.txt | 9 |


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
```!minio-remove-object bucket_name="test10" name="test.txt"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test10",
            "object": "test.txt",
            "status": "removed"
        }
    }
}
```

#### Human Readable Output

>### Results
>|bucket|object|status|
>|---|---|---|
>| test10 | test.txt | removed |


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
```!minio-fput-object bucket_name="test10" entry_id="297@58b146a9-f748-4f65-8846-a1d63c7e77f4"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test10",
            "object": "test.yml",
            "status": "uploaded"
        }
    }
}
```

#### Human Readable Output

>### Results
>|bucket|object|status|
>|---|---|---|
>| test10 | test.yml | uploaded |


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
```!minio-put-object bucket_name="test10" data="'test100'" name="test.txt"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test10",
            "object": "test.txt",
            "status": "uploaded"
        }
    }
}
```

#### Human Readable Output

>### Results
>|bucket|object|status|
>|---|---|---|
>| test10 | test.txt | uploaded |


### minio-get-tags
***
Get tags configuration of an object.


#### Base Command

`minio-get-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. | Required | 
| name | Object name in the bucket. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Objects.bucket | Unknown | Bucket Name. | 
| MinIO.Objects.object | Unknown | Object Name. | 
| MinIO.Objects.tags | Unknown | Object Tags. | 

#### Command Example
```!minio-get-tags bucket_name="test11" name="test.txt"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test11",
            "object": "test.txt",
            "status": "completed",
            "tags": {
                "test": "test"
            }
        }
    }
}
```

### minio-set-tag
***
Set tags configuration to an object.


#### Base Command

`minio-set-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name | Bucket Name. | Required | 
| name | Object name in the bucket. | Required | 
| tag_key | Key for the tag to add on the object. | Required | 
| tag_value | Value for the tag to add on the object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Objects.bucket | Unknown | Bucket Name. | 
| MinIO.Objects.object | Unknown | Object Name. | 
| MinIO.Objects.tags | Unknown | Object Tags. | 

#### Command Example
```!minio-set-tag bucket_name="test11" name="test.txt" tag_key="status" tag_value="in_progress"```

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test11",
            "object": "test.txt",
            "status": "completed",
            "tags": {
                "test": "test",
                "status": "in_progress"
            }
        }
    }
}
```

### minio-copy-object
***
Create an object by server-side copying data from another object.


#### Base Command

`minio-copy-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket_name_src | Bucket Name to copy object from. | Required | 
| name_src | Object name to copy. | Required | 
| bucket_name_dst | Bucket Name to copy object to. | Required | 
| name_dst | Object name copied. | Required | 
| metadata | Any user-defined metadata to be copied along with destination object. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MinIO.Objects.bucket | Unknown | Bucket Name. | 
| MinIO.Objects.object | Unknown | Object Name | 
| MinIO.Objects.status | Unknown | Object Status | 


#### Command Example
```!minio-copy-object bucket_name_src="test12" name_src="test_source.txt" bucket_name_dst="test12" name_dst="test_destination.txt"```

```!minio-copy-object bucket_name_src="test12" name_src="test_source.txt" bucket_name_dst="test12" name_dst="myFolder/test_destination.txt"``` (It will create the folder *myFolder*)

#### Context Example
```json
{
    "MinIO": {
        "Objects": {
            "bucket": "test12",
            "object": "test_destination.txt",
            "status": "copied"
        }
    }
}
```