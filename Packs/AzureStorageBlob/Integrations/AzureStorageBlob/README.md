# Azure Storage Blob
Create and Manage Azure Storage Blob services.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Blob

## Configure Azure Storage Blob on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Storage Blob.
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
### azure-storage-blob-container-list
***
List Containers under the specified storage account.


#### Base Command

`azure-storage-blob-container-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of Containers to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only Containers whose names begin with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageBlob.Container.container_name | String | Container name. | 


#### Command Example
```!azure-storage-blob-container-list prefix="xs"```

#### Context Example
```json
{
    "AzureStorageBlob": {
        "Container": {
            "container_name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Containers List:
> Current page size: 50
> Showing page 1 out others that may exist
>|Container Name|
>|---|
>| xsoar |


### azure-storage-blob-container-create
***
Create a new Container under the specified account.


#### Base Command

`azure-storage-blob-container-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-container-create container_name="xsoar"```

#### Human Readable Output

>Container xsoar successfully created.

### azure-storage-blob-container-properties-get
***
Retrieve properties for the specified Container.


#### Base Command

`azure-storage-blob-container-properties-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageBlob.Container.Properties.last_modified | Date | Last modified time of the container. | 
| AzureStorageBlob.Container.Properties.etag | String | The entity tag for the container. | 
| AzureStorageBlob.Container.Properties.lease_status | String | The lease status of the container. | 
| AzureStorageBlob.Container.Properties.lease_state | String | The lease state of the container. | 
| AzureStorageBlob.Container.Properties.has_immutability_policy | String | Indicates whether the container has an immutability policy set on it.  | 
| AzureStorageBlob.Container.Properties.has_legal_hold | String | Indicates whether the container has a legal hold. | 
| AzureStorageBlob.Container.container_name | String | Container name. | 


#### Command Example
```!azure-storage-blob-container-properties-get container_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageBlob": {
        "Container": {
            "Properties": {
                "content_length": "0",
                "date": "2021-08-29T14:33:39",
                "default_encryption_scope": "$account-encryption-key",
                "deny_encryption_scope_override": "false",
                "etag": "\"0x8D96AF9F9C879F5\"",
                "has_immutability_policy": "false",
                "has_legal_hold": "false",
                "immutable_storage_with_versioning_enabled": "false",
                "last_modified": "2021-08-29T14:33:31",
                "lease_state": "available",
                "lease_status": "unlocked",
                "request_id": "XXXX",
                "server": "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0",
                "version": "2020-10-02"
            },
            "container_name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Containers Properties:
>|Last Modified|Etag|Lease Status|Lease State|Has Immutability Policy|Has Legal Hold|
>|---|---|---|---|---|---|
>| 2021-08-29T14:33:31 | "0x8D96AF9F9C879F5" | unlocked | available | false | false |


### azure-storage-blob-container-delete
***
Marks the specified Container for deletion. The Container and any Blobs contained within it, will be deleted during garbage collection.


#### Base Command

`azure-storage-blob-container-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-container-delete container_name="xsoar"```

#### Human Readable Output

>Container xsoar successfully deleted.

### azure-storage-blob-blob-list
***
List Blobs under the specified container.


#### Base Command

`azure-storage-blob-blob-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| limit | Number of blobs to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only blobs whose names begin with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageBlob.Blob.blob_name | String | Blob name. | 
| AzureStorageBlob.Blob.container_name | String | Container name. | 


#### Command Example
```!azure-storage-blob-blob-list container_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageBlob": {
        "Blob": {
            "blob_name": "xsoar.txt",
            "container_name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Blobs List:
> Current page size: 50
> Showing page 1 out others that may exist
>|Blob Name|
>|---|
>| xsoar.txt |


### azure-storage-blob-blob-create
***
Create a new Blob under the specified Container.


#### Base Command

`azure-storage-blob-blob-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| file_entry_id | XSOAR file entry ID. | Required | 
| blob_name | Blob name.Default is XSOAR file name. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-blob-create container_name="xsoar" file_entry_id="XXXX" blob_name="xsoar.txt"```

#### Human Readable Output

>Blob successfully created.

### azure-storage-blob-blob-update
***
Update the content of an existing Blob.


#### Base Command

`azure-storage-blob-blob-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| file_entry_id | XSOAR file entry ID. | Required | 
| blob_name | Blob name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-blob-update container_name="xsoar" file_entry_id="XXXX" blob_name="xsoar.txt"```

#### Human Readable Output

>Blob xsoar.txt successfully updated.

### azure-storage-blob-blob-get
***
Retrieve Blob from Container.


#### Base Command

`azure-storage-blob-blob-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| blob_name | Blob name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | Unknown | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 


#### Command Example
```!azure-storage-blob-blob-get container_name="xsoar" blob_name="xsoar.txt"```

#### Context Example
```json
{
    "File": {
        "EntryID": "XXXX",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "1b515195a83a0bc1fc9344f9cd0c3323",
        "Name": "xsoar.txt",
        "SHA1": "8ceedf2239a13a53c98dc8be6cd916cb21d2773c",
        "SHA256": "5ea085e5f21a99a24f2013eb6dda82a13b220956bffc32420ee9dce21e7f7cb7",
        "SHA512": "04f9068eb7eeceb52d603a71ef2c2d0ae2e859c2b51ce6385fc3e24bd04bdd30b55b2f068cf33c403f4d3865453487307823bafb9cc1e4a56e85ac68ba200da5",
        "SSDeep": "3:IKl:IKl",
        "Size": 6,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



### azure-storage-blob-blob-tag-get
***
Retrieve the tags of the specified Blob.


#### Base Command

`azure-storage-blob-blob-tag-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| blob_name | Blob name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageBlob.Tag.Key | String | Tag key. | 
| AzureStorageBlob.Tag.Value | String | Tag value. | 
| AzureStorageBlob.container_name | String | Container name. | 
| AzureStorageBlob.blob_name | String | Blob name. | 


#### Command Example
```!azure-storage-blob-blob-tag-get container_name="xsoar" blob_name="xsoar.txt"```

#### Context Example
```json
{
    "AzureStorageBlob": {
        "Blob": {
            "Tag": [
                {
                    "Key": "tag-name-1",
                    "Value": "tag-value-1"
                }
            ],
            "blob_name": "xsoar.txt",
            "container_name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Blob Tags:
>|Key|Value|
>|---|---|
>| tag-name-1 | tag-value-1 |


### azure-storage-blob-blob-tag-set
***
Sets the tags for the specified Blob.


#### Base Command

`azure-storage-blob-blob-tag-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| blob_name | Blob name. | Required | 
| tags | Tags records in JSON format: {"tag-name-1": "tag-value-1", "tag-name-2": "tag-value-2"}.The tag set may contain at most 10 tags. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-blob-tag-set container_name="xsoar" blob_name="xsoar.txt" tags=`{ "tag-name-1": "tag-value-1" }````

#### Human Readable Output

>xsoar.txt Tags successfully updated.

### azure-storage-blob-blob-delete
***
Marks the specified Blob for deletion. The Blob will be deleted during garbage collection.


#### Base Command

`azure-storage-blob-blob-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| blob_name | Blob name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-blob-delete container_name="xsoar" blob_name="xsoar.txt"```

#### Human Readable Output

>Blob xsoar.txt successfully deleted.

### azure-storage-blob-blob-properties-get
***
Retrieve Blob properties.


#### Base Command

`azure-storage-blob-blob-properties-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| blob_name | Blob name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageBlob.Blob.Properties.last_modified | Date | Last modified time of the blob. | 
| AzureStorageBlob.Blob.Properties.etag | String | The entity tag for the blob. | 
| AzureStorageBlob.Blob.Properties.lease_status | String | The lease status of the blob. | 
| AzureStorageBlob.Blob.Properties.lease_state | String | The lease state of the blob. | 
| AzureStorageBlob.Blob.Properties.blob_type | String | The blob type. | 
| AzureStorageBlob.Blob.Properties.content_length | Number | The size of the blob in bytes. | 
| AzureStorageBlob.Blob.Properties.content_type | String | The content type specified for the blob. If no content type was specified, the default content type is application/octet-stream. | 
| AzureStorageBlob.Blob.Properties.content-md5 | String | The MD5 hash of the blob content. | 
| AzureStorageBlob.Blob.Properties.creation_time | Date | The date at which the blob was created. | 
| AzureStorageBlob.Blob.container_name | String | Container name. | 
| AzureStorageBlob.Blob.blob_name | String | Blob name. | 


#### Command Example
```!azure-storage-blob-blob-properties-get container_name="xsoar" blob_name="xsoar.txt"```

#### Context Example
```json
{
    "AzureStorageBlob": {
        "Blob": {
            "Properties": {
                "accept_ranges": "bytes",
                "access_tier": "Hot",
                "access_tier_inferred": "true",
                "blob_type": "BlockBlob",
                "content_length": "18715",
                "content_md5": "DPWmUdkhcDWvyYWlz4rvsA==",
                "content_type": "application/octet-stream",
                "creation_time": "2021-08-29T14:33:42",
                "date": "2021-08-29T14:33:56",
                "etag": "\"0x8D96AFA04A23350\"",
                "last_modified": "2021-08-29T14:33:50",
                "lease_state": "available",
                "lease_status": "unlocked",
                "request_id": "XXXX",
                "server": "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0",
                "server_encrypted": "true",
                "version": "2020-10-02"
            },
            "blob_name": "xsoar.txt",
            "container_name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Blob Properties:
>|Creation Time|Last Modified|Content Length|Content Type|Etag|
>|---|---|---|---|---|
>| 2021-08-29T14:33:42 | 2021-08-29T14:33:50 | 18715 | application/octet-stream | "0x8D96AFA04A23350" |


### azure-storage-blob-blob-properties-set
***
Set Blob properties.


#### Base Command

`azure-storage-blob-blob-properties-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | Container name. | Required | 
| blob_name | Blob name. | Required | 
| content_type | Blob content type. | Optional | 
| content_md5 | Blob MD5 hash. | Optional | 
| content_encoding | Blob content encoding. | Optional | 
| content_language | Blob content language. | Optional | 
| content_disposition | Blob content disposition. | Optional | 
| cache_control | Modifies the cache control string for the blob. | Optional | 
| request_id | Request ID generated by the client and recorded in the analytics logs when storage analytics logging is enabled. | Optional | 
| lease_id | Required if the blob has an active lease. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-blob-blob-properties-set container_name="xsoar" blob_name="xsoar.txt" content_type="text/plain"```

#### Human Readable Output

>Blob xsoar.txt properties successfully updated.
