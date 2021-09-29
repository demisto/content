# Azure Storage Container
Create and Manage Azure Storage Container services.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Container

## Configure Azure Storage Container on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Storage Container.
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
### azure-storage-container-list
***
List Containers under the specified storage account.


#### Base Command

`azure-storage-container-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of Containers to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only Containers whose names begin with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageContainer.Container.name | String | Container name. | 


#### Command Example
```!azure-storage-container-list prefix="xs"```

#### Context Example
```json
{
    "AzureStorageContainer": {
        "Container": {
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Containers List:
> Current page size: 50
> Showing page 1 out others that may exist
>|Name|
>|---|
>| xsoar |


### azure-storage-container-create
***
Create a new Container under the specified account.


#### Base Command

`azure-storage-container-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Container to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-create container_name="xsoar"```

#### Human Readable Output

>Container xsoar successfully created.

### azure-storage-container-property-get
***
Retrieve properties for the specified Container.


#### Base Command

`azure-storage-container-property-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Container. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageContainer.Container.Property.last_modified | Date | Last modified time of the container. | 
| AzureStorageContainer.Container.Property.etag | String | The entity tag for the container. | 
| AzureStorageContainer.Container.Property.lease_status | String | The lease status of the container. | 
| AzureStorageContainer.Container.Property.lease_state | String | The lease state of the container. | 
| AzureStorageContainer.Container.Property.has_immutability_policy | String | Indicates whether the container has an immutability policy set on it. | 
| AzureStorageContainer.Container.Property.has_legal_hold | String | Indicates whether the container has a legal hold. | 
| AzureStorageContainer.Container.name | String | Container name. | 


#### Command Example
```!azure-storage-container-property-get container_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageContainer": {
        "Container": {
            "Property": {
                "content_length": "0",
                "date": "2021-09-23T11:17:25",
                "default_encryption_scope": "$account-encryption-key",
                "deny_encryption_scope_override": "false",
                "etag": "\"0x8D97E83B550986C\"",
                "has_immutability_policy": "false",
                "has_legal_hold": "false",
                "immutable_storage_with_versioning_enabled": "false",
                "last_modified": "2021-09-23T11:17:19",
                "lease_state": "available",
                "lease_status": "unlocked",
                "request_id": "10b95aab-101e-002c-466c-b0fc9b000000",
                "server": "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0",
                "version": "2020-10-02"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Container xsoar Properties:
>|Last Modified|Etag|Lease Status|Lease State|Has Immutability Policy|Has Legal Hold|
>|---|---|---|---|---|---|
>| 2021-09-23T11:17:19 | "0x8D97E83B550986C" | unlocked | available | false | false |


### azure-storage-container-delete
***
Marks the specified Container for deletion. The Container and any Blobs contained within it, will be deleted during garbage collection.


#### Base Command

`azure-storage-container-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Container to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-delete container_name="xsoar"```

#### Human Readable Output

>Container xsoar successfully deleted.

### azure-storage-container-blob-list
***
List Blobs under the specified container.


#### Base Command

`azure-storage-container-blob-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Container. | Required | 
| limit | Number of blobs to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only blobs whose names begin with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageContainer.Container.Blob.name | String | Blob name. | 
| AzureStorageContainer.Container.name | String | Container name. | 


#### Command Example
```!azure-storage-container-blob-list container_name="xsoar"```

#### Context Example
```json
{
    "AzureStorageContainer": {
        "Container": {
            "Blob": [
                {
                    "name": "xsoar.txt"
                }
            ],
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### xsoar Container Blobs List:
> Current page size: 50
> Showing page 1 out others that may exist
>|Name|
>|---|
>| xsoar.txt |


### azure-storage-container-blob-create
***
Create a new Blob under the specified Container.


#### Base Command

`azure-storage-container-blob-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| file_entry_id | XSOAR file entry ID. | Required | 
| blob_name | The name of the Blob to create. Default is XSOAR file name. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-create container_name="xsoar" file_entry_id=""XXXX" blob_name="xsoar.txt"```

#### Human Readable Output

>Blob successfully created.

### azure-storage-container-blob-update
***
Update the content of an existing Blob.


#### Base Command

`azure-storage-container-blob-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| file_entry_id | XSOAR file entry ID. | Required | 
| blob_name | The name of the Blob to update. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-update container_name="xsoar" file_entry_id="XXXX" blob_name="xsoar.txt"```

#### Human Readable Output

>Blob xsoar.txt successfully updated.

### azure-storage-container-blob-get
***
Retrieve Blob from Container.


#### Base Command

`azure-storage-container-blob-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| blob_name | The name of the Blob to retrieve. | Required | 


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
```!azure-storage-container-blob-get container_name="xsoar" blob_name="xsoar.txt"```

#### Context Example
```json
{
    "File": {
        "EntryID": "XXXX",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "0851a698747621af9d8f7c66ae5c361f",
        "Name": "xsoar.txt",
        "SHA1": "1ab557b3f2e8cf975902b881dee5c162fed32339",
        "SHA256": "5b5e9535b6415794e2a483097c74f917f7855ca27e28f96a57dc4e1313778064",
        "SHA512": "d41dbfa5eda143025450dd1af92375f154378658daec30451d14dac23135bbfb5250f04f21381fac76504b8cf98eade4996f829b73c02fca802c04e031b0c4d8",
        "SSDeep": "768:/NRxnYun56IhNMbGCZ4ewD+pdX8qdF8tdjXLxfcrjxzvLImTFvFbX214Rs:PXfmGjyph8S8t29vLIMFvFZ+",
        "Size": 52575,
        "Type": "PDF document, version 1.5"
    }
}
```

#### Human Readable Output



### azure-storage-container-blob-tag-get
***
Retrieve the tags of the specified Blob.


#### Base Command

`azure-storage-container-blob-tag-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| blob_name | The name of the blob. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageContainer.Container.Blob.Tag.Key | String | Tag key. | 
| AzureStorageContainer.Container.Blob.Tag.Value | String | Tag value. | 
| AzureStorageContainer.Container.Blob.name | String | Blob name. | 
| AzureStorageContainer.Container.name | String | Container name. | 


#### Command Example
```!azure-storage-container-blob-tag-get container_name="xsoar" blob_name="xsoar.txt"```

#### Context Example
```json
{
    "AzureStorageContainer": {
        "Container": {
            "Blob": {
                "Tag": [
                    {
                        "Key": "tag-name-1",
                        "Value": "tag-value-1"
                    }
                ],
                "name": "xsoar.txt"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Blob xsoar.txt Tags:
>|Key|Value|
>|---|---|
>| tag-name-1 | tag-value-1 |


### azure-storage-container-blob-tag-set
***
Sets the tags for the specified Blob. The command replace the entire tags of the Blob and can be used to remove tags.


#### Base Command

`azure-storage-container-blob-tag-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| blob_name | The name of the blob. | Required | 
| tags | Tags fields in JSON format: {"tag-name-1": "tag-value-1", "tag-name-2": "tag-value-2"}. The tags fields may contain at most 10 tags. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-tag-set container_name="xsoar" blob_name="xsoar.txt" tags=`{ "tag-name-1": "tag-value-1" }````

#### Human Readable Output

>xsoar.txt Tags successfully updated.

### azure-storage-container-blob-delete
***
Marks the specified Blob for deletion. The Blob will be deleted during garbage collection.


#### Base Command

`azure-storage-container-blob-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| blob_name | The name of the Blob to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-delete container_name="xsoar" blob_name="xsoar.txt"```

#### Human Readable Output

>Blob xsoar.txt successfully deleted.

### azure-storage-container-blob-property-get
***
Retrieve Blob properties.


#### Base Command

`azure-storage-container-blob-property-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| blob_name | The name of the blob. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageContainer.Container.Blob.Property.last_modified | Date | Last modified time of the blob. | 
| AzureStorageContainer.Container.Blob.Property.etag | String | The entity tag for the blob. | 
| AzureStorageContainer.Container.Blob.Property.lease_status | String | The lease status of the blob. | 
| AzureStorageContainer.Container.Blob.Property.lease_state | String | The lease state of the blob. | 
| AzureStorageContainer.Container.Blob.Property.blob_type | String | The blob type. | 
| AzureStorageContainer.Container.Blob.Property.content_length | Number | The size of the blob in bytes. | 
| AzureStorageContainer.Container.Blob.Property.content_type | String | The content type specified for the blob. If no content type was specified, the default content type is application/octet-stream. | 
| AzureStorageContainer.Container.Blob.Property.content-md5 | String | The MD5 hash of the blob content. | 
| AzureStorageContainer.Container.Blob.Property.creation_time | Date | The date at which the blob was created. | 
| AzureStorageContainer.Container.Blob.name | String | Blob name. | 


#### Command Example
```!azure-storage-container-blob-property-get container_name="xsoar" blob_name="xsoar.txt"```

#### Context Example
```json
{
    "AzureStorageContainer": {
        "Container": {
            "Blob": {
                "Property": {
                    "accept_ranges": "bytes",
                    "access_tier": "Hot",
                    "access_tier_inferred": "true",
                    "blob_type": "BlockBlob",
                    "content_length": "52575",
                    "content_md5": "CFGmmHR2Ia+dj3xmrlw2Hw==",
                    "content_type": "application/octet-stream",
                    "creation_time": "2021-09-23T11:17:30",
                    "date": "2021-09-23T11:17:43",
                    "etag": "\"0x8D97E83BFC44D27\"",
                    "last_modified": "2021-09-23T11:17:37",
                    "lease_state": "available",
                    "lease_status": "unlocked",
                    "request_id": "94de3d85-901e-0022-776c-b0d52b000000",
                    "server": "Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0",
                    "server_encrypted": "true",
                    "version": "2020-10-02"
                },
                "name": "xsoar.txt"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Blob xsoar.txt Properties:
>|Creation Time|Last Modified|Content Length|Content Type|Etag|
>|---|---|---|---|---|
>| 2021-09-23T11:17:30 | 2021-09-23T11:17:37 | 52575 | application/octet-stream | "0x8D97E83BFC44D27" |


### azure-storage-container-blob-property-set
***
Set Blob properties.


#### Base Command

`azure-storage-container-blob-property-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 
| blob_name | The name of the blob. | Required | 
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
```!azure-storage-container-blob-property-set container_name="xsoar" blob_name="xsoar.txt" content_type="text/plain"```

#### Human Readable Output

>Blob xsoar.txt properties successfully updated.
