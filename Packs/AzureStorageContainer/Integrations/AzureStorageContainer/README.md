# Azure Storage Container
Create and Manage Azure Storage Container services.
This integration was integrated and tested with version "2020-10-02" of Azure Storage Container

## Configure Azure Storage Container in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Storage account name | True |
| Account SAS Token | False |
| Use Azure Managed Identities | False |
| Azure Managed Identities Client ID | False |   
| Shared Key | False |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |


## ## Shared Access Signatures Information (SAS)
* The required SAS token for this integration should be taken at the **storage account level and not at container level**.

## Shared Access Signatures (SAS) Permissions
In order to use the integration use-cases, 
please make sure your SAS token contains the following permissions:
  1. 'Blob' and 'File' service.
  2. 'Service', 'Container' and 'Object' resource types.
  3. 'Read', 'Write', 'Delete', 'List', 'Create', 'Add', 'Update' and 'Immutable storage' permissions.
  4. 'Blob versioning permissions'
## Shared Key Permissions
To set the AllowSharedKeyAccess property for an Azure Storage account, a user needs to have the permissions to create and manage storage accounts.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| container_name | The name of the Container to create. Rules for naming containers can be found here:<br/>https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata<br/>. | Required | 


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
                "date": "2021-11-28T12:43:05",
                "default_encryption_scope": "$account-encryption-key",
                "deny_encryption_scope_override": "false",
                "etag": "\"0x8D9B26C9BBF026C\"",
                "has_immutability_policy": "false",
                "has_legal_hold": "false",
                "immutable_storage_with_versioning_enabled": "false",
                "last_modified": "2021-11-28T12:42:58",
                "lease_state": "available",
                "lease_status": "unlocked",
                "request_id": "00a9c6bf-f01e-007a-5255-e448bd000000",
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
>| 2021-11-28T12:42:58 | "0x8D9B26C9BBF026C" | unlocked | available | false | false |


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
| file_entry_id | The entry ID of the file to upload as a new blob. Available from XSOAR war room while the context data contains file output. | Required | 
| blob_name | The name of the Blob to create. Default is XSOAR file name. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-create container_name="xsoar" file_entry_id="16488@b5e40781-86c8-4799-8f10-ace443e93234" blob_name="xsoar.txt"```

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
| file_entry_id | The entry ID of the file to upload as a new blob. Available from XSOAR war room while the context data contains file output. | Required | 
| blob_name | The name of the Blob to update. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-update container_name="xsoar" file_entry_id="16488@b5e40781-86c8-4799-8f10-ace443e93234" blob_name="xsoar.txt"```

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
        "EntryID": "16508@b5e40781-86c8-4799-8f10-ace443e93234",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "950eb0708854a661313dd150a643af8b",
        "Name": "xsoar.txt",
        "SHA1": "2f82d9a13f948a1ced93f9da85323d45fb2eedf8",
        "SHA256": "150296c0c1a1ca044fc132010b6049342c460f4a68386ab24de9b6a167e54765",
        "SHA512": "6d9deaacce47943767d19c8de846c9e57692543c90b4f45c3abbe4123380bd1665dc4bd9b4d0a99d09d3a0f8c67da842826181834223362f1c75f5f9e6c358ef",
        "SSDeep": "3:h8Kpl:Rpl",
        "Size": 11,
        "Type": "ASCII text, with no line terminators"
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
                    "content_length": "11",
                    "content_md5": "lQ6wcIhUpmExPdFQpkOviw==",
                    "content_type": "application/octet-stream",
                    "creation_time": "2021-11-28T12:43:09",
                    "date": "2021-11-28T12:43:24",
                    "etag": "\"0x8D9B26CA6AD74B3\"",
                    "last_modified": "2021-11-28T12:43:17",
                    "lease_state": "available",
                    "lease_status": "unlocked",
                    "request_id": "8f64c941-501e-0097-4255-e403f0000000",
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
>| 2021-11-28T12:43:09 | 2021-11-28T12:43:17 | 11 | application/octet-stream | "0x8D9B26CA6AD74B3" |


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
| content_type | Blob content type. Indicates the media type of the blob. | Optional | 
| content_md5 | Blob MD5 hash value. Can be used by the client to check for content integrity. | Optional | 
| content_encoding | Blob content encoding. Used to specify the compression algorithm of the blob content. | Optional | 
| content_language | Blob content language. Describes the human languages of the blob content. | Optional | 
| content_disposition | Blob content disposition. Conveys additional information about how to process the response payload, and also can be used to attach additional metadata. | Optional | 
| cache_control | Modifies the cache control string for the blob. Indicates directives for caching in both requests and responses. | Optional | 
| request_id | Request ID generated by the client and recorded in the analytics logs when storage analytics logging is enabled. | Optional | 
| lease_id | Required if the blob has an active lease. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-blob-property-set container_name="xsoar" blob_name="xsoar.txt" content_type="text/plain"```

#### Human Readable Output

>Blob xsoar.txt properties successfully updated.

### azure-storage-container-sas-create

***
Retrieve Blob properties.


#### Base Command

`azure-storage-container-sas-create`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                        | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| container_name | The name of the Blob Container.                                                                                                                                                                                                                                                        | Required | 
| expiry_time | Expiry time for sas token(hours).                                                                                                                                                                                                                                                      | Required | 
| signed_resources | specifies which resources are accessible via the shared access signature. Options available c(container), b(blob), bv(blob version),bs(blob snapshot),d(directory)                                                                                                                     | Required | 
| signed_permissions | The permissions that are associated with the shared access signature. The user is restricted to operations that are allowed by the permissions. Possible permission: r = Read, a=access, c=create, w=write. Also must follow the  this order "racwdxltmeop"Example: r,c,a,w,rac, racw. | Required | 
| signed_ip | specifies a public IP address or a range of public IP addresses from which to accept requests.                                                                                                                                                                                         | Required |
| account_key | The account key to create the SAS token with.                                                                                                                                                                                         |  |

#### Command Example
```!azure-storage-container-sas-create account_key="TestAccountKey" expiry_time="1" signed_resources="test signed_permissions="test signed_ip="127.0.0.1"```

### azure-storage-container-block-public-access
***
Block public access to a container..


#### Base Command

`azure-storage-container-block-public-access`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| container_name | The name of the Blob Container. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-container-block-public-access container_name="xsoar"```

#### Human Readable Output

>xsoar.txt Public access to container '{container_name}' has been successfully blocked.
