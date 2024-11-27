# Azure Storage FileShare
Create and Manage Azure FileShare Files and Directories.
This integration was integrated and tested with version "2020-10-02" of Azure Storage FileShare

## Configure Azure Storage FileShare in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Storage account name | True |
| Account SAS Token | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Shared Access Signatures (SAS) Permissions
In order to use the integration use-cases, 
please make sure your SAS token contains the following permissions:
  1. 'File' and 'Blob' services.
  2. 'Service', 'Container' and 'Object' resource types.
  3. 'Read', 'Write', 'Delete', 'List', 'Create', 'Add', 'Update' and 'Immutable storage' permissions.
  4. 'Blob versioning permissions'
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-storage-fileshare-create
***
Create a new Azure file share under the specified account.


#### Base Command

`azure-storage-fileshare-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the new Share to create. Rules for naming shares can be found here: https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-shares--directories--files--and-metadata. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshare-create share_name="test-xsoar"```

#### Human Readable Output

>Share test-xsoar successfully created.

### azure-storage-fileshare-delete
***
Delete file share under the specified account.


#### Base Command

`azure-storage-fileshare-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the Share to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshare-delete share_name="test-xsoar"```

#### Human Readable Output

>Share test-xsoar successfully deleted.

### azure-storage-fileshare-list
***
list Azure file shares under the specified account.


#### Base Command

`azure-storage-fileshare-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of shares to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only shares whose name begins with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageFileShare.Share.Name | String | Share name. | 


#### Command Example
```!azure-storage-fileshare-list prefix="test-xsoar" limit="1"```

#### Context Example
```json
{
    "AzureStorageFileShare": {
        "Share": {
            "Name": "test-xsoar"
        }
    }
}
```

#### Human Readable Output

>### Shares List:
> Current page size: 1
> Showing page 1 out others that may exist
>|Name|
>|---|
>| test-xsoar |


### azure-storage-fileshare-content-list
***
List files and directories under the specified share or directory.


#### Base Command

`azure-storage-fileshare-content-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prefix | Filters the results to return only files and directories whose name begins with the specified prefix. | Optional | 
| limit | Number of directories and files to retrieve. Default is 50. Default is 50. | Optional | 
| share_name | The name of the Share in which the directories ans files are located. | Required | 
| directory_path | The path to the parent directory of the directories and files to retrieve. A path name is composed of one or more directory name components separated by the forward-slash (/) character. If the parent directory path is omitted, the directory will be referred to the first level of the specified share. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageFileShare.Share.Name | String | Share name. | 
| AzureStorageFileShare.Share.Content.Path | String | Directory path.. | 
| AzureStorageFileShare.Share.Content.DirectoryId | String | Directory ID. | 
| AzureStorageFileShare.Share.Content.File.FileId | String | File ID. | 
| AzureStorageFileShare.Share.Content.File.Name | String | File name. | 
| AzureStorageFileShare.Share.Content.File.Property.Content-Length | String | File size in bytes. | 
| AzureStorageFileShare.Share.Content.File.Property.CreationTime | Date | File creation time. | 
| AzureStorageFileShare.Share.Content.File.Property.LastAccessTime | Date | File last access time. | 
| AzureStorageFileShare.Share.Content.File.Property.LastWriteTime | Date | File last write time. | 
| AzureStorageFileShare.Share.Content.File.Property.ChangeTime | Date | File change time. | 
| AzureStorageFileShare.Share.Content.File.Property.Last-Modified | Date | File last modified time. | 
| AzureStorageFileShare.Share.Content.Directory.FileId | String | Directory ID. | 
| AzureStorageFileShare.Share.Content.Directory.Name | String | Directory name. | 
| AzureStorageFileShare.Share.Content.Directory.Property.CreationTime | Date | File creation time. | 
| AzureStorageFileShare.Share.Content.Directory.Property.LastAccessTime | Date | File last access time. | 
| AzureStorageFileShare.Share.Content.Directory.Property.LastWriteTime | Date | File last write time. | 
| AzureStorageFileShare.Share.Content.Directory.Property.ChangeTime | Date | File change time. | 
| AzureStorageFileShare.Share.Content.Directory.Property.Last-Modified | Date | File last modified time. | 


#### Command Example
```!azure-storage-fileshare-content-list limit="50" share_name="myfileshare" directory_path="mydirectorytest" page="1"```

#### Context Example
```json
{
    "AzureStorageFileShare": {
        "Share": {
            "Content": {
                "Directory": [
                    {
                        "FileId": "13835084443561230336",
                        "Name": "tttttt",
                        "Property": {
                            "ChangeTime": "2021-08-12T07:11:50",
                            "CreationTime": "2021-08-12T07:11:50",
                            "Last-Modified": "2021-08-12T07:11:50",
                            "LastAccessTime": "2021-08-12T07:11:50",
                            "LastWriteTime": "2021-08-12T07:11:50"
                        }
                    },
                    {
                        "FileId": "16140971433240035328",
                        "Name": "yehuda123",
                        "Property": {
                            "ChangeTime": "2021-08-06T13:44:04",
                            "CreationTime": "2021-08-06T13:44:04",
                            "Last-Modified": "2021-08-06T13:44:04",
                            "LastAccessTime": "2021-08-06T13:44:04",
                            "LastWriteTime": "2021-08-06T13:44:04"
                        }
                    }
                ],
                "DirectoryId": "11529285414812647424",
                "File": [
                    {
                        "FileId": "13835137220119363584",
                        "Name": "testepoccreation.txt",
                        "Property": {
                            "ChangeTime": "2021-08-12T05:26:11",
                            "Content-Length": "11",
                            "CreationTime": "2021-08-12T05:26:11",
                            "Last-Modified": "2021-08-15T09:39:17",
                            "LastAccessTime": "2021-08-12T05:26:11",
                            "LastWriteTime": "2021-08-12T05:26:11"
                        }
                    },
                    {
                        "FileId": "13835060254305419264",
                        "Name": "testsasss.txt",
                        "Property": {
                            "ChangeTime": "2021-08-15T09:44:16",
                            "Content-Length": "11",
                            "CreationTime": "2021-08-15T09:44:16",
                            "Last-Modified": "2021-08-15T09:44:16",
                            "LastAccessTime": "2021-08-15T09:44:16",
                            "LastWriteTime": "2021-08-15T09:44:16"
                        }
                    }
                ],
                "Path": "mydirectorytest"
            },
            "Name": "myfileshare"
        }
    }
}
```

#### Human Readable Output

>Directories and Files List:
> Current page size: 50
> Showing page 1 out others that may exist
>### Directories:
>|Name|File Id|
>|---|---|
>| tttttt | 13835084443561230336 |
>| yehuda123 | 16140971433240035328 |
>
>### Files:
>|Name|File Id|
>|---|---|
>| testepoccreation.txt | 13835137220119363584 |
>| testsasss.txt | 13835060254305419264 |


### azure-storage-fileshare-directory-create
***
Create a new directory under the specified share or parent directory.


#### Base Command

`azure-storage-fileshare-directory-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the Share in which the new directory will be created. | Required | 
| directory_name | The name of the new directory. | Required | 
| directory_path | The path to the parent directory where the new directory will be created. A path name is composed of one or more directory name components separated by the forward-slash (/) character. If the parent directory path is omitted, the directory will be referred to the first level of the specified share. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshare-directory-create share_name="test-xsoar" directory_name="xsoar-directory"```

#### Human Readable Output

>xsoar-directory Directory successfully created in test-xsoar.

### azure-storage-fileshare-directory-delete
***
Delete the specified empty directory. Note that the directory must be empty before it can be deleted.


#### Base Command

`azure-storage-fileshare-directory-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the Share in which the directory is located. | Required | 
| directory_name | The name of the directory to delete. | Required | 
| directory_path | The path to the parent directory of the directory to delete. A path name is composed of one or more directory name components separated by the forward-slash (/) character. If the parent directory path is omitted, the directory will be referred to the first level of the specified share. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshare-directory-delete share_name="test-xsoar" directory_name="xsoar-directory"```

#### Human Readable Output

>xsoar-directory Directory successfully deleted from test-xsoar.

### azure-storage-fileshare-file-create
***
Creates a new file in Share.


#### Base Command

`azure-storage-fileshare-file-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the Share in which the new file will be created. | Required | 
| file_entry_id | The entry ID of the file to upload as a new file. Available from XSOAR war room while the context data contains file output. | Required | 
| directory_path | The path to the parent directory where the new file will be created. A path name is composed of one or more directory name components separated by the forward-slash (/) character. If the parent directory path is omitted, the directory will be created within first level of the specified share. | Optional | 
| file_name | The name of the new file to create. Default is XSOAR file name. The file suffix should be specified. for example: test.txt. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshare-file-create share_name="test-xsoar" directory_path="xsoar-directory" file_name="AzureStorage.txt" file_entry_id="16488@b5e40781-86c8-4799-8f10-ace443e93234"```

#### Human Readable Output

>File successfully created in test-xsoar.

### azure-storage-fileshare-file-get
***
Retrieve file from Share.


#### Base Command

`azure-storage-fileshare-file-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the Share in which the file is located. | Required | 
| file_name | The name of the file to retrieve. The file suffix should be specified. for example: test.txt. | Required | 
| directory_path | The path to the parent directory of the file to retrieve. A path name is composed of one or more directory name components separated by the forward-slash (/) character. If the parent directory path is omitted, the directory will be referred to the first level of the specified share. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 


#### Command Example
```!azure-storage-fileshare-file-get share_name="test-xsoar" file_name="AzureStorage.txt" directory_path="xsoar-directory"```

#### Context Example
```json
{
    "File": {
        "EntryID": "16572@b5e40781-86c8-4799-8f10-ace443e93234",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "950eb0708854a661313dd150a643af8b",
        "Name": "AzureStorage.txt",
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



### azure-storage-fileshare-file-delete
***
Delete file from Share.


#### Base Command

`azure-storage-fileshare-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | The name of the Share in which the file is located. | Required | 
| file_name | The name of the file to delete. The file suffix should be specified. for example: test.txt. | Required | 
| directory_path | The path to the parent directory of the file to delete. A path name is composed of one or more directory name components separated by the forward-slash (/) character. If the parent directory path is omitted, the directory will be referred to the first level of the specified share. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshare-file-delete share_name="test-xsoar" file_name="AzureStorage.txt" directory_path="xsoar-directory"```

#### Human Readable Output

>File AzureStorage.txt successfully deleted from test-xsoar.