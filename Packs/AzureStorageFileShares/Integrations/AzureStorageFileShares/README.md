# Azure Storage FileShares
Create and Manage Azure FileShares Files and Directories.
This integration was integrated and tested with version "2020-10-02" of Azure Storage FileShares

## Configure Azure Storage FileShares on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Storage FileShares.
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
### azure-storage-fileshares-share-create
***
Create a new Azure file share under the specified account.


#### Base Command

`azure-storage-fileshares-share-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshares-share-create share_name="test-xsoar"```

#### Human Readable Output

>Shared test-xsoar successfully created.

### azure-storage-fileshares-share-delete
***
Delete file share under the specified account.


#### Base Command

`azure-storage-fileshares-share-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshares-share-delete share_name="test-xsoar"```

#### Human Readable Output

>Shared test-xsoar successfully deleted.

### azure-storage-fileshares-share-list
***
list Azure file shares under the specified account.


#### Base Command

`azure-storage-fileshares-share-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of shares to retrieve. Default is 50. Default is 50. | Optional | 
| prefix | Filters the results to return only shares whose name begins with the specified prefix. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageFileShares.Share.Name | String | Share name. | 


#### Command Example
```!azure-storage-fileshares-share-list prefix="test-xsoar" limit="1"```

#### Context Example
```json
{
    "AzureStorageFileShares": {
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


### azure-storage-fileshares-directory-file-list
***
List files and directories under the specified share or directory.


#### Base Command

`azure-storage-fileshares-directory-file-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prefix | Filters the results to return only files and directories whose name begins with the specified prefix. | Optional | 
| limit | Number of directories and files to retrieve. Default is 50. Default is 50. | Optional | 
| share_name | Share name. | Required | 
| directory_path | The path to the directory. | Optional | 
| page | Page number. Default is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureStorageFileShares.Directory.DirectoryId | String | Directory ID. | 
| AzureStorageFileShares.Directory.File.FileId | String | File ID. | 
| AzureStorageFileShares.Directory.File.Name | String | File name. | 
| AzureStorageFileShares.Directory.File.Properties.Content-Length | String | File size in bytes. | 
| AzureStorageFileShares.Directory.File.Properties.CreationTime | Date | File creation time. | 
| AzureStorageFileShares.Directory.File.Properties.LastAccessTime | Date | File last access time. | 
| AzureStorageFileShares.Directory.File.Properties.LastWriteTime | Date | File last write time. | 
| AzureStorageFileShares.Directory.File.Properties.ChangeTime | Date | File change time. | 
| AzureStorageFileShares.Directory.File.Properties.Last-Modified | Date | File last modified time. | 
| AzureStorageFileShares.Directory.Directory.FileId | String | Directory ID. | 
| AzureStorageFileShares.Directory.Directory.Name | String | Directory name. | 
| AzureStorageFileShares.Directory.Directory.Properties.CreationTime | Date | File creation time. | 
| AzureStorageFileShares.Directory.Directory.Properties.LastAccessTime | Date | File last access time. | 
| AzureStorageFileShares.Directory.Directory.Properties.LastWriteTime | Date | File last write time. | 
| AzureStorageFileShares.Directory.Directory.Properties.ChangeTime | Date | File change time. | 
| AzureStorageFileShares.Directory.Directory.Properties.Last-Modified | Date | File last modified time. | 
| AzureStorageFileShares.Directory.share_name | String | Share name. | 
| AzureStorageFileShares.Directory.path | String | Directory path. | 


#### Command Example
```!azure-storage-fileshares-directory-file-list share_name="test-xsoar"```

#### Context Example
```json
{
    "AzureStorageFileShares": {
        "Directory": {
            "Directory": [
                {
                    "FileId": "XXXX",
                    "Name": "xsoar-directory",
                    "Properties": {
                        "ChangeTime": "2021-08-26T14:44:03",
                        "CreationTime": "2021-08-26T14:44:03",
                        "Last-Modified": "2021-08-26T14:44:03",
                        "LastAccessTime": "2021-08-26T14:44:03",
                        "LastWriteTime": "2021-08-26T14:44:03"
                    }
                }
            ],
            "DirectoryId": "XXXX",
            "File": [],
            "path": "",
            "share_name": "test-xsoar"
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
>| xsoar-directory | XXXX |
>
>### Files:
>**No entries.**


### azure-storage-fileshares-directory-create
***
Create a new directory under the specified share or parent directory.


#### Base Command

`azure-storage-fileshares-directory-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 
| directory_name | New directory name. | Required | 
| directory_path | The path to the parent directory where the new directory will be created. If the parent directory path is omitted, the directory will be created within the specified share. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshares-directory-create share_name="test-xsoar" directory_name="xsoar-directory"```

#### Human Readable Output

>xsoar-directory Directory successfully created.

### azure-storage-fileshares-directory-delete
***
Delete the specified empty directory. Note that the directory must be empty before it can be deleted.


#### Base Command

`azure-storage-fileshares-directory-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 
| directory_name | The directory name to delete. | Required | 
| directory_path | The path to the parent directory. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshares-directory-delete share_name="test-xsoar" directory_name="xsoar-directory"```

#### Human Readable Output

>xsoar-directory Directory successfully deleted.

### azure-storage-fileshares-file-create
***
Creates a new file in Share.


#### Base Command

`azure-storage-fileshares-file-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 
| file_entry_id | XSOAR file entry ID. | Required | 
| directory_path | The path to the directory where the file should be created.If the directory path is omitted, the file will be created within the specified share. | Optional | 
| file_name | File name.Default is XSOAR file name. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshares-file-create share_name="test-xsoar" directory_path="xsoar-directory" file_name="AzureStorage_image.png" file_entry_id="XXXX"```

#### Human Readable Output

>File successfully created.

### azure-storage-fileshares-file-get
***
Get file from Share.


#### Base Command

`azure-storage-fileshares-file-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 
| file_name | File name. | Required | 
| directory_path | The path to the file directory. | Optional | 


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
```!azure-storage-fileshares-file-get share_name="test-xsoar-1" file_name="test.png"```

#### Context Example
```json
{
    "File": {
        "EntryID": "XXXX",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "3695f84101979143f602e152c7e916d9",
        "Name": "test.png",
        "SHA1": "6f15a7042cd94a3ed0315df6f20c6808cb7ff9b3",
        "SHA256": "2a02d678269b1c68087be91cf16b80e90bebd6a79f71be04094ac2d20629c90c",
        "SHA512": "b278526019b60d5c36fa854aded8d8a52d6ae4f454960d1d7fb67391a411659763722a41c81638375acf40f8bdb6f740ab53de6d406c015ae556901231933977",
        "SSDeep": "96:8SiS3cO2n/MWu4gGW0LR3wx1gAnFVJ/Ow5:8SDc/LlgGVd3wYAP8w5",
        "Size": 3523,
        "Type": "PNG image data, 120 x 50, 8-bit/color RGBA, non-interlaced"
    }
}
```

#### Human Readable Output



### azure-storage-fileshares-file-delete
***
Delete file from Share.


#### Base Command

`azure-storage-fileshares-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| share_name | Share name. | Required | 
| file_name | File name. | Required | 
| directory_path | The path to the file directory. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-storage-fileshares-file-delete share_name="test-xsoar" file_name="AzureStorage_image.png" directory_path="xsoar-directory"```

#### Human Readable Output

>File AzureStorage_image.png successfully deleted.
