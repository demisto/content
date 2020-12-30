## Overview

---

Microsoft Graph lets your app get an authorized access to files in OneDrive, SharePoint and MS Teams across all organization. (requires admin consent).

## Authentication
---
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

### Required Permissions
1. Directory.Read.All - Delegated
2. Files.ReadWrite.All - Application
3. Files.ReadWrite.All - Delegated
4. Sites.ReadWrite.All - Application
5. Sites.ReadWrite.All - Delegated
6. User.Read - Delegated

## Configure Microsoft Graph Files on Demisto


1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Microsoft_Graph_Files.
3. Click __Add instance__ to create and configure a new integration instance.
   - __Name__: a textual name for the integration instance.
   - __Server URL__
   - __ID (received from the admin consent - see Detailed Instructions)__
   - __Token (received from the admin consent - see Detailed Instructions)__
   - __Key (received from the admin consent - see Detailed Instructions)__
   - __Trust any certificate (not secure)__
   - __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands

---

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. msgraph-delete-file
2. msgraph-upload-new-file
3. msgraph-replace-existing-file
4. msgraph-create-new-folder
5. msgraph-list-drives-in-site
6. msgraph-list-drive-content
7. msgraph-list-share-point-sites
8. msgraph-download-file

### 1. msgraph-delete-file

---

Delete a DriveItem by using its ID

##### Required Permissions

    Files.ReadWrite.All

##### Base Command

`msgraph-delete-file`

##### Input

| **Argument Name** | **Description**       | **Required** |
| ----------------- | --------------------- | ------------ |
| object_type       | MS Graph resource.    | Required     |
| object_type_id    | MS Graph resource id. | Required     |
| item_id           | Ms Graph item_id.     | Required     |


##### Context Output

There is no context output for this command.

##### Command Example

```!msgraph-delete-file object_type=drives object_type_id=test item_id=test```

##### Human Readable Output

### MsGraphFiles - File information:

| 123 |
| ---------------------------------- |
| Item was deleted successfully      |


### 2. msgraph-upload-new-file

---

Uploads a file from Demisto to MS Graph resource

##### Required Permissions

    Files.ReadWrite.All

##### Base Command

`msgraph-upload-new-file`

##### Input

| **Argument Name** | **Description**                            | **Required** |
| ----------------- | ------------------------------------------ | ------------ |
| object_type       | MS Graph resource.                         | Required     |
| object_type_id    | MS Graph resource id.                      | Required     |
| parent_id         | An ID of the folder to upload the file to. | Required     |
| file_name         | A file name for the uploaded file.         | Required     |
| entry_id          | Desmito entry ID of the file               | Required     |


##### Context Output

| **Path**                                                     | **Type** | **Description**                                              |
| ------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| MsGraphFiles.UploadedFiles.ParentReference.DriveId           | String   | Unique identifier of the drive that contains the item.       |
| MsGraphFiles.UploadedFiles.ParentReference.DriveType         | String   | Identifies the type of drive.                                |
| MsGraphFiles.UploadedFiles.ParentReference.ID                | String   | Unique identifier of the item in the drive.                  |
| MsGraphFiles.UploadedFiles.ParentReference.Path              | String   | Path to navigate to the item                                 |
| MsGraphFiles.UploadedFiles.LastModifiedDateTime              | String   | Date and time that the item was last modified.               |
| MsGraphFiles.UploadedFiles.File.MimeType                     | String   | File type                                                    |
| MsGraphFiles.UploadedFiles.File.Hashes                       | String   | Hash type                                                    |
| MsGraphFiles.UploadedFiles.CreatedDateTime                   | String   | Timestamp of item creation.                                  |
| MsGraphFiles.UploadedFiles.WebUrl                            | String   | URL to the resource in the browser                           |
| MsGraphFiles.UploadedFiles.OdataContext                      | String   | OData query                                                  |
| MsGraphFiles.UploadedFiles.FileSystemInfo.CreatedDateTime    | String   | The date and time the item was created on a client.          |
| MsGraphFiles.UploadedFiles.FileSystemInfo.LastModifiedDateTime | String   | The date and time the item was last modified on a client.    |
| MsGraphFiles.UploadedFiles.LastModifiedBy.DisplayName        | String   | The item display name                                        |
| MsGraphFiles.UploadedFiles.LastModifiedBy.Type               | String   | Application, user or device                                  |
| MsGraphFiles.UploadedFiles.CreatedBy.DisplayName             | String   | Identity of the user, device,or application which created the item |
| MsGraphFiles.UploadedFiles.CreatedBy.ID                      | String   | The ID of the creator                                        |
| MsGraphFiles.UploadedFiles.CreatedBy.Type                    | String   | Application, user or device                                  |
| MsGraphFiles.UploadedFiles.DownloadUrl                       | String   | URL to download this file's content                          |
| MsGraphFiles.UploadedFiles.Size                              | Number   | File's size                                                  |
| MsGraphFiles.UploadedFiles.ID                                | String   | File ID                                                      |
| MsGraphFiles.UploadedFiles.Name                              | String   | The file's name                                              |
| MsGraph.UploadedFiles.File                                   | String   | Graph's file object                                          |


##### Command Example

```!msgraph-upload-new-file object_type=drives object_type_id=123 parent_id=123 file_name="test.txt" entry_id=123```

##### Context Example

```
{
    "MsGraphFiles.UploadedFiles": {
        "ParentReference": {
            "DriveId": "test", 
            "DriveType": "documentLibrary", 
            "ID": "test", 
            "Path": "test"
        }, 
        "LastModifiedBy": {
            "Type": "Application", 
            "DisplayName": "Microsoft Graph", 
            "ID": "test"
        }, 
        "LastModifiedDateTime": "2020-01-22T20:03:00Z", 
        "CreatedBy": {
            "Type": "Application", 
            "DisplayName": "Microsoft Graph", 
            "ID": "test"
        }, 
        "CreatedDateTime": "2020-01-22T20:03:00Z", 
        "WebUrl": "test", 
        "FileSystemInfo": {
            "CreatedDateTime": "2020-01-22T20:03:00Z", 
            "LastModifiedDateTime": "2020-01-22T20:03:00Z"
        }, 
        "DownloadUrl": "test", 
        "File": {
            "MimeType": "text/plain", 
            "Hashes": {
                "QuickXorHash": "test"
            }
        }, 
        "OdataContext": "test", 
        "Size": 15, 
        "ID": "test", 
        "Name": "test.txt"
    }
}
```

##### Human Readable Output

### MsGraphFiles - File information:

| CreatedBy       | CreatedDateTime      | ID   | LastModifiedBy  | Name     | Size | WebUrl |
| --------------- | -------------------- | ---- | --------------- | -------- | ---- | ------ |
| Microsoft Graph | 2020-01-22T20:03:00Z | Test | Microsoft Graph | test.txt | 15   | Test   |


### 3. msgraph-replace-existing-file

---

Replace file context in MS Graph resource

##### Required Permissions

    Files.ReadWrite.All
    Sites.ReadWrite.All

##### Base Command

`msgraph-replace-existing-file`

##### Input

| **Argument Name** | **Description**        | **Required** |
| ----------------- | ---------------------- | ------------ |
| object_type       | MS Graph resource.     | Required     |
| object_type_id    | MS Graph resource id.  | Required     |
| item_id           | Ms Graph item_id.      | Required     |
| entry_id          | Demisto file entry id. | Required     |


##### Context Output

| **Path**                                                     | **Type** | **Description**                                              |
| ------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| MsGraphFiles.ReplacedFiles.ParentReference.DriveId           | String   | Unique identifier of the drive that contains the item.       |
| MsGraphFiles.ReplacedFiles.ParentReference.DriveType         | String   | Identifies the type of drive.                                |
| MsGraphFiles.ReplacedFiles.ParentReference.ID                | String   | Unique identifier of the item in the drive.                  |
| MsGraphFiles.ReplacedFiles.ParentReference.Path              | String   | Path to navigate to the item                                 |
| MsGraphFiles.ReplacedFiles.LastModifiedDateTime              | Date     | Date and time that the item was last modified.               |
| MsGraphFiles.ReplacedFiles.File.MimeType                     | String   | File type                                                    |
| MsGraphFiles.ReplacedFiles.File.Hashes                       | String   | Hash type                                                    |
| MsGraphFiles.ReplacedFiles.CreatedDateTime                   | String   | Timestamp of item creation                                   |
| MsGraphFiles.ReplacedFiles.WebUrl                            | String   | URL to the resource in the browser                           |
| MsGraphFiles.ReplacedFiles.OdataContext                      | String   | OData query                                                  |
| MsGraphFiles.ReplacedFiles.FileSystemInfo.CreatedDateTime    | Date     | The date and time the item was created on a client           |
| MsGraphFiles.ReplacedFiles.FileSystemInfo.LastModifiedDateTime | Date     | The date and time the item was last modified on a client     |
| MsGraphFiles.ReplacedFiles.LastModifiedBy.DisplayName        | String   | The item display name                                        |
| MsGraphFiles.ReplacedFiles.LastModifiedBy.ID                 | String   | Identity of the application which last modified the item     |
| MsGraphFiles.ReplacedFiles.CreatedBy.DisplayName             | String   | Identity of the user, device,or application which created the item |
| MsGraphFiles.ReplacedFiles.CreatedBy.ID                      | String   | The ID of the creator                                        |
| MsGraphFiles.ReplacedFiles.CreatedBy.Type                    | String   | Application, user or device                                  |
| MsGraphFiles.ReplacedFiles.DownloadUrl                       | String   | URL to download the file's content                           |
| MsGraphFiles.ReplacedFiles.Size                              | Number   | File's size                                                  |
| MsGraphFiles.ReplacedFiles.Id                                | String   | File ID                                                      |
| MsGraphFiles.ReplacedFiles.Name                              | String   | The file's name                                              |
| MsGraphFiles.ReplacedFiles.File                              | String   | Graph's file object                                          |


##### Command Example

```!msgraph-replace-existing-file object_type=drives entry_id=test item_id=test object_type_id=test ```

##### Context Example

```
{
    "MsGraphFiles.ReplacedFiles": {
        "ParentReference": {
            "DriveId": "test", 
            "DriveType": "documentLibrary", 
            "ID": "test", 
            "Path": "test"
        }, 
        "LastModifiedBy": {
            "Type": "Application", 
            "DisplayName": "Microsoft Graph", 
            "ID": "test"
        }, 
        "LastModifiedDateTime": "2020-01-22T20:03:06Z", 
        "CreatedBy": {
            "Type": "Application", 
            "DisplayName": "SharePoint DEV", 
            "ID": "test"
        }, 
        "CreatedDateTime": "2020-01-05T15:30:21Z", 
        "WebUrl": "test", 
        "FileSystemInfo": {
            "CreatedDateTime": "2020-01-05T15:30:21Z", 
            "LastModifiedDateTime": "2020-01-22T20:03:06Z"
        }, 
        "DownloadUrl": "test", 
        "File": {
            "MimeType": "text/plain", 
            "Hashes": {
                "QuickXorHash": "test"
            }
        }, 
        "OdataContext": "test", 
        "Size": 15, 
        "ID": "test", 
        "Name": "test.txt"
    }
}
```

##### Human Readable Output

### MsGraphFiles - File information:

| Created By     | Created Date Time    | ID   | Last Modified By | Name     | Size | Web Url |
| -------------- | -------------------- | ---- | ---------------- | -------- | ---- | ------- |
| SharePoint DEV | 2020-01-05T15:30:21Z | 123  | Microsoft Graph  | yaya.txt | 15   | 123     |


### 4. msgraph-create-new-folder

---

Create a new folder in a Drive with a specified parent item or path.

##### Required Permissions

    Files.ReadWrite.All
    Sites.ReadWrite.All


##### Base Command

`msgraph-create-new-folder`

##### Input

| **Argument Name** | **Description**                             | **Required** |
| ----------------- | ------------------------------------------- | ------------ |
| object_type       | MS Graph resource.                          | Required     |
| object_type_id    | MS Graph resource id.                       | Required     |
| parent_id         | An ID of the Drive to upload the folder to. | Required     |
| folder_name       | the folder name for the created folder.     | Required     |


##### Context Output

| **Path**                                                     | **Type** | **Description**                                              |
| ------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| MsGraph.Folder                                               | Unknown  | Graph's folder object                                        |
| Msgraphfiles.CreatedFolder.ParentReference.DriveId           | String   | Unique identifier of the drive that contains the item.       |
| Msgraphfiles.CreatedFolder.ParentReference.DriveType         | String   | Identifies the type of drive.                                |
| Msgraphfiles.CreatedFolder.ParentReference.ID                | String   | Unique identifier of the item in the drive.                  |
| Msgraphfiles.CreatedFolder.ParentReference.Path              | String   | Path to navigate to the item                                 |
| Msgraphfiles.CreatedFolder.LastModifiedDateTime              | Date     | Date and time that the item was last modified.               |
| Msgraphfiles.CreatedFolder.Name                              | String   | The folder's name                                            |
| Msgraphfiles.CreatedFolder.CreatedDateTime                   | Date     | Timestamp of item creation.                                  |
| Msgraphfiles.CreatedFolder.WebUrl                            | String   | URL to the resource in the browser                           |
| Msgraphfiles.CreatedFolder.OdataContext                      | String   | OData query                                                  |
| Msgraphfiles.CreatedFolder.FileSystemInfo.CreatedDateTime    | Date     | The date and time the item was created on a client.          |
| Msgraphfiles.CreatedFolder.FileSystemInfo.LastModifiedDateTime | Date     | The date and time the item was last modified on a client     |
| Msgraphfiles.CreatedFolder.LastModifiedBy.DisplayName        | String   | The item display name                                        |
| Msgraphfiles.CreatedFolder.LastModifiedBy.ID                 | String   | The item display name                                        |
| Msgraphfiles.CreatedFolder.CreatedBy.DisplayName             | String   | Identity of the user, device,or application which created the item |
| Msgraphfiles.CreatedFolder.CreatedBy.ID                      | String   | The ID of the creator                                        |
| Msgraphfiles.CreatedFolder.ChildCount                        | Number   | The number of the folder's sub items                         |
| Msgraphfiles.CreatedFolder.ID                                | String   | Folder ID                                                    |
| Msgraphfiles.CreatedFolder.Size                              | Number   | Folder size                                                  |


##### Command Example

```!msgraph-create-new-folder object_type=drives object_type_id=123 parent_id=123 folder_name=test11```

##### Context Example

```
{
    "MsGraphFiles.CreatedFolders": {
        "ParentReference": {
            "DriveId": "test", 
            "DriveType": "documentLibrary", 
            "ID": "test", 
            "Path": "test"
        }, 
        "OdataContext": "test", 
        "LastModifiedDateTime": "2020-01-22T20:03:09Z", 
        "Name": "test11 19", 
        "CreatedDateTime": "2020-01-22T20:03:09Z", 
        "WebUrl": "test", 
        "FileSystemInfo": {
            "CreatedDateTime": "2020-01-22T20:03:09Z", 
            "LastModifiedDateTime": "2020-01-22T20:03:09Z"
        }, 
        "LastModifiedBy": {
            "Type": "Application", 
            "DisplayName": "Microsoft Graph", 
            "ID": "test"
        }, 
        "CreatedBy": {
            "Type": "Application", 
            "DisplayName": "Microsoft Graph", 
            "ID": "test"
        }, 
        "Folder": {
            "ChildCount": 0
        }, 
        "ID": "test", 
        "Size": 0
    }
}
```

##### Human Readable Output

### MsGraphFiles - Folder information:

| Child Count   | Created By      | Created Date Time    | ID   | Last Modified By | Name      | Size | Web Url |
| ------------- | --------------- | -------------------- | ---- | ---------------- | --------- | ---- | ------- |
| ChildCount: 0 | Microsoft Graph | 2020-01-22T20:03:09Z | 123  | Microsoft Graph  | test11 19 | 0    | 123     |


### 5. msgraph-list-drives-in-site

---

Returns the list of Drive resources available for a target Site

##### Required Permissions

    Sites.ReadWrite.All
    Files.ReadWrite.All

##### Base Command

`msgraph-list-drives-in-site`

##### Input

| **Argument Name** | **Description**                    | **Required** |
| ----------------- | ---------------------------------- | ------------ |
| site_id           | Selected Site ID.                  | Optional     |
| limit             | Sets the page size of results.     | Optional     |
| next_page_url     | The URL for the next results page. | Optional     |


##### Context Output

| **Path**                                           | **Type** | **Description**                                              |
| -------------------------------------------------- | -------- | ------------------------------------------------------------ |
| MsGraphFiles.ListDrives.Value.LastModifiedDateTime | Date     | Date and time that the item was last modified                |
| MsGraphFiles.ListDrives.Value.Description          | String   | A user visible description of the drive                      |
| MsGraphFiles.ListDrives.Value.CreatedDateTime      | Date     | Timestamp of Drive creation                                  |
| MsGraphFiles.ListDrives.Value.WebUrl               | String   | URL to the resource in the browser                           |
| MsGraphFiles.ListDrives.Value.CreatedBy            | String   | Identity of the user, application, or device  which created the Drive. |
| MsGraphFiles.ListDrives.Value.Owner.DisplayName    | String   | DisplayName of the user, device or application which owns the Drive |
| MsGraphFiles.ListDrives.Value.Owner.ID             | String   | ID of the user, device or application which owns the Drive   |
| MsGraphFiles.ListDrives.Value.Owner.Type           | String   | user, device or application                                  |
| MsGraphFiles.ListDrives.Value.DriveType            | String   | Identifies the type of drive                                 |
| MsGraphFiles.ListDrives.Value.ID                   | String   | Drive ID                                                     |
| MsGraphFiles.ListDrives.Value.Name                 | String   | The drive's name                                             |
| MsGraphFiles.ListDrives.OdataContext               | String   | OData query                                                  |


##### Command Example

```!msgraph-list-drives-in-site limit=1 site_id=test limit=1```

##### Context Example

```
{
    "MsGraphFiles.ListDrives": {
        "OdataContext": "test", 
        "Value": [
            {
                "LastModifiedDateTime": "2019-09-21T08:17:20Z", 
                "Description": "", 
                "CreatedDateTime": "2019-09-21T08:17:20Z", 
                "WebUrl": "test", 
                "CreatedBy": {
                    "Type": "User", 
                    "DisplayName": "System Account"
                }, 
                "Owner": {
                    "Group": {
                        "DisplayName": "site_test2 Owners", 
                        "Email": "test", 
                        "ID": "a6975ca6-9adf-40e9-bf1e-3f574e7510ae"
                    }
                }, 
                "DriveType": "documentLibrary", 
                "ID": "test", 
                "Name": "Documents"
            }
        ]
    }
}
```

##### Human Readable Output

### MsGraphFiles - Drives information:

| Created By     | Created Date Time    | Description | Drive Type      | ID   | Last Modified Date Time | Name      | Web Url |
| -------------- | -------------------- | ----------- | --------------- | ---- | ----------------------- | --------- | ------- |
| System Account | 2019-09-21T08:17:20Z |             | documentLibrary | Test | 2019-09-21T08:17:20Z    | Documents | Test    |


### 6. msgraph-list-drive-content

---

This command list all the drive's files and folders

##### Required Permissions

    Files.ReadWrite.All
    Sites.ReadWrite.All

##### Base Command

`msgraph-list-drive-content`

##### Input

| **Argument Name** | **Description**                    | **Required** |
| ----------------- | ---------------------------------- | ------------ |
| object_type       | MS Graph resource.                 | Required     |
| object_type_id    | MS Graph resource id.              | Required     |
| item_id           | Ms Graph item_id.                  | Optional     |
| limit             | Sets the page size of results.     | Optional     |
| next_page_url     | The URL for the next results page. | Optional     |


##### Context Output

| **Path**                                                     | **Type** | **Description**                                              |
| ------------------------------------------------------------ | -------- | ------------------------------------------------------------ |
| MsGraphFiles.ListChildren.Children.Value.OdataNextLink       | String   | The URL for the next results page.                           |
| MsGraphFiles.ListChildren.Children.Value.ParentReference.DriveId | String   | Unique identifier of the drive that contains the item.       |
| MsGraphFiles.ListChildren.Children.Value.ParentReference.DriveType | String   | Identifies the type of drive.                                |
| MsGraphFiles.ListChildren.Children.Value.ParentReference.ID  | String   | Unique identifier of the item in the drive.                  |
| MsGraphFiles.ListChildren.Children.Value.ParentReference.Path | String   | Path to navigate to the item                                 |
| MsGraphFiles.ListChildren.Children.Value.LastModifiedDateTime | Date     | Date and time that the item was last modified.               |
| MsGraphFiles.ListChildren.Children.Value.Name                | String   | The file's name                                              |
| MsGraphFiles.ListChildren.Children.Value.CreatedDateTime     | Date     | Timestamp of item creation.                                  |
| MsGraphFiles.ListChildren.Children.Value.WebUrl              | String   | URL to the resource in the browser                           |
| MsGraphFiles.ListChildren.Children.Value.FileSystemInfo.CreatedDateTime | Date     | The date and time the item was created on a client.          |
| MsGraphFiles.ListChildren.Children.Value.FileSystemInfo.LastModifiedDateTime | Date     | The date and time the item was last modified on a client.    |
| MsGraphFiles.ListChildren.Children.Value.LastModifiedBy.DisplayName | String   | The item display name                                        |
| MsGraphFiles.ListChildren.Children.Value.LastModifiedBy.ID   | String   | Identity of the application, user or device which last modified the item |
| MsGraphFiles.ListChildren.Children.Value.CreatedBy.DisplayName | String   | Identity of the user, device,or application which created the item |
| MsGraphFiles.ListChildren.Children.Value.CreatedBy.ID        | String   | The ID of the creator                                        |
| MsGraphFiles.ListChildren.Children.Value.CreatedBy.Type      | String   | application, user or device                                  |
| MsGraphFiles.ListChildren.ID                                 | String   | File or folder ID                                            |
| MsGraphFiles.ListChildren.Children.Size                      | Number   | File or folder size                                          |
| MsGraphFiles.ListChildren.Children.OdataContext              | String   | OData query                                                  |


##### Command Example

```!msgraph-list-drive-content object_type=drives limit=1 object_type_id=test parent_id=test```

##### Context Example

```
{
    "MsGraphFiles.ListChildren": {
        "Children": {
            "OdataContext": "test", 
            "Value": [
                {
                    "ParentReference": {
                        "DriveId": "test", 
                        "DriveType": "documentLibrary", 
                        "ID": "test", 
                        "Path": "test"
                    }, 
                    "LastModifiedDateTime": "2019-12-29T11:57:41Z", 
                    "Name": "Attachments", 
                    "CreatedDateTime": "2019-12-29T11:57:41Z", 
                    "WebUrl": "test", 
                    "FileSystemInfo": {
                        "CreatedDateTime": "2019-12-29T11:57:41Z", 
                        "LastModifiedDateTime": "2019-12-29T11:57:41Z"
                    }, 
                    "LastModifiedBy": {
                        "Type": "Application", 
                        "DisplayName": "MS Graph Files", 
                        "ID": "test"
                    }, 
                    "CreatedBy": {
                        "Type": "Application", 
                        "DisplayName": "MS Graph Files Dev", 
                        "ID": "test"
                    }, 
                    "Folder": {
                        "ChildCount": 2
                    }, 
                    "ID": "test", 
                    "Size": 0
                }
            ]
        }, 
        "ParentID": "root"
    }
}
```

##### Human Readable Output

### MsGraphFiles - drivesItems information:

| Created By         | Created Date Time    | Description | ID   | Last Modified Date Time | Name        | Size | Web Url |
| ------------------ | -------------------- | ----------- | ---- | ----------------------- | ----------- | ---- | ------- |
| MS Graph Files Dev | 2019-12-29T11:57:41Z |             | 123  | 2019-12-29T11:57:41Z    | Attachments | 0    | 123     |


### 7. msgraph-list-share-point-sites

---

Returns a list of the tenant Sites

##### Required Permissions

    Sites.ReadWrite.All

##### Base Command

`msgraph-list-share-point-sites`

##### Input

There are no input arguments for this command.

##### Context Output

| **Path**                                             | **Type** | **Description**                                |
| ---------------------------------------------------- | -------- | ---------------------------------------------- |
| MsGraph.Sites                                        | Unknown  | Graph's site object                            |
| MsGraphFiles.OdataContext                            | String   | OData query                                    |
| MsGraphFiles.OdataNextLink                           | String   | The URL for the next results page.             |
| MsGraphFiles.ListSites.Value.LastModifiedDateTime    | String   | Date and time that the item was last modified. |
| MsGraphFiles.ListSites.Value.DisplayName             | String   | The item display name                          |
| MsGraphFiles.ListSites.Value.Description             | String   | The item description                           |
| MsGraphFiles.ListSites.Value.CreatedDateTime         | Date     | imestamp of site creation                      |
| MsGraphFiles.ListSites.Value.WebUrl                  | String   | URL to the resource in the browser             |
| MsGraphFiles.ListSites.Value.OdataContext            | String   | OData query                                    |
| MsGraphFiles.ListSites.Value.SiteCollection.Hostname | String   | The hostname for the site collection           |
| MsGraphFiles.ListSites.Value.ID                      | String   | Site id                                        |
| MsGraphFiles.ListSites.Value.Name                    | String   | Site name                                      |


##### Command Example

```!msgraph-list-share-point-sites site_id=123```

##### Context Example

```
{
    "MsGraphFiles.ListSites": {
        "OdataContext": "123", 
        "Value": [
            {
                "LastModifiedDateTime": "2016-09-14T11:13:53Z", 
                "DisplayName": "Demisto Team", 
                "Name": "123", 
                "CreatedDateTime": "2016-09-14T11:12:59Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123"
            }, 
            {
                "LastModifiedDateTime": "2019-09-21T08:17:21Z", 
                "DisplayName": "123", 
                "Description": "this is a private site", 
                "CreatedDateTime": "2019-09-23T15:55:03Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123", 
                "Name": "site_test_1"
            }, 
            {
                "LastModifiedDateTime": "2019-09-21T08:17:21Z", 
                "DisplayName": "site_test2", 
                "Description": "this is a public site", 
                "CreatedDateTime": "2019-09-23T15:57:14Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123", 
                "Name": "site_test2"
            }, 
            {
                "LastModifiedDateTime": "0001-01-01T08:00:00Z", 
                "DisplayName": "Community", 
                "Name": "Community", 
                "CreatedDateTime": "2016-09-14T11:15:40Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123"
            }, 
            {
                "LastModifiedDateTime": "0001-01-01T08:00:00Z", 
                "DisplayName": "PointPublis", 
                "Name": "hub", 
                "CreatedDateTime": "2016-09-14T11:14:07Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123"
            }, 
            {
                "LastModifiedDateTime": "0001-01-01T08:00:00Z", 
                "DisplayName": "shelly", 
                "Name": "DemistoTe", 
                "CreatedDateTime": "2020-01-05T13:28:50Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123"
            }, 
            {
                "LastModifiedDateTime": "0001-01-01T08:00:00Z", 
                "DisplayName": "Sade - shelly", 
                "Name": "Sade-shelly", 
                "CreatedDateTime": "2020-01-05T13:27:51Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123"
            }, 
            {
                "LastModifiedDateTime": "0001-01-01T08:00:00Z", 
                "DisplayName": "DemistoTeam - test", 
                "Name": "DemistoTeam79-test", 
                "CreatedDateTime": "2020-01-06T08:05:27Z", 
                "WebUrl": "123", 
                "SiteCollection": {
                    "Hostname": "123"
                }, 
                "Root": {}, 
                "ID": "123"
            }

        ]
    }
}
```

##### Human Readable Output

### List Sites:

| Created Date Time    | ID   | Last Modified Date Time | Name                 | Web Url |
| -------------------- | ---- | ----------------------- | -------------------- | ------- |
| 2016-09-14T11:12:59Z | 123  | 2016-09-14T11:13:53Z    | 123                  | 123     |
| 2019-09-23T15:55:03Z | 123  | 2019-09-21T08:17:21Z    | site_test_1          | 123     |
| 2019-09-23T15:57:14Z | 123  | 2019-09-21T08:17:21Z    | site_test2           | 123     |
| 2016-09-14T11:15:40Z | 123  | 0001-01-01T08:00:00Z    | Community            | 123     |
| 2016-09-14T11:14:07Z | 123  | 0001-01-01T08:00:00Z    | hub                  | 123     |
| 2020-01-05T13:28:50Z | 123  | 0001-01-01T08:00:00Z    | DemistoTeam79-shelly | 123     |
| 2020-01-05T13:27:51Z | 123  | 0001-01-01T08:00:00Z    | Sade-shelly          | 123     |
| 2020-01-06T08:05:27Z | 123  | 0001-01-01T08:00:00Z    | DemistoTeam79-test   | 123     |
| 2016-09-14T11:14:02Z | 123  | 2016-09-14T11:15:28Z    | contentTypeHub       | 123     |
| 2018-12-26T09:44:17Z | 123  | 2018-11-17T12:17:41Z    | testpublic           | 123     |
| 2018-12-26T09:42:25Z | 123  | 2018-11-17T12:17:41Z    | testgroup            | 123     |
| 2019-08-03T11:31:53Z | 123  | 2019-07-27T08:31:04Z    | wowalias1            | 123     |
| 2019-08-03T06:17:27Z | 123  | 2019-07-27T08:31:04Z    | library              | 123     |
| 2019-08-03T11:30:11Z | 123  | 2019-07-27T08:31:04Z    | wowalias             | 123     |
| 2019-08-24T09:39:08Z | 123  | 2019-07-27T08:31:04Z    | DemistoTeam79        | 123     |
| 2019-08-27T13:00:28Z | 123  | 2019-08-24T10:14:13Z    | Sade                 | 123     |
| 2019-10-25T20:20:29Z | 123  | 2019-10-19T23:21:12Z    | kkk                  | 123     |
| 2019-11-12T13:49:07Z | 123  | 2019-11-03T01:15:16Z    | FileTestTeam         | 123     |
| 2019-12-31T07:58:14Z | 123  | 2019-11-17T05:24:33Z    | ShellysTeam          | 123     |
| 2020-01-05T15:17:45Z | 123  | 2019-11-17T05:24:33Z    | aaaaa                | 123     |


### 8. msgraph-download-file

---

Download the contents of the file of a DriveItem.

##### Required Permissions

    Files.ReadWrite.All
    Sites.ReadWrite.All

##### Base Command

`msgraph-download-file`

##### Input

| **Argument Name** | **Description**       | **Required** |
| ----------------- | --------------------- | ------------ |
| object_type       | MS Graph resource.    | Required     |
| object_type_id    | MS Graph resource id. | Required     |
| item_id           | Ms Graph item_id.     | Required     |


##### Context Output

| **Path**     | **Type** | **Description**  |
| ------------ | -------- | ---------------- |
| File.Size    | String   | File's size      |
| File.SHA1    | String   | File's SHA1      |
| File.SHA256  | String   | File's SHA256    |
| File.SHA512  | String   | File's SHA512    |
| File.Name    | String   | File name        |
| File.SSDeep  | String   | File's SSDeep    |
| File.EntryID | Unknown  | Demisto file ID  |
| File.Info    | String   | File information |
| File.Type    | String   | File type        |
| File.MD5     | String   | File's MD5       |


##### Command Example

```!msgraph-download-file object_type=drives object_type_id=123 item_id=123```



