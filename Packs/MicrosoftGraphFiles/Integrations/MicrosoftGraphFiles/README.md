Use the Microsoft Graph Files integration to enable your app to get authorized access to files in OneDrive, SharePoint, and MS Teams across your entire organization. This integration requires admin consent.

## Configure Microsoft_Graph_Files on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft_Graph_Files.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| host | Server URL | True |
| auth_id | ID \(received from the admin consent - see Detailed Instructions\) | True |
| tenant_id | Token \(received from the admin consent - see Detailed Instructions\) | False |
| enc_key | Key \(received from the admin consent - see Detailed Instructions\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| self_deployed | Use a self-deployed Azure Application | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### msgraph-delete-file
***
Deletes an item from OneDrive.


#### Base Command

`msgraph-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Can be "drives", "groups", "sites", or "users". | Required | 
| object_type_id | MS Graph resource ID.<br/> For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Microsoft Graph Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Microsoft Graph User' integration and use the msgraph-user-list command. | Required | 
| item_id | The ID of the item to delete.<br/>In order to get the ID of the file you want to delete you can use the msgraph-list-drive-content command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-delete-file object_type=drives object_type_id=test item_id=test```

#### Human Readable Output
| 123 |
| ---------------------------------- |
| Item was deleted successfully      |


### msgraph-upload-new-file
***
Uploads a file from Cortex XSOAR to the specified MS Graph resource.


#### Base Command

`msgraph-upload-new-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Can be "drives", "groups", "sites", or "users". | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Microsoft Graph Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Microsoft Graph User' integration and use the msgraph-user-list command. | Required | 
| parent_id | The ID of the folder in which to upload the file.<br/>In order to get the ID of a folder, you can use the msgraph-list-drive-content command. | Required | 
| file_name | A name for the file to upload. | Required | 
| entry_id | The Cortex XSOAR entry ID of the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.UploadedFiles.ParentReference.DriveId | String | Unique identifier of the drive that contains the item. | 
| MsGraphFiles.UploadedFiles.ParentReference.DriveType | String | Identifies the drive type. | 
| MsGraphFiles.UploadedFiles.ParentReference.ID | String | Unique identifier of the item in the drive. | 
| MsGraphFiles.UploadedFiles.ParentReference.Path | String | The path of the item. | 
| MsGraphFiles.UploadedFiles.LastModifiedDateTime | String | Timestamp of when the item was last modified. | 
| MsGraphFiles.UploadedFiles.File.MimeType | String | The file type. | 
| MsGraphFiles.UploadedFiles.File.Hashes | String | The file hash type. | 
| MsGraphFiles.UploadedFiles.CreatedDateTime | String | Timestamp of when the item was created. | 
| MsGraphFiles.UploadedFiles.WebUrl | String | URL to the resource in the browser. | 
| MsGraphFiles.UploadedFiles.OdataContext | String | The OData query. | 
| MsGraphFiles.UploadedFiles.FileSystemInfo.CreatedDateTime | String | Timestamp of when the item was created on a client. | 
| MsGraphFiles.UploadedFiles.FileSystemInfo.LastModifiedDateTime | String | Timestamp of when the item was last modified on a client. | 
| MsGraphFiles.UploadedFiles.LastModifiedBy.DisplayName | String | The item display name. | 
| MsGraphFiles.UploadedFiles.LastModifiedBy.Type | String | The application, user, or device that last modified the item. | 
| MsGraphFiles.UploadedFiles.CreatedBy.DisplayName | String | The identity of the user, device,or application that created the item. | 
| MsGraphFiles.UploadedFiles.CreatedBy.ID | String | The ID of the creator. | 
| MsGraphFiles.UploadedFiles.CreatedBy.Type | String | The application, user, or device that created the item. | 
| MsGraphFiles.UploadedFiles.DownloadUrl | String | URL to download this file's content. | 
| MsGraphFiles.UploadedFiles.Size | Number | The file size. | 
| MsGraphFiles.UploadedFiles.ID | String | The file ID. | 
| MsGraphFiles.UploadedFiles.Name | String | The file name. | 
| MsGraph.UploadedFiles.File | String | The MS Graph file object. | 


#### Command Example
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

#### Human Readable Output
| CreatedBy       | CreatedDateTime      | ID   | LastModifiedBy  | Name     | Size | WebUrl |
| --------------- | -------------------- | ---- | --------------- | -------- | ---- | ------ |
| Microsoft Graph | 2020-01-22T20:03:00Z | Test | Microsoft Graph | test.txt | 15   | Test   |


### msgraph-replace-existing-file
***
Replaces the content of the file in the specified MS Graph resource.


#### Base Command

`msgraph-replace-existing-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Can be "drives", "groups", "sites", or "users". | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Microsoft Graph Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Microsoft Graph User' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID of the file you want to replace.<br/>In order to get the ID of the file you want to replace you can use the msgraph-list-drive-content command. | Required | 
| entry_id | The Cortex XSOAR entry ID of the replacing file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.ReplacedFiles.ParentReference.DriveId | String | Unique identifier of the drive that contains the item. | 
| MsGraphFiles.ReplacedFiles.ParentReference.DriveType | String | The drive type. | 
| MsGraphFiles.ReplacedFiles.ParentReference.ID | String | Unique identifier of the item in the drive. | 
| MsGraphFiles.ReplacedFiles.ParentReference.Path | String | The path of the item. | 
| MsGraphFiles.ReplacedFiles.LastModifiedDateTime | Date | Timestamp of when the item was last modified. | 
| MsGraphFiles.ReplacedFiles.File.MimeType | String | The file type. | 
| MsGraphFiles.ReplacedFiles.File.Hashes | String | The file hash type. | 
| MsGraphFiles.ReplacedFiles.CreatedDateTime | String | Timestamp of when the item was created. | 
| MsGraphFiles.ReplacedFiles.WebUrl | String | URL to the resource in the browser. | 
| MsGraphFiles.ReplacedFiles.OdataContext | String | The OData query. | 
| MsGraphFiles.ReplacedFiles.FileSystemInfo.CreatedDateTime | Date | Timestamp of when the item was created on a client. | 
| MsGraphFiles.ReplacedFiles.FileSystemInfo.LastModifiedDateTime | Date | Timestamp of when the item was last modified on a client. | 
| MsGraphFiles.ReplacedFiles.LastModifiedBy.DisplayName | String | The item display name. | 
| MsGraphFiles.ReplacedFiles.LastModifiedBy.ID | String | Identity of the application that last modified the item. | 
| MsGraphFiles.ReplacedFiles.CreatedBy.DisplayName | String | Identity of the user, device, or application that created the item. | 
| MsGraphFiles.ReplacedFiles.CreatedBy.ID | String | The ID of the creator. | 
| MsGraphFiles.ReplacedFiles.CreatedBy.Type | String | Application, user, or device. | 
| MsGraphFiles.ReplacedFiles.DownloadUrl | String | URL to download the file's content. | 
| MsGraphFiles.ReplacedFiles.Size | Number | File's size | 
| MsGraphFiles.ReplacedFiles.Id | String | The file ID. | 
| MsGraphFiles.ReplacedFiles.Name | String | The file name. | 
| MsGraphFiles.ReplacedFiles.File | String | The MS Graph file object. | 


#### Command Example
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
#### Human Readable Output
### MsGraphFiles - File information:

| Created By     | Created Date Time    | ID   | Last Modified By | Name     | Size | Web Url |
| -------------- | -------------------- | ---- | ---------------- | -------- | ---- | ------- |
| SharePoint DEV | 2020-01-05T15:30:21Z | 123  | Microsoft Graph  | yaya.txt | 15   | 123     |


### msgraph-create-new-folder
***
Creates a new folder in a drive with the specified parent item or path.


#### Base Command

`msgraph-create-new-folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Can be "drives", "groups", "sites", or "users". | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Microsoft Graph Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Microsoft Graph User' integration and use the msgraph-user-list command. | Required | 
| parent_id | The ID of the parent in which to upload the new folder.<br/>Parent can be either 'root' or another folder.<br/>In order to get the required folder ID you can use the msgraph-list-drive-content command. | Required | 
| folder_name | The name of the new folder. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Folder | Unknown | The MS Graph folder object. | 
| Msgraphfiles.CreatedFolder.ParentReference.DriveId | String | Unique identifier of the drive that contains the item. | 
| Msgraphfiles.CreatedFolder.ParentReference.DriveType | String | The drive type. | 
| Msgraphfiles.CreatedFolder.ParentReference.ID | String | Unique identifier of the item in the drive. | 
| Msgraphfiles.CreatedFolder.ParentReference.Path | String | The path to the item | 
| Msgraphfiles.CreatedFolder.LastModifiedDateTime | Date | Timestamp of when the item was last modified. | 
| Msgraphfiles.CreatedFolder.Name | String | The folder name. | 
| Msgraphfiles.CreatedFolder.CreatedDateTime | Date | Timestamp of when the item was created. | 
| Msgraphfiles.CreatedFolder.WebUrl | String | URL to the resource in the browser. | 
| Msgraphfiles.CreatedFolder.OdataContext | String | The OData query. | 
| Msgraphfiles.CreatedFolder.FileSystemInfo.CreatedDateTime | Date | Timestamp of when the item was created on a client. | 
| Msgraphfiles.CreatedFolder.FileSystemInfo.LastModifiedDateTime | Date | Timestamp of when the item was last modified on a client. | 
| Msgraphfiles.CreatedFolder.LastModifiedBy.DisplayName | String | The item display name. | 
| Msgraphfiles.CreatedFolder.LastModifiedBy.ID | String | Identity of the application that last modified the item. | 
| Msgraphfiles.CreatedFolder.CreatedBy.DisplayName | String | Identity of the user, device,or application that created the item. | 
| Msgraphfiles.CreatedFolder.CreatedBy.ID | String | The ID of the creator. | 
| Msgraphfiles.CreatedFolder.ChildCount | Number | The number of sub-items in the folder. | 
| Msgraphfiles.CreatedFolder.ID | String | The folder ID. | 
| Msgraphfiles.CreatedFolder.Size | Number | The folder size. | 


#### Command Example
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
#### Human Readable Output
### MsGraphFiles - Folder information:

| Child Count   | Created By      | Created Date Time    | ID   | Last Modified By | Name      | Size | Web Url |
| ------------- | --------------- | -------------------- | ---- | ---------------- | --------- | ---- | ------- |
| ChildCount: 0 | Microsoft Graph | 2020-01-22T20:03:09Z | 123  | Microsoft Graph  | test11 19 | 0    | 123     |


### msgraph-list-drives-in-site
***
Returns the list of document libraries (drives) available for a target site.


#### Base Command

`msgraph-list-drives-in-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | The ID of the site for which to return available drive resources.<br/>To find a list of all sites, use the msgraph-list-sharepoint-sites command. | Optional | 
| limit | The maximum number of results to return. | Optional | 
| next_page_url | The URL for the next results page.<br/>If a next page of results exists, you will find it in Cortex XSOAR context under MsGraphFiles.ListDrives.OdataNextLink. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.ListDrives.Value.LastModifiedDateTime | Date | Timestamp of when the item was last modified. | 
| MsGraphFiles.ListDrives.Value.Description | String | A human-readable description of the drive. | 
| MsGraphFiles.ListDrives.Value.CreatedDateTime | Date | Timestamp of when the drive was created. | 
| MsGraphFiles.ListDrives.Value.WebUrl | String | URL to the resource in the browser. | 
| MsGraphFiles.ListDrives.Value.CreatedBy | String | Identity of the user, application, or device that created the drive. | 
| MsGraphFiles.ListDrives.Value.Owner.DisplayName | String | The display name of the user, device, or application that owns the drive. | 
| MsGraphFiles.ListDrives.Value.Owner.ID | String | The ID of the user, device, or application that owns the drive. | 
| MsGraphFiles.ListDrives.Value.Owner.Type | String | The owner type. Can be "user", "device", or "application". | 
| MsGraphFiles.ListDrives.Value.DriveType | String | The drive type. | 
| MsGraphFiles.ListDrives.Value.ID | String | The drive ID. | 
| MsGraphFiles.ListDrives.Value.Name | String | The name of the drive. | 
| MsGraphFiles.ListDrives.OdataContext | String | The OData query. | 


#### Command Example
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
#### Human Readable Output
### MsGraphFiles - Drives information:

| Created By     | Created Date Time    | Description | Drive Type      | ID   | Last Modified Date Time | Name      | Web Url |
| -------------- | -------------------- | ----------- | --------------- | ---- | ----------------------- | --------- | ------- |
| System Account | 2019-09-21T08:17:20Z |             | documentLibrary | Test | 2019-09-21T08:17:20Z    | Documents | Test    |


### msgraph-list-drive-content
***
Returns a list of files and folders in the specified drive.


#### Base Command

`msgraph-list-drive-content`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Can be "drives", "groups", "sites", or "users". | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Microsoft Graph Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Microsoft Graph User' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID.<br/>It can be either 'root' or another folder.<br/>Passing a folder ID retrieves files from a specified folder.<br/>The default is 'root': retrieve content in the root of the drive.<br/><br/>In order to get the required folder ID you can use this command and leave this argument empty in order to get a list of folders that are located in the root.<br/><br/>If your folder is nested inside another folder, pass the parent ID found when running this command without 'item_id', to this argument to get the required folder ID. | Optional | 
| limit | The maximum number of results to return. | Optional | 
| next_page_url | The URL for the next results page.<br/>If a next page of results exists, you will find it in Cortex XSOAR context under MsGraphFiles.ListChildren.OdataNextLink. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.ListChildren.Children.Value.OdataNextLink | String | The URL for the next results page. | 
| MsGraphFiles.ListChildren.Children.Value.ParentReference.DriveId | String | Unique identifier of the drive that contains the item. | 
| MsGraphFiles.ListChildren.Children.Value.ParentReference.DriveType | String | The drive type. | 
| MsGraphFiles.ListChildren.Children.Value.ParentReference.ID | String | Unique identifier of the item in the drive. | 
| MsGraphFiles.ListChildren.Children.Value.ParentReference.Path | String | The path to the item. | 
| MsGraphFiles.ListChildren.Children.Value.LastModifiedDateTime | Date | Timestamp of when the item was last modified. | 
| MsGraphFiles.ListChildren.Children.Value.Name | String | The file name. | 
| MsGraphFiles.ListChildren.Children.Value.CreatedDateTime | Date | Timestamp of when the item was created. | 
| MsGraphFiles.ListChildren.Children.Value.WebUrl | String | URL to the resource in the browser. | 
| MsGraphFiles.ListChildren.Children.Value.FileSystemInfo.CreatedDateTime | Date | Timestamp of when the item was created on a client. | 
| MsGraphFiles.ListChildren.Children.Value.FileSystemInfo.LastModifiedDateTime | Date | Timestamp of when the item was last modified on a client. | 
| MsGraphFiles.ListChildren.Children.Value.LastModifiedBy.DisplayName | String | The item display name. | 
| MsGraphFiles.ListChildren.Children.Value.LastModifiedBy.ID | String | Identity of the application, user, or device that last modified the item. | 
| MsGraphFiles.ListChildren.Children.Value.CreatedBy.DisplayName | String | Identity of the user, device, or application that created the item. | 
| MsGraphFiles.ListChildren.Children.Value.CreatedBy.ID | String | The ID of the creator. | 
| MsGraphFiles.ListChildren.Children.Value.CreatedBy.Type | String | The created by type. Can be "application", "user", or "device". | 
| MsGraphFiles.ListChildren.ID | String | The file ID or folder ID. | 
| MsGraphFiles.ListChildren.Children.Size | Number | The file size or folder size. | 
| MsGraphFiles.ListChildren.Children.OdataContext | String | The OData query. | 


#### Command Example
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
#### Human Readable Output
### MsGraphFiles - drivesItems information:

| Created By         | Created Date Time    | Description | ID   | Last Modified Date Time | Name        | Size | Web Url |
| ------------------ | -------------------- | ----------- | ---- | ----------------------- | ----------- | ---- | ------- |
| MS Graph Files Dev | 2019-12-29T11:57:41Z |             | 123  | 2019-12-29T11:57:41Z    | Attachments | 0    | 123     |


### msgraph-list-sharepoint-sites
***
Returns a list of the tenant sites.


#### Base Command

`msgraph-list-sharepoint-sites`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Sites | Unknown | The MS Graph site object. | 
| MsGraphFiles.OdataContext | String | The OData query. | 
| MsGraphFiles.OdataNextLink | String | The URL for the next results page. | 
| MsGraphFiles.ListSites.Value.LastModifiedDateTime | String | Timestamp of when the item was last modified. | 
| MsGraphFiles.ListSites.Value.DisplayName | String | The item display name. | 
| MsGraphFiles.ListSites.Value.Description | String | The item description. | 
| MsGraphFiles.ListSites.Value.CreatedDateTime | Date | Timestamp of when the site was created. | 
| MsGraphFiles.ListSites.Value.WebUrl | String | URL to the resource in the browser. | 
| MsGraphFiles.ListSites.Value.OdataContext | String | The OData query. | 
| MsGraphFiles.ListSites.Value.SiteCollection.Hostname | String | The hostname for the site collection. | 
| MsGraphFiles.ListSites.Value.ID | String | The site ID. | 
| MsGraphFiles.ListSites.Value.Name | String | The site name. | 


#### Command Example
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
            }
        ]
    }
}
```

#### Human Readable Output
| Created Date Time    | ID   | Last Modified Date Time | Name                 | Web Url |
| -------------------- | ---- | ----------------------- | -------------------- | ------- |
| 2016-09-14T11:12:59Z | 123  | 2016-09-14T11:13:53Z    | 123                  | 123     |


### msgraph-download-file
***
Downloads the file contents of the drive item.


#### Base Command

`msgraph-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Can be "drives", "groups", "sites", or "users". | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Microsoft Graph Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Microsoft Graph User' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID.<br/>In order to get the ID of the file you want to download you can use the msgraph-list-drive-content command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The file size. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The file name. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | Unknown | The Cortex XSOAR file ID. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 


#### Command Example
```!msgraph-download-file object_type=drives object_type_id=123 item_id=123```
