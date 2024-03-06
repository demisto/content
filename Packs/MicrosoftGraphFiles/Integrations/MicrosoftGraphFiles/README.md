Use the O365 File Management (Onedrive/Sharepoint/Teams) integration to enable your app to get authorized access to files in OneDrive, SharePoint, and MS Teams across your entire organization. This integration requires admin consent.

## Authentication

For more details about the authentication used in this integration, see <a href="https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication">Microsoft Integrations - Authentication</a>.

### Required Permissions
The required permission depends on whether you want to access all sites (Sites.ReadWrite.All) or specific sites (Site.Selected):
- `Sites.ReadWrite.All`: Provides read and write access to all sites.  
`Client Credentials Flow` - Application permission.  
`Authorization Code Flow` - Delegated permission.  

Note: This permission is sufficient for all the commands, but if you want the least privileged permissions for each command, they are listed for each command definition.

OR
- `Sites.Selected - Application`: Provides read and write access to specific sites.  
This option is not supported with the `Authorization Code Flow` according to [Microsoft documentation](https://learn.microsoft.com/en-us/graph/permissions-reference#sitesselected).

Note: Using `Site.Selected` requires additional configuration steps outlined below.

### Steps to use the Site.Selected permission:

Two applications and two instances are required, one for the administrator and one for the user.

Configuration:

1. In the Microsoft website:
   1. Create "Admin" application with the `Sites.FullControl.All` permission.
   2. Create "User" application with the `Site.Selected - Application` permission.
2. In Cortex XSOAR, navigate to **Settings** > **Integrations**.
3. Search for O365 File Management (Onedrive/Sharepoint/Teams).
4. Create an admin instance:
    1. Click **Add instance** to create and configure a new integration instance.
    2. Enter the admin application credentials.
    3. Click **Test** to validate the connection.
    4. Use the following commands to give the user application access to specific sites:
        - `msgraph-list-site-permissions` - Get permissions for a site
        - `msgraph-create-site-permissions` - Add permissions for a site
        - `msgraph-update-site-permissions` - Update permissions for a site
        - `msgraph-delete-site-permissions` - Delete permissions for a site
    5. Delete the admin instance after configuring user access.
5. Create a user instance:
    1. Click **Add instance** to create and configure a new integration instance.
    2. Enter the user application credentials.
    3. Click **Test** to validate the connection.

Note: The `msgraph-list-sharepoint-sites` command cannot be run, as it requires the `Sites.Read.All - Application` permission.

- [YouTube tutorial](https://www.youtube.com/watch?v=pPfxHvugnTA) from Microsoft.
- [Microsoft documentation](https://learn.microsoft.com/en-us/graph/api/resources/permission?view=graph-rest-1.0).


## Configure O365 File Management (Onedrive/Sharepoint/Teams) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations**.
2. Search for O365 File Management (Onedrive/Sharepoint/Teams).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Application ID / Client ID |  | False |
    | Token / Tenant ID |  | False |
    | Key / Client Secret |  | False |
    | Application redirect URI (for Self Deployed - Authorization Code Flow) |  | False |
    | Authorization code (for Self Deployed - Authorization Code Flow) |  | False |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use a self-deployed Azure Application | Select this checkbox if you are using a self-deployed Azure application. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-delete-file

***
Deletes an item from OneDrive.

#### Base Command

`msgraph-delete-file`

#### Required Permissions

Client Credentials Flow - `Files.ReadWrite.All - Application`  
Authorization Code Flow - `Files.ReadWrite.All - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Azure Active Directory Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Azure Active Directory Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The ID of the item to delete.<br/>To get the ID of the file you want to delete, use the msgraph-list-drive-content command. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example

```!msgraph-delete-file object_type=drives object_type_id=test item_id=test```

#### Human Readable Output

>| 123 |
>| --- |
>| Item was deleted successfully |


### msgraph-upload-new-file

***
Uploads a file from Cortex XSOAR to the specified MS Graph resource.

#### Base Command

`msgraph-upload-new-file`

#### Required Permissions

Client Credentials Flow - `Sites.ReadWrite.All - Application`  
Authorization Code Flow - `Files.ReadWrite.All - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, users, sites. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Azure Active Directory Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Azure Active Directory Users' integration and use the msgraph-user-list command. | Required | 
| parent_id | The ID of the folder in which to upload the file.<br/>To get the ID of a folder, use the msgraph-list-drive-content command. | Required | 
| file_name | The name of the file to upload. | Required | 
| entry_id | The Cortex XSOAR entry ID of the file. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.UploadedFiles.ParentReference.DriveId | String | Unique identifier of the drive that contains the item. | 
| MsGraphFiles.UploadedFiles.ParentReference.DriveType | String | Identifies the drive type. | 
| MsGraphFiles.UploadedFiles.ParentReference.ID | String | Unique identifier of the item in the drive. | 
| MsGraphFiles.UploadedFiles.ParentReference.Path | String | The path of the item. | 
| MsGraphFiles.UploadedFiles.LastModifiedDateTime | String | The timestamp of when the item was last modified. | 
| MsGraphFiles.UploadedFiles.File.MimeType | String | The file type. | 
| MsGraphFiles.UploadedFiles.File.Hashes | String | The file hash type. | 
| MsGraphFiles.UploadedFiles.CreatedDateTime | String | The timestamp of when the item was created. | 
| MsGraphFiles.UploadedFiles.WebUrl | String | The URL of the resource in the browser. | 
| MsGraphFiles.UploadedFiles.OdataContext | String | The OData query. | 
| MsGraphFiles.UploadedFiles.FileSystemInfo.CreatedDateTime | String | The timestamp of when the item was created on a client. | 
| MsGraphFiles.UploadedFiles.FileSystemInfo.LastModifiedDateTime | String | The timestamp of when the item was last modified on a client. | 
| MsGraphFiles.UploadedFiles.LastModifiedBy.DisplayName | String | The item display name. | 
| MsGraphFiles.UploadedFiles.LastModifiedBy.Type | String | The application, user, or device that last modified the item. | 
| MsGraphFiles.UploadedFiles.CreatedBy.DisplayName | String | The identity of the user, device, or application that created the item. | 
| MsGraphFiles.UploadedFiles.CreatedBy.ID | String | The ID of the creator. | 
| MsGraphFiles.UploadedFiles.CreatedBy.Type | String | The application, user, or device that created the item. | 
| MsGraphFiles.UploadedFiles.DownloadUrl | String | The URL to download this file's content. | 
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

>| CreatedBy       | CreatedDateTime      | ID   | LastModifiedBy  | Name     | Size | WebUrl |
>| --- | --- | --- | --- | --- | --- | --- |
>| Microsoft Graph | 2020-01-22T20:03:00Z | Test | Microsoft Graph | test.txt | 15   | Test   |


### msgraph-replace-existing-file

***
Replaces the content of the file in the specified MS Graph resource.

#### Base Command

`msgraph-replace-existing-file`

#### Required Permissions

Client Credentials Flow - `Sites.ReadWrite.All - Application`  
Authorization Code Flow - `Files.ReadWrite.All - Delegated`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Azure Active Directory Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Azure Active Directory Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID of the file you want to replace.<br/>To get the ID of the file you want to replace, use the msgraph-list-drive-content command. | Required | 
| entry_id | The Cortex XSOAR entry ID of the new file that will replace the current file. | Required | 

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
| MsGraphFiles.ReplacedFiles.Size | Number | File's size. | 
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

>### MsGraphFiles - File information:

>| Created By     | Created Date Time    | ID   | Last Modified By | Name     | Size | Web Url |
>| -------------- | -------------------- | ---- | ---------------- | -------- | ---- | ------- |
>| SharePoint DEV | 2020-01-05T15:30:21Z | 123  | Microsoft Graph  | yaya.txt | 15   | 123     |


### msgraph-create-new-folder

***
Creates a new folder in a drive with the specified parent item or path.

#### Base Command

`msgraph-create-new-folder`

#### Required Permissions

Client Credentials Flow - `Files.ReadWrite.All - Application`  
Authorization Code Flow - `Files.ReadWrite.All - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Azure Active Directory Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Azure Active Directory Users' integration and use the msgraph-user-list command. | Required | 
| parent_id | The ID of the parent in which to upload the new folder.<br/>Parent can be either 'root' or another folder.<br/>To get the required folder ID, use the msgraph-list-drive-content command. | Required | 
| folder_name | The name of the new folder. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Folder | Unknown | The MS Graph folder object. | 
| Msgraphfiles.CreatedFolder.ParentReference.DriveId | String | Unique identifier of the drive that contains the item. | 
| Msgraphfiles.CreatedFolder.ParentReference.DriveType | String | The drive type. | 
| Msgraphfiles.CreatedFolder.ParentReference.ID | String | Unique identifier of the item in the drive. | 
| Msgraphfiles.CreatedFolder.ParentReference.Path | String | The path to the item. | 
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

>### MsGraphFiles - Folder information:

>| Child Count   | Created By      | Created Date Time    | ID   | Last Modified By | Name      | Size | Web Url |
>| --- | --- | --- | --- | --- | --- | --- | --- |
>| ChildCount: 0 | Microsoft Graph | 2020-01-22T20:03:09Z | 123  | Microsoft Graph  | test11 19 | 0    | 123     |


### msgraph-list-drives-in-site

***
Returns the list of document libraries (drives) available for a target site.

#### Base Command

`msgraph-list-drives-in-site`

#### Required Permissions

Client Credentials Flow - `Files.Read.All - Application`  
Authorization Code Flow - `Files.Read - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | The ID of the site for which to return available drive resources.<br/>To find a list of all sites, use the msgraph-list-sharepoint-sites command. | Optional | 
| limit | The maximum number of results to return. | Optional | 
| next_page_url | The URL for the next results page.<br/>If a next page of results exists, you will find it in the Cortex XSOAR context under MsGraphFiles.ListDrives.OdataNextLink. | Optional | 

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
| MsGraphFiles.ListDrives.NextToken | String | The token for the next page. |

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

>### MsGraphFiles - Drives information:

>| Created By     | Created Date Time    | Description | Drive Type      | ID   | Last Modified Date Time | Name      | Web Url |
>| -------------- | -------------------- | ----------- | --------------- | ---- | ----------------------- | --------- | ------- |
>| System Account | 2019-09-21T08:17:20Z |             | documentLibrary | Test | 2019-09-21T08:17:20Z    | Documents | Test    |


### msgraph-list-drive-content

***
Returns a list of files and folders in the specified drive.

#### Base Command

`msgraph-list-drive-content`

#### Required Permissions

Client Credentials Flow - `Files.Read.All - Application`  
Authorization Code Flow - `Files.Read - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Azure Active Directory Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Azure Active Directory Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID.<br/>It can be either 'root' or another folder.<br/>Passing a folder ID retrieves files from a specified folder.<br/>The default is 'root': It retrieves the content in the root of the drive.<br/><br/>To get the required folder ID, use the msgraph-list-drive-content command and leave the argument empty in order to get a list of folders that are located in the root.<br/><br/>If your folder is nested inside another folder, pass the parent ID found when running the msgraph-list-drive-content command without an 'item_id' in this argument to get the required folder ID. | Optional | 
| limit | The maximum number of results to return. | Optional | 
| next_page_url | The URL for the next results page.<br/>If a next page of results exists, you will find it in the Cortex XSOAR context under MsGraphFiles.ListChildren.OdataNextLink. | Optional | 

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
| MsGraphFiles.ListChildren.NextToken | String | The token for the next page. |


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

>### MsGraphFiles - drivesItems information:

>| Created By         | Created Date Time    | Description | ID   | Last Modified Date Time | Name        | Size | Web Url |
>| ------------------ | -------------------- | ----------- | ---- | ----------------------- | ----------- | ---- | ------- |
>| MS Graph Files Dev | 2019-12-29T11:57:41Z |             | 123  | 2019-12-29T11:57:41Z    | Attachments | 0    | 123     |


### msgraph-list-sharepoint-sites

***
Returns a list of the tenant sites.

#### Base Command

`msgraph-list-sharepoint-sites`

#### Required Permissions

Client Credentials Flow - `Sites.Read.All - Application`  
Authorization Code Flow - `Sites.Read.All - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | Keyword used to search for sites across a SharePoint tenant. If a keyword is not provided, it returns all sites. | Optional | 

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
                "DisplayName": "XSOAR Team",
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

>| Created Date Time    | ID   | Last Modified Date Time | Name                 | Web Url |
>| -------------------- | ---- | ----------------------- | -------------------- | ------- |
>| 2016-09-14T11:12:59Z | 123  | 2016-09-14T11:13:53Z    | 123                  | 123     |


### msgraph-download-file

***
Downloads the file contents of the drive item.

#### Base Command

`msgraph-download-file`

#### Required Permissions

Client Credentials Flow - `Files.Read.All - Application`  
Authorization Code Flow - `Files.Read - Delegated`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Azure Active Directory Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Azure Active Directory Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID.<br/>To get the ID of the file you want to download, use the msgraph-list-drive-content command. | Required | 
| file_name | The file name to download.<br/>Use msgraph-list-drive-content to retrieve the name of a file, if not provided, the file name will be the value of the item_id argument. | Optional |

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


### msgraph-list-site-permissions

***
List of apps with permissions for the site. If permission_id is provided, it will return the details of that permission.

#### Required Permissions

`Sites.FullControl.All`
The command only runs from admin instance.

#### Base Command

`msgraph-list-site-permissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 50. | Optional | 
| site_id | The ID of the site. Required if site_name is not provided.<br/>To find a list of all sites, use the msgraph-list-sharepoint-sites command. | Optional | 
| site_name | The name of the site. Required if site_id is not provided. | Optional | 
| permission_id | The ID of the permission. | Optional | 
| all_results | Whether to retrieve all the apps with permission for the site. If true, the "limit" argument will be ignored. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.SitePermission.id | String | The unique identifier of the permission among all permissions on the item. | 
| MsGraphFiles.SitePermission.roles | List | The type of permission, for example, read. | 
| MsGraphFiles.SitePermission.grantedToIdentitiesV2.application.id | String | Unique identifier for the application. | 
| MsGraphFiles.SitePermission.grantedToIdentitiesV2.application.displayName | String | The display name of the application. The display name might not always be available or up to date. | 

#### Command example

```!msgraph-list-site-permissions site_name=Test```

#### Context Example

```json
{
    "MsGraphFiles": {
        "SitePermission": [
            {
                "grantedToIdentities": [
                    {
                        "application": {
                            "displayName": "MS Graph Files",
                            "id": "test_id"
                        }
                    }
                ],
                "grantedToIdentitiesV2": [
                    {
                        "application": {
                            "displayName": "MS Graph Files",
                            "id": "test_id"
                        }
                    }
                ],
                "id": "test_id"
            },
            {
                "grantedToIdentities": [
                    {
                        "application": {
                            "displayName": "test_admin",
                            "id": "test_id"
                        }
                    }
                ],
                "grantedToIdentitiesV2": [
                    {
                        "application": {
                            "displayName": "test_admin",
                            "id": "test_id"
                        }
                    }
                ],
                "id": "test_id"
            }
        ]
    }
}
```

#### Human Readable Output

>### Site Permission

>|Application ID|Application Name|ID|
>|---|---|---|
>| test_id | MS Graph Files | test_id |
>| test_id | test_sk_1_admin | test_id |


### msgraph-create-site-permissions

***
Create a new application permission for a site.

#### Required Permissions

`Sites.FullControl.All`
The command only runs from admin instance.

#### Base Command

`msgraph-create-site-permissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | The ID of the site. Required if site_name is not provided.<br/>To find a list of all sites, use the msgraph-list-sharepoint-sites command. | Optional | 
| site_name | The name of the site. Required if site_id is not provided. | Optional | 
| role | read: Provides the ability to read the metadata and contents of the item.<br/>write: Provides the ability to read and modify the metadata and contents of the item.<br/>owner: Site owners can create and manage lists, libraries, and pages within their site, as well as manage user access and permissions. Possible values are: read, write, owner. | Required | 
| app_id | The ID of the application. | Required | 
| display_name | The display name of the application. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-create-site-permissions site_name=Test role=write app_id=test_id display_name=test```

#### Context Example

```json
{
    "MsGraphFiles": {
        "SitePermission": {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#sites(test)/permissions/$entity",
            "grantedToIdentities": [
                {
                    "application": {
                        "displayName": "test",
                        "id": "test_id"
                    }
                }
            ],
            "grantedToIdentitiesV2": [
                {
                    "application": {
                        "displayName": "test",
                        "id": "test_id"
                    }
                }
            ],
            "id": "test_id",
            "roles": [
                "write"
            ]
        }
    }
}
```

#### Human Readable Output

>### Site Permission

>|Application ID|Application Name|ID|Roles|
>|---|---|---|---|
>| test | test | test | write |


### msgraph-update-site-permissions

***
Updates an existing permission for a site.

#### Required Permissions

`Sites.FullControl.All`
The command only runs from admin instance.

#### Base Command

`msgraph-update-site-permissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_name | The name of the site. Required if site_id is not provided. | Optional | 
| site_id | The ID of the site. Required if site_name is not provided.<br/>To find a list of all sites, use the msgraph-list-sharepoint-sites command. | Optional | 
| permission_id | The unique identifier of the permission to update. | Required | 
| role | read: Provides the ability to read the metadata and contents of the item.<br/>write: Provides the ability to read and modify the metadata and contents of the item.<br/>owner: Site owners can create and manage lists, libraries, and pages within their site, as well as manage user access and permissions. Possible values are: read, write, owner. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-update-site-permissions permission_id=test role=read site_name=Test```

#### Human Readable Output

>Permission test_id of site site_id was updated successfully with new role ['read'].

### msgraph-delete-site-permissions

***
Deletes an app permission from a site.

#### Required Permissions

`Sites.FullControl.All`
The command only runs from admin instance.

#### Base Command

`msgraph-delete-site-permissions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Unique identifier for SharePoint site. Required if site_name is not provided.<br/>To find a list of all sites, use the msgraph-list-sharepoint-sites command. | Optional | 
| site_name | The name of the site. Required if site_id is not provided. | Optional | 
| permission_id | The unique identifier of the permission to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msgraph-delete-site-permissions site_name=Test permission_id=test_id```

#### Human Readable Output

>Site permission was deleted.

### msgraph-files-auth-test

***
Tests connectivity to Microsoft.

#### Base Command

`msgraph-files-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### msgraph-files-generate-login-url

***
Generate the login URL used for Authorization code flow.

#### Base Command

`msgraph-files-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msgraph-files-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-files-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
