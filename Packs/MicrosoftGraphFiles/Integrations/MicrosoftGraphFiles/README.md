Use the O365 File Management (Onedrive/Sharepoint/Teams) integration to enable your app to get authorized access to files in OneDrive, SharePoint, and MS Teams across your entire organization. This integration requires admin consent.
This integration was integrated and tested with version xx of Microsoft_Graph_Files.

## Configure O365 File Management (Onedrive/Sharepoint/Teams) in Cortex


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

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-delete-file

***
Deletes an item from OneDrive.

#### Base Command

`msgraph-delete-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The ID of the item to delete.<br/>To get the ID of the file you want to delete, use the msgraph-list-drive-content command. | Required | 

#### Context Output

There is no context output for this command.
### msgraph-upload-new-file

***
Uploads a file from Cortex XSOAR to the specified MS Graph resource.

#### Base Command

`msgraph-upload-new-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, users, sites. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
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

### msgraph-replace-existing-file

***
Replaces the content of the file in the specified MS Graph resource.

#### Base Command

`msgraph-replace-existing-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
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

### msgraph-create-new-folder

***
Creates a new folder in a drive with the specified parent item or path.

#### Base Command

`msgraph-create-new-folder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
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

### msgraph-list-drive-content

***
Returns a list of files and folders in the specified drive.

#### Base Command

`msgraph-list-drive-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
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

### msgraph-list-sharepoint-sites

***
Returns a list of the tenant sites. This command requires the 'Sites.Read.All' permission.

#### Base Command

`msgraph-list-sharepoint-sites`

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

### msgraph-download-file

***
Downloads the file contents of the drive item.

#### Base Command

`msgraph-download-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The MS Graph item ID.<br/>To get the ID of the file you want to download, use the msgraph-list-drive-content command. | Required | 
| file_name | The file name to download.<br/>Use msgraph-list-drive-content to retrieve the name of a file,<br/>if not provided, the file name will be the value of the item_id argument. | Optional | 

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

### msgraph-files-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-files-auth-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-list-site-permissions

***
List of apps with permissions for the site. if permission_id is provided, it will return the details of that permission.

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

### msgraph-create-site-permissions

***
Create a new application permission for a site.

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
### msgraph-update-site-permissions

***
Updates an existing permission for a site.

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
### msgraph-delete-site-permissions

***
Deletes an app permission from a site.

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
### msgraph-files-auth-test

***
Tests connectivity to Microsoft.

#### Base Command

`msgraph-files-auth-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-files-generate-login-url

***
Generate the login URL used for Authorization code flow.

#### Base Command

`msgraph-files-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-get-sensitivity-label

***
Retrieves the sensitivity label currently assigned to a drive item. Returns the label ID, display name, and protection state regardless of whether the label has encryption enabled.

#### Base Command

`msgraph-get-sensitivity-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The ID of the drive item to read the sensitivity label from. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.SensitivityLabel.itemId | String | The ID of the drive item the label was retrieved from. | 
| MsGraphFiles.SensitivityLabel.id | String | The GUID of the sensitivity label assigned to the drive item, or empty string when no label is assigned. | 
| MsGraphFiles.SensitivityLabel.displayName | String | The human-readable display name of the assigned sensitivity label, or empty string when no label is assigned. | 
| MsGraphFiles.SensitivityLabel.protectionEnabled | Boolean | True if the assigned label has encryption/protection settings; false for classification-only labels. Defaults to false when no label is assigned. | 

### msgraph-assign-sensitivity-label

***
Assigns a sensitivity label to a drive item. Microsoft Graph treats this call as a long-running operation and returns the operation status URL in the Location response header; poll that URL to track completion. HTTP error responses from Microsoft Graph are surfaced verbatim as a command error.

#### Base Command

`msgraph-assign-sensitivity-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The MS Graph resource. Possible values are: drives, groups, sites, users. | Required | 
| object_type_id | MS Graph resource ID.<br/>For resource type 'drive': To get a list of all drives in your site, use the msgraph-list-drives-in-site command.<br/>For resource type 'group': To get a list of all groups that exists, configure the 'Entra ID Groups' integration and use the msgraph-groups-list-groups command.<br/>For resource type 'sites': To get a list of all sites, use the msgraph-list-sharepoint-sites command.<br/>For resource type 'users': To get a list of all users that exists, configure the 'Entra ID Users' integration and use the msgraph-user-list command. | Required | 
| item_id | The ID of the drive item to assign the sensitivity label to. | Required | 
| sensitivity_label_id | The GUID of the sensitivity label to assign. Pass an empty string to remove the existing sensitivity label from the drive item. Retrieve label GUIDs from the Microsoft Purview compliance portal or via the PowerShell `Get-Label` cmdlet. | Required | 
| assignment_method | Assignment method recorded on Microsoft Graph.<br/>standard: a user-driven assignment.<br/>privileged: overrides existing user-applied labels.<br/>auto: recorded as a system-driven assignment. Possible values are: standard, privileged, auto. | Optional | 
| justification_text | Free-text justification recorded with the assignment. Required by Microsoft Graph when downgrading or replacing a user-assigned label. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraphFiles.AssignedSensitivityLabel.itemId | String | The ID of the drive item the label was assigned to. | 
| MsGraphFiles.AssignedSensitivityLabel.sensitivityLabelId | String | The GUID of the sensitivity label that was assigned. Empty string indicates the existing label was removed. | 
| MsGraphFiles.AssignedSensitivityLabel.location | String | URL returned in the Microsoft Graph Location response header. Microsoft Graph treats assignSensitivityLabel as a long-running operation; poll this URL to track the operation's completion status. | 
