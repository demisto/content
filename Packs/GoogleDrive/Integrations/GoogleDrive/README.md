Google Drive allows users to store files on their servers, synchronize files across devices, and share files. This integration helps you to create a new drive, query past activity, and view change logs performed by the users.
This integration was integrated and tested with version 1.31.0 of GoogleDrive

## Configure Google Drive in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| User's Service Account JSON |  | False |
| User ID | The primary email address of the user to fetch the incident\(s\). | False |
| User ID |  | False |
| User's Service Account JSON |  | False |
| Action Detail Case Include | Action types to include for fetching the incident. | False |
| Drive Item Search Field | itemName - Fetch activities for this drive item. The format is "items/ITEM_ID". folderName - Fetch activities for this drive folder and all children and descendants. The format is "items/ITEM_ID". | False |
| Drive Item Search Value | itemName or folderName for fetching the incident. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Max Incidents | The maximum number of incidents to fetch each time. | False |
| First Fetch Time Interval | The time range to consider for the initial data fetch in the format &lt;number&gt; &lt;unit&gt; e.g., 1 hour, 2 hours, 6 hours, 12 hours, 24 hours, 48 hours. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### google-drive-create

***
Deprecated. Use the `google-drive-drive-create` command instead.


### google-drive-drive-create

***
Creates a new Team Drive. The name argument specifies the name of the Team Drive. The specified user will be the first organizer.
This shared drive/team drive feature is available only with G Suite Enterprise, Enterprise for Education, G Suite Essentials, Business, Education, and Nonprofits edition.

#### Base Command

`google-drive-drive-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's primary email address. | Optional | 
| name | The name of this shared drive. | Required | 
| hidden | Whether the shared drive is hidden from the default view. Possible values: "True" and "False". Possible values are: True, False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.Drive.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.Drive.id | String | The ID of the shared drive which is also the ID of the top level folder of the shared drive. | 
| GoogleDrive.Drive.name | String | The name of the shared drive. | 
| GoogleDrive.Drive.hidden | Boolean | Whether the shared drive is hidden from the default view. | 

### google-drive-changes-list

***
Lists the changes for a user or shared drive.

#### Base Command

`google-drive-changes-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_token | The token for continuing a previous list request on the next page. | Required | 
| user_id | The user's primary email address. | Optional | 
| drive_id | The shared drive from which changes are returned. Can be retrieved using the `google-drive-drives-list` command. | Optional | 
| include_corpus_removals | Whether changes should include the file resource if the file is still accessible by the user at the time of the request, even when a file was removed from the list of changes and there will be no further change entries for this file. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| include_items_from_all_drives | Whether both My Drive and shared drive items should be included in the results. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| include_permissions_for_view | Specifies which additional view's permissions to include in the response. Only 'published' is supported. | Optional | 
| include_removed | Whether to include changes indicating that items have been removed from the list of changes, for example by deletion or loss of access. Possible values: "true" and "false". Possible values are: true, false. Default is true. | Optional | 
| page_size | The maximum number of changes to return per page. Acceptable values are 1 to 1000, inclusive. Default is 100. | Optional | 
| restrict_to_my_drive | Whether to restrict the results to changes inside the My Drive hierarchy. This omits changes to files such as those in the Application Data folder or shared files which have not been added to My Drive. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| spaces | A comma-separated list of spaces to query within the user corpus. Possible values are 'drive', 'appDataFolder', and 'photos'. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| fields | The paths of the fields you want to include in the response. Possible values are: "basic" (the response will include a default set of fields specific to this method) and "advance" (you can use the value * to return all the fields). Possible values are: basic, advance. Default is basic. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.PageToken.DriveChange.nextPageToken | String | The page token for the next page of changes. | 
| GoogleDrive.PageToken.DriveChange.newStartPageToken | String | The starting page token for future changes. | 
| GoogleDrive.PageToken.DriveChange.driveId | String | The ID of the shared drive associated with this change. | 
| GoogleDrive.PageToken.DriveChange.userId | String | The user's primary email address. | 
| GoogleDrive.DriveChange.userId | String | The user's primary email address. | 
| GoogleDrive.DriveChange.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.changeType | String | The type of the change. Possible values are "file" and "drive". | 
| GoogleDrive.DriveChange.time | Date | The time of this change \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.removed | Boolean | Whether the file or shared drive has been removed from this list of changes, for example by deletion or loss of access. | 
| GoogleDrive.DriveChange.fileId | String | The ID of the file which has changed. | 
| GoogleDrive.DriveChange.driveId | String | The ID of the shared drive associated with this change. | 
| GoogleDrive.DriveChange.file.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.id | String | The ID of the file. | 
| GoogleDrive.DriveChange.file.name | String | The name of the file. | 
| GoogleDrive.DriveChange.file.mimeType | String | The MIME type of the file. | 
| GoogleDrive.DriveChange.file.description | String | A short description of the file. | 
| GoogleDrive.DriveChange.file.starred | Boolean | Whether the user has starred the file. | 
| GoogleDrive.DriveChange.file.trashed | Boolean | Whether the file has been trashed, either explicitly or from a trashed parent folder. Only the owner may trash a file. | 
| GoogleDrive.DriveChange.file.explicitlyTrashed | Boolean | Whether the file has been explicitly trashed, as opposed to recursively trashed from a parent folder. | 
| GoogleDrive.DriveChange.file.trashingUser.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.trashingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.DriveChange.file.trashingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.DriveChange.file.trashingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.DriveChange.file.trashingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.DriveChange.file.trashingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.DriveChange.file.trashedTime | Date | The time that the item was trashed \(RFC 3339 date-time\). Only populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.parents | Unknown | The IDs of the parent folders which contain the file. | 
| GoogleDrive.DriveChange.file.properties | Unknown | A collection of arbitrary key-value pairs which are visible to all apps. | 
| GoogleDrive.DriveChange.file.appProperties | Unknown | A collection of arbitrary key-value pairs which are private to the requesting app. | 
| GoogleDrive.DriveChange.file.spaces | Unknown | The list of spaces which contain the file. The currently supported values are 'drive', 'appDataFolder' and 'photos'. | 
| GoogleDrive.DriveChange.file.version | Number | A monotonically increasing version number for the file. This reflects every change made to the file on the server, even those not visible to the user. | 
| GoogleDrive.DriveChange.file.webContentLink | String | A link for downloading the content of the file in a browser. This is only available for files with binary content in Google Drive. | 
| GoogleDrive.DriveChange.file.webViewLink | String | A link for opening the file in a relevant Google editor or viewer in a browser. | 
| GoogleDrive.DriveChange.file.iconLink | String | A static, unauthenticated link to the file's icon. | 
| GoogleDrive.DriveChange.file.hasThumbnail | Boolean | Whether this file has a thumbnail. | 
| GoogleDrive.DriveChange.file.thumbnailLink | String | A short-lived link to the file's thumbnail, if available. | 
| GoogleDrive.DriveChange.file.thumbnailVersion | Number | The thumbnail version for use in thumbnail cache invalidation. | 
| GoogleDrive.DriveChange.file.viewedByMe | Boolean | Whether the file has been viewed by this user. | 
| GoogleDrive.DriveChange.file.viewedByMeTime | Date | The last time the file was viewed by the user \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.file.createdTime | Date | The time at which the file was created \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.file.modifiedTime | Date | The last time the file was modified by anyone \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.file.modifiedByMeTime | Date | The last time the file was modified by the user \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.file.modifiedByMe | Boolean | Whether the file has been modified by the user. | 
| GoogleDrive.DriveChange.file.sharedWithMeTime | Date | The time at which the file was shared with the user, if applicable \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.file.sharingUser.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.sharingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.DriveChange.file.sharingUser.photoLink | Date | A link to the user's profile photo, if available. | 
| GoogleDrive.DriveChange.file.sharingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.DriveChange.file.sharingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.DriveChange.file.sharingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.DriveChange.file.owners.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.owners.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.DriveChange.file.owners.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.DriveChange.file.owners.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.DriveChange.file.owners.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.DriveChange.file.owners.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.DriveChange.file.driveId | String | ID of the shared drive the file resides in. Only populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.lastModifyingUser.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.lastModifyingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.DriveChange.file.lastModifyingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.DriveChange.file.lastModifyingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.DriveChange.file.lastModifyingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.DriveChange.file.lastModifyingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.DriveChange.file.shared | Boolean | Whether the file has been shared. Not populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.ownedByMe | Boolean | Whether the user owns the file. Not populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.capabilities.canAddChildren | Boolean | Whether the current user can add children to this folder. This is always false when the item is not a folder. | 
| GoogleDrive.DriveChange.file.capabilities.canAddFolderFromAnotherDrive | Boolean | Whether the current user can add a folder from another drive \(different shared drive or My Drive\) to this folder. | 
| GoogleDrive.DriveChange.file.capabilities.canAddMyDriveParent | Boolean | Whether the current user can add a parent for the item without removing an existing parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.DriveChange.file.capabilities.canChangeCopyRequiresWriterPermission | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this file. | 
| GoogleDrive.DriveChange.file.capabilities.canComment | Boolean | Whether the current user can comment on this file. | 
| GoogleDrive.DriveChange.file.capabilities.canCopy | Boolean | Whether the current user can copy this file. | 
| GoogleDrive.DriveChange.file.capabilities.canDelete | Boolean | Whether the current user can delete this file. | 
| GoogleDrive.DriveChange.file.capabilities.canDeleteChildren | Boolean | Whether the current user can delete children of this folder. This is false when the item is not a folder. Only populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.capabilities.canDownload | Boolean | Whether the current user can download this file. | 
| GoogleDrive.DriveChange.file.capabilities.canEdit | Boolean | Whether the current user can edit this file. | 
| GoogleDrive.DriveChange.file.capabilities.canListChildren | Boolean | Whether the current user can list the children of this folder. This is always false when the item is not a folder. | 
| GoogleDrive.DriveChange.file.capabilities.canModifyContent | Boolean | Whether the current user can modify the content of this file. | 
| GoogleDrive.DriveChange.file.capabilities.canModifyContentRestriction | Boolean | Whether the current user can modify restrictions on content of this file. | 
| GoogleDrive.DriveChange.file.capabilities.canMoveChildrenOutOfDrive | Boolean | Whether the current user can move children of this folder outside of the shared drive. | 
| GoogleDrive.DriveChange.file.capabilities.canMoveChildrenWithinDrive | Boolean | Whether the current user can move children of this folder within this drive. | 
| GoogleDrive.DriveChange.file.capabilities.canMoveItemOutOfDrive | Boolean | Whether the current user can move this item outside of this drive by changing its parent. | 
| GoogleDrive.DriveChange.file.capabilities.canMoveItemWithinDrive | Boolean | Whether the current user can move this item within this drive. | 
| GoogleDrive.DriveChange.file.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of this file. | 
| GoogleDrive.DriveChange.file.capabilities.canReadDrive | Boolean | Whether the current user can read the shared drive to which this file belongs. Only populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.capabilities.canRemoveChildren | Boolean | Whether the current user can remove children from this folder. | 
| GoogleDrive.DriveChange.file.capabilities.canRemoveMyDriveParent | Boolean | Whether the current user can remove a parent from the item without adding another parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.DriveChange.file.capabilities.canRename | Boolean | Whether the current user can rename this file. | 
| GoogleDrive.DriveChange.file.capabilities.canShare | Boolean | Whether the current user can modify the sharing settings for this file. | 
| GoogleDrive.DriveChange.file.capabilities.canTrash | Boolean | Whether the current user can move this file to trash. | 
| GoogleDrive.DriveChange.file.capabilities.canTrashChildren | Boolean | Whether the current user can trash children of this folder. This is false when the item is not a folder. Only populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.capabilities.canUntrash | Boolean | Whether the current user can restore this file from trash. | 
| GoogleDrive.DriveChange.file.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download this file, should be disabled for readers and commenters. | 
| GoogleDrive.DriveChange.file.writersCanShare | Boolean | Whether users with only writer permission can modify the file's permissions. Not populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.permissions.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.permissions.id | String | The ID of this permission. | 
| GoogleDrive.DriveChange.file.permissions.type | String | The type of the grantee. | 
| GoogleDrive.DriveChange.file.permissions.emailAddress | String | The email address of the user or group to which this permission refers. | 
| GoogleDrive.DriveChange.file.permissions.domain | String | The domain to which this permission refers. | 
| GoogleDrive.DriveChange.file.permissions.role | String | The role granted by this permission. | 
| GoogleDrive.DriveChange.file.permissions.view | String | Indicates the view for this permission. | 
| GoogleDrive.DriveChange.file.permissions.allowFileDiscovery | Boolean | Whether the permission allows the file to be discovered through search. | 
| GoogleDrive.DriveChange.file.permissions.displayName | String | The "pretty" name of the value of the permission. | 
| GoogleDrive.DriveChange.file.permissions.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.DriveChange.file.permissions.expirationTime | Date | The time at which this permission will expire \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.file.permissions.permissionDetails.permissionType | String | The permission type for this user. | 
| GoogleDrive.DriveChange.file.permissions.permissionDetails.role | String | The primary role for this user. | 
| GoogleDrive.DriveChange.file.permissions.permissionDetails.inheritedFrom | String | The ID of the item from which this permission is inherited. | 
| GoogleDrive.DriveChange.file.permissions.permissionDetails.inherited | Boolean | Whether this permission is inherited. | 
| GoogleDrive.DriveChange.file.permissions.deleted | Boolean | Whether the account associated with this permission has been deleted. | 
| GoogleDrive.DriveChange.file.permissionIds | Unknown | List of permission IDs for users with access to this file. | 
| GoogleDrive.DriveChange.file.hasAugmentedPermissions | Boolean | Whether there are permissions directly on this file. This field is only populated for items in shared drives. | 
| GoogleDrive.DriveChange.file.folderColorRgb | String | The color for a folder as an RGB hex string. | 
| GoogleDrive.DriveChange.file.originalFilename | String | The original filename of the uploaded content if available, or else the original value of the name field. This is only available for files with binary content in Google Drive. | 
| GoogleDrive.DriveChange.file.fullFileExtension | String | The full file extension extracted from the name field. | 
| GoogleDrive.DriveChange.file.fileExtension | String | The final component of fullFileExtension. This is only available for files with binary content in Google Drive. | 
| GoogleDrive.DriveChange.file.md5Checksum | String | The MD5 checksum for the content of the file. This is only applicable to files with binary content in Google Drive. | 
| GoogleDrive.DriveChange.file.size | Number | The size of the file's content in bytes. This is only applicable to files with binary content in Google Drive. | 
| GoogleDrive.DriveChange.file.quotaBytesUsed | Number | The number of storage quota bytes used by the file. This includes the head revision as well as previous revisions with keepForever enabled. | 
| GoogleDrive.DriveChange.file.headRevisionId | String | The ID of the file's head revision. This is currently only available for files with binary content in Google Drive. | 
| GoogleDrive.DriveChange.file.contentHints.thumbnail.image | Unknown | The thumbnail data encoded with URL-safe Base64 \(RFC 4648 section 5\). | 
| GoogleDrive.DriveChange.file.contentHints.thumbnail.mimeType | String | The MIME type of the thumbnail. | 
| GoogleDrive.DriveChange.file.contentHints.indexableText | String | Text to be indexed for the file to improve fullText queries. This is limited to 128KB in length and may contain HTML elements. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.width | Number | The width of the image in pixels. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.height | Number | The height of the image in pixels. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.rotation | Number | The number of clockwise 90 degree rotations applied from the image's original orientation. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.location.latitude | Number | The latitude stored in the image. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.location.longitude | Number | The longitude stored in the image. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.location.altitude | Number | The altitude stored in the image. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.time | String | The date and time the photo was taken \(EXIF DateTime\). | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.cameraMake | String | The make of the camera used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.cameraModel | String | The model of the camera used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.exposureTime | Number | The length of the exposure, in seconds. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.aperture | Number | The aperture used to create the photo \(f-number\). | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.flashUsed | Boolean | Whether a flash was used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.focalLength | Number | The focal length used to create the photo, in millimeters. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.isoSpeed | Number | The ISO speed used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.meteringMode | String | The metering mode used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.sensor | String | The type of sensor used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.exposureMode | String | The exposure mode used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.colorSpace | String | The color space of the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.whiteBalance | String | The white balance mode used to create the photo. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.exposureBias | Number | The exposure bias of the photo \(APEX value\). | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.maxApertureValue | Number | The smallest f-number of the lens at the focal length used to create the photo \(APEX value\). | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.subjectDistance | Number | The distance to the subject of the photo, in meters. | 
| GoogleDrive.DriveChange.file.imageMediaMetadata.lens | String | The lens used to create the photo. | 
| GoogleDrive.DriveChange.file.videoMediaMetadata.width | Number | The width of the video in pixels. | 
| GoogleDrive.DriveChange.file.videoMediaMetadata.height | Number | The height of the video in pixels. | 
| GoogleDrive.DriveChange.file.videoMediaMetadata.durationMillis | Number | The duration of the video in milliseconds. | 
| GoogleDrive.DriveChange.file.isAppAuthorized | Boolean | Whether the file was created or opened by the requesting app. | 
| GoogleDrive.DriveChange.file.exportLinks | Unknown | Links for exporting Google Docs to specific formats. | 
| GoogleDrive.DriveChange.file.shortcutDetails.targetId | String | The ID of the file that this shortcut points to. | 
| GoogleDrive.DriveChange.file.shortcutDetails.targetMimeType | String | The MIME type of the file that this shortcut points to. The value of this field is a snapshot of the target's MIME type, captured when the shortcut is created. | 
| GoogleDrive.DriveChange.file.contentRestrictions.readOnly | Boolean | Whether the content of the file is read-only. | 
| GoogleDrive.DriveChange.file.contentRestrictions.reason | String | Reason for why the content of the file is restricted. This is only mutable on requests that also set readOnly=true. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictingUser.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.DriveChange.file.contentRestrictions.restrictionTime | Date | The time at which the content restriction was set \(formatted RFC 3339 timestamp\). Only populated if readOnly is true. | 
| GoogleDrive.DriveChange.file.contentRestrictions.type | String | The type of the content restriction. Currently the only possible value is globalContentRestriction. | 
| GoogleDrive.DriveChange.drive.kind | String | Identifies what kind of resource this is. | 
| GoogleDrive.DriveChange.drive.id | String | The ID of this shared drive which is also the ID of the top level folder of this shared drive. | 
| GoogleDrive.DriveChange.drive.name | String | The name of this shared drive. | 
| GoogleDrive.DriveChange.drive.themeId | String | The ID of the theme from which the background image and color will be set. | 
| GoogleDrive.DriveChange.drive.colorRgb | String | The color of this shared drive as an RGB hex string. It can only be set on a drive.drives.update request that does not set themeId. | 
| GoogleDrive.DriveChange.drive.backgroundImageFile.id | String | The ID of an image file in Google Drive to use for the background image. | 
| GoogleDrive.DriveChange.drive.backgroundImageFile.xCoordinate | Number | The X coordinate of the upper left corner of the cropping area in the background image. | 
| GoogleDrive.DriveChange.drive.backgroundImageFile.yCoordinate | Number | The Y coordinate of the upper left corner of the cropping area in the background image. | 
| GoogleDrive.DriveChange.drive.backgroundImageFile.width | Number | The width of the cropped image in the closed range of 0 to 1. | 
| GoogleDrive.DriveChange.drive.backgroundImageLink | String | A short-lived link to this shared drive's background image. | 
| GoogleDrive.DriveChange.drive.capabilities.canAddChildren | Boolean | Whether the current user can add children to folders in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canChangeCopyRequiresWriterPermissionRestriction | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canChangeDomainUsersOnlyRestriction | Boolean | Whether the current user can change the 'domain users only' restriction of this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canChangeDriveBackground | Boolean | Whether the current user can change the background of this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canChangeDriveMembersOnlyRestriction | Boolean | Whether the current user can change the 'drive members only' restriction of this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canComment | Boolean | Whether the current user can comment on files in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canCopy | Boolean | Whether the current user can copy files in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canDeleteChildren | Boolean | Whether the current user can delete children from folders in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canDeleteDrive | Boolean | Whether the current user can delete this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canDownload | Boolean | Whether the current user can download files in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canEdit | Boolean | Whether the current user can edit files in this shared drive | 
| GoogleDrive.DriveChange.drive.capabilities.canListChildren | Boolean | Whether the current user can list the children of folders in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canManageMembers | Boolean | Whether the current user can add members to this shared drive or remove them or change their role. | 
| GoogleDrive.DriveChange.drive.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of files in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canRename | Boolean | Whether the current user can rename files or folders in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canRenameDrive | Boolean | Whether the current user can rename this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canShare | Boolean | Whether the current user can share files or folders in this shared drive. | 
| GoogleDrive.DriveChange.drive.capabilities.canTrashChildren | Boolean | Whether the current user can trash children from folders in this shared drive. | 
| GoogleDrive.DriveChange.drive.createdTime | Date | The time at which the shared drive was created \(RFC 3339 date-time\). | 
| GoogleDrive.DriveChange.drive.hidden | Boolean | Whether the shared drive is hidden from the default view. | 
| GoogleDrive.DriveChange.drive.restrictions.adminManagedRestrictions | Boolean | Whether administrative privileges on this shared drive are required to modify restrictions. | 
| GoogleDrive.DriveChange.drive.restrictions.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download files inside this shared drive, should be disabled for readers and commenters. | 
| GoogleDrive.DriveChange.drive.restrictions.domainUsersOnly | Boolean | Whether access to this shared drive and items inside this shared drive is restricted to users of the domain to which this shared drive belongs. | 
| GoogleDrive.DriveChange.drive.restrictions.driveMembersOnly | Boolean | Whether access to items inside this shared drive is restricted to its members. | 

### google-drive-activity-list

***
Query past activity in Google Drive.

#### Base Command

`google-drive-activity-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's primary email address. | Optional | 
| folder_name | Return activities for this drive folder and all children and descendants. The format is "items/ITEM_ID". | Optional | 
| item_name | Return activities for this drive item. The format is "items/ITEM_ID". | Optional | 
| filter | The filtering for items returned from this query request. The format of the filter string is a sequence of expressions, joined by an optional "AND", where each expression is of the form "field operator value".<br/><br/>Supported fields:<br/>time - Uses numerical operators on date values either in terms of milliseconds since Jan 1, 1970 or in RFC 3339 format.<br/>Examples:<br/>time &gt; 1452409200000 AND time &lt;= 1492812924310<br/>time &gt;= "2016-01-10T01:02:03-05:00"<br/><br/>detail.action_detail_case - Uses the "has" operator (:) and either a singular value or a list of allowed action types enclosed in parentheses.<br/>Examples:<br/>detail.action_detail_case: RENAME<br/>detail.action_detail_case:(CREATE EDIT)<br/>-detail.action_detail_case:MOVE". | Optional | 
| time_range | The time range to consider for getting drive activity. Use the format "&lt;number&gt; &lt;time unit&gt;". <br/>Example: 12 hours, 7 days, 3 months, 1 year. This argument will override if the filter argument is given. | Optional | 
| action_detail_case_include | A singular value or a list of allowed action types enclosed in parentheses. The filters are based on given actions. For example: <br/>RENAME <br/>(CREATE EDIT)<br/>This argument will override if the filter argument is given. | Optional | 
| action_detail_case_remove | A singular value or a list of allowed action types enclosed in parentheses. The filters are based on given actions. For example:<br/>RENAME <br/>(CREATE EDIT)<br/>This argument will override if the filter argument is given. | Optional | 
| page_token | The token identifying which page of results to return. Set this to the nextPageToken value returned from a previous query to obtain the following page of results. If not set, the first page of results will be returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.PageToken.DriveActivity.nextPageToken | String | Token to retrieve the next page of results, or empty if there are no more results in the list. | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.new | Boolean | If true, the object was newly created. | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.upload | Boolean | If true, the object originated externally and was uploaded to Drive. | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.copy.originalObject.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.create.copy.originalObject.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.primaryActionDetail.edit | Boolean | If true, the object was edited. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.addedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.addedParents.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.addedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.addedParents.driveItem.driveFolder.type | String | The type of a Drive folder. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.addedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.addedParents.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.removedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.removedParents.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.removedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.removedParents.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.removedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.move.removedParents.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.primaryActionDetail.rename.oldTitle | String | The previous title of the drive object. | 
| GoogleDrive.DriveActivity.primaryActionDetail.rename.newTitle | String | The new title of the drive object. | 
| GoogleDrive.DriveActivity.primaryActionDetail.delete.type | String | The type of delete action taken. | 
| GoogleDrive.DriveActivity.primaryActionDetail.restore.type | String | The type of restore action taken. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g., in the user's "Shared with me" collection\) without needing a link to the item. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.group.email | String | The email address of the group. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.group.title | String | The title of the group. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g., in the user's "Shared with me" collection\) without needing a link to the item. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.group.email | String | The email address of the group. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.group.title | String | The title of the group. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.mentionedUsers.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.mentionedUsers.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.mentionedUsers.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.mentionedUsers.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.post.subtype | String | The sub-type of post event. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.assignment.subtype | String | The sub-type of assignment event. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.primaryActionDetail.comment.suggestion.subtype | String | The sub-type of suggestion event. | 
| GoogleDrive.DriveActivity.primaryActionDetail.dlpChange.type | String | The type of Data Leak Prevention \(DLP\) change. | 
| GoogleDrive.DriveActivity.primaryActionDetail.reference.type | String | The reference type corresponding to this event. | 
| GoogleDrive.DriveActivity.primaryActionDetail.settingsChange.restrictionChanges.feature | String | The feature which had a change in restriction policy. | 
| GoogleDrive.DriveActivity.primaryActionDetail.settingsChange.restrictionChanges.newRestriction | String | The restriction in place after the change. | 
| GoogleDrive.DriveActivity.actors.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actors.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actors.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actors.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actors.anonymous | Boolean | If true, the user is an anonymous user. | 
| GoogleDrive.DriveActivity.actors.impersonation.impersonatedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actors.impersonation.impersonatedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actors.impersonation.impersonatedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actors.impersonation.impersonatedUser.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actors.system.type | String | The type of the system event that may triggered activity. | 
| GoogleDrive.DriveActivity.actors.administrator | Boolean | If true, the user is an administrator. | 
| GoogleDrive.DriveActivity.actions.detail.create.new | Boolean | If true, the object was newly created. | 
| GoogleDrive.DriveActivity.actions.detail.create.upload | Boolean | If true, the object originated externally and was uploaded to Drive. | 
| GoogleDrive.DriveActivity.actions.detail.create.copy.originalObject.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.actions.detail.create.copy.originalObject.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.actions.detail.create.copy.originalObject.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.actions.detail.create.copy.originalObject.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.actions.detail.create.copy.originalObject.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.detail.create.copy.originalObject.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.detail.edit | Boolean | If true, the object was edited. | 
| GoogleDrive.DriveActivity.actions.detail.move.addedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.actions.detail.move.addedParents.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.actions.detail.move.addedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.actions.detail.move.addedParents.driveItem.driveFolder.type | String | The type of a Drive folder. | 
| GoogleDrive.DriveActivity.actions.detail.move.addedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.detail.move.addedParents.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.detail.move.removedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.actions.detail.move.removedParents.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.actions.detail.move.removedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.actions.detail.move.removedParents.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.actions.detail.move.removedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.detail.move.removedParents.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.detail.rename.oldTitle | String | The previous title of the drive object. | 
| GoogleDrive.DriveActivity.actions.detail.rename.newTitle | String | The new title of the drive object. | 
| GoogleDrive.DriveActivity.actions.detail.delete.type | String | The type of delete action taken. | 
| GoogleDrive.DriveActivity.actions.detail.restore.type | String | The type of restore action taken. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g., in the user's "Shared with me" collection\) without needing a link to the item. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.group.email | String | The email address of the group. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.group.title | String | The title of the group. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.addedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g., in the user's "Shared with me" collection\) without needing a link to the item. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.group.email | String | The email address of the group. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.group.title | String | The title of the group. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.actions.detail.permissionChange.removedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GoogleDrive.DriveActivity.actions.detail.comment.mentionedUsers.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.detail.comment.mentionedUsers.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.detail.comment.mentionedUsers.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.detail.comment.mentionedUsers.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.detail.comment.post.subtype | String | The sub-type of post event. | 
| GoogleDrive.DriveActivity.actions.detail.comment.assignment.subtype | String | The sub-type of assignment event. | 
| GoogleDrive.DriveActivity.actions.detail.comment.assignment.assignedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.detail.comment.assignment.assignedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.detail.comment.assignment.assignedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.detail.comment.assignment.assignedUser.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.detail.comment.suggestion.subtype | String | The sub-type of suggestion event. | 
| GoogleDrive.DriveActivity.actions.detail.dlpChange.type | String | The type of Data Leak Prevention \(DLP\) change. | 
| GoogleDrive.DriveActivity.actions.detail.reference.type | String | The reference type corresponding to this event. | 
| GoogleDrive.DriveActivity.actions.detail.settingsChange.restrictionChanges.feature | String | The feature which had a change in restriction policy. | 
| GoogleDrive.DriveActivity.actions.detail.settingsChange.restrictionChanges.newRestriction | String | The restriction in place after the change. | 
| GoogleDrive.DriveActivity.actions.actor.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.actor.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.actor.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.actor.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.actor.anonymous | Boolean | If true, the user is an anonymous user. | 
| GoogleDrive.DriveActivity.actions.actor.impersonation.impersonatedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.actor.impersonation.impersonatedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.actor.impersonation.impersonatedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.actor.impersonation.impersonatedUser.unknownUser | String | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.actor.system.type | String | The type of the system event that may triggered activity. | 
| GoogleDrive.DriveActivity.actions.actor.administrator | Boolean | If true, the user is an administrator. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.actions.target.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.mimeType | String | The MIME type of the Drive item. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.target.driveItem.owner.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.actions.target.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.actions.target.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.target.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.actions.target.drive.root.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.mimeType | String | The MIME type of the Drive item. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.target.drive.root.owner.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.actions.target.drive.root.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.legacyCommentId | String | The comment in the discussion thread. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.legacyDiscussionId | String | The discussion thread to which the comment was added. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.linkToDiscussion | String | The link to the discussion thread containing this comment, for example, "https://docs.google.com/DOCUMENT_ID/edit?disco=THREAD_ID". | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.mimeType | String | The MIME type of the Drive item. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.owner.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.actions.target.fileComment.parent.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.actions.timestamp | String | The activity occurred at this specific time. | 
| GoogleDrive.DriveActivity.actions.timeRange.startTime | String | The start of the time range. | 
| GoogleDrive.DriveActivity.actions.timeRange.endTime | String | The end of the time range. | 
| GoogleDrive.DriveActivity.targets.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.targets.driveItem.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.targets.driveItem.mimeType | String | The MIME type of the Drive item. | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.targets.driveItem.owner.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.targets.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.targets.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.targets.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.targets.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.targets.drive.root.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.targets.drive.root.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.targets.drive.root.mimeType | String | The MIME type of the Drive item. | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.targets.drive.root.owner.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.targets.drive.root.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.targets.drive.root.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.targets.fileComment.legacyCommentId | String | The comment in the discussion thread. | 
| GoogleDrive.DriveActivity.targets.fileComment.legacyDiscussionId | String | The discussion thread to which the comment was added. | 
| GoogleDrive.DriveActivity.targets.fileComment.linkToDiscussion | String | The link to the discussion thread containing this comment, for example, "https://docs.google.com/DOCUMENT_ID/edit?disco=THREAD_ID". | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.title | String | The title of the Drive item. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.mimeType | String | The MIME type of the Drive item. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.domain.name | String | The name of the domain, e.g., "google.com". | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.owner.drive.title | String | The title of the shared drive. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.driveFile | Boolean | If true, the Drive item is a file. | 
| GoogleDrive.DriveActivity.targets.fileComment.parent.driveFolder.type | String | The type of Drive folder. | 
| GoogleDrive.DriveActivity.timestamp | String | The activity occurred at this specific time. | 
| GoogleDrive.DriveActivity.timeRange.startTime | String | The start of the time range. | 
| GoogleDrive.DriveActivity.timeRange.endTime | String | The end of the time range. | 

### google-drive-drives-list

***
Lists the user's shared drives.

#### Base Command

`google-drive-drives-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of shared drives to return. Acceptable values are 1 to 100, inclusive. Default is 100. | Optional | 
| page_token | Page token for shared drives. | Optional | 
| query | Query string for searching shared drives. | Optional | 
| use_domain_admin_access | Issue the request as a domain administrator. If set to true, all shared drives of the domain in which the requester is an administrator are returned. Possible values are: true, false. Default is false. | Optional | 
| user_id | The user's primary email address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.Drive.Drive.id | String | The ID of this shared drive which is also the ID of the top level folder of this shared drive. | 
| GoogleDrive.Drive.Drive.name | String | The name of this shared drive. | 
| GoogleDrive.Drive.Drive.colorRgb | String | The color of this shared drive as an RGB hex string. | 
| GoogleDrive.Drive.Drive.capabilities.canAddChildren | Boolean | Whether the current user can add children to folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeCopyRequiresWriterPermissionRestriction | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeDomainUsersOnlyRestriction | Boolean | Whether the current user can change the 'domain users only' restriction of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeDriveBackground | Boolean | Whether the current user can change the background of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeDriveMembersOnlyRestriction | Boolean | Whether the current user can change the 'drive members only' restriction of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canComment | Boolean | Whether the current user can comment on files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canCopy | Boolean | Whether the current user can copy files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canDeleteChildren | Boolean | Whether the current user can delete children from folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canDeleteDrive | Boolean | Whether the current user can delete this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canDownload | Boolean | Whether the current user can download files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canEdit | Boolean | Whether the current user can edit files in this shared drive | 
| GoogleDrive.Drive.Drive.capabilities.canListChildren | Boolean | Whether the current user can list the children of folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canManageMembers | Boolean | Whether the current user can add members to this shared drive or remove them or change their role. | 
| GoogleDrive.Drive.Drive.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canRename | Boolean | Whether the current user can rename files or folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canRenameDrive | Boolean | Whether the current user can rename this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canShare | Boolean | Whether the current user can share files or folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canTrashChildren | Boolean | Whether the current user can trash children from folders in this shared drive. | 
| GoogleDrive.Drive.Drive.createdTime | Date | The time at which the shared drive was created \(RFC 3339 date-time\). | 
| GoogleDrive.Drive.Drive.hidden | Boolean | Whether the shared drive is hidden from the default view. | 
| GoogleDrive.Drive.Drive.restrictions.adminManagedRestrictions | Boolean | Whether administrative privileges on this shared drive are required to modify restrictions. | 
| GoogleDrive.Drive.Drive.restrictions.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download files inside this shared drive, should be disabled for readers and commenters. When this restriction is set to true, it will override the similarly named field to true for any file inside this shared drive. | 
| GoogleDrive.Drive.Drive.restrictions.domainUsersOnly | Boolean | Whether access to this shared drive and items inside this shared drive is restricted to users of the domain to which this shared drive belongs. This restriction may be overridden by other sharing policies controlled outside of this shared drive. | 
| GoogleDrive.Drive.Drive.restrictions.driveMembersOnly | Boolean | Whether access to items inside this shared drive is restricted to its members. | 

### google-drive-drive-get

***
Gets a user shared drives.

#### Base Command

`google-drive-drive-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| use_domain_admin_access | Issue the request as a domain administrator. If set to true, all shared drives of the domain in which the requester is an administrator are returned. Possible values are: true, false. Default is false. | Optional | 
| user_id | The user's primary email address. | Optional | 
| drive_id | ID of the shared drive. Can be retrieved using the `google-drive-drives-list` command. | Optional | 
| fields | The fields you want included in the response. Default is kind, id, name, themeId, capabilities, createdTime, hidden, restrictions. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.Drive.Drive.id | String | The ID of this shared drive which is also the ID of the top level folder of this shared drive. | 
| GoogleDrive.Drive.Drive.name | String | The name of this shared drive. | 
| GoogleDrive.Drive.Drive.colorRgb | String | The color of this shared drive as an RGB hex string. | 
| GoogleDrive.Drive.Drive.capabilities.canAddChildren | Boolean | Whether the current user can add children to folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeCopyRequiresWriterPermissionRestriction | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeDomainUsersOnlyRestriction | Boolean | Whether the current user can change the 'domain users only' restriction of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeDriveBackground | Boolean | Whether the current user can change the background of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canChangeDriveMembersOnlyRestriction | Boolean | Whether the current user can change the 'drive members only' restriction of this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canComment | Boolean | Whether the current user can comment on files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canCopy | Boolean | Whether the current user can copy files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canDeleteChildren | Boolean | Whether the current user can delete children from folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canDeleteDrive | Boolean | Whether the current user can delete this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canDownload | Boolean | Whether the current user can download files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canEdit | Boolean | Whether the current user can edit files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canListChildren | Boolean | Whether the current user can list the children of folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canManageMembers | Boolean | Whether the current user can add members to this shared drive or remove them or change their role. | 
| GoogleDrive.Drive.Drive.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of files in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canRename | Boolean | Whether the current user can rename files or folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canRenameDrive | Boolean | Whether the current user can rename this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canShare | Boolean | Whether the current user can share files or folders in this shared drive. | 
| GoogleDrive.Drive.Drive.capabilities.canTrashChildren | Boolean | Whether the current user can trash children from folders in this shared drive. | 
| GoogleDrive.Drive.Drive.createdTime | Date | The time at which the shared drive was created \(RFC 3339 date-time\). | 
| GoogleDrive.Drive.Drive.hidden | Boolean | Whether the shared drive is hidden from the default view. | 
| GoogleDrive.Drive.Drive.restrictions.adminManagedRestrictions | Boolean | Whether administrative privileges on this shared drive are required to modify restrictions. | 
| GoogleDrive.Drive.Drive.restrictions.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download files inside this shared drive, should be disabled for readers and commenters. When this restriction is set to true, it will override the similarly named field to true for any file inside this shared drive. | 
| GoogleDrive.Drive.Drive.restrictions.domainUsersOnly | Boolean | Whether access to this shared drive and items inside this shared drive is restricted to users of the domain to which this shared drive belongs. This restriction may be overridden by other sharing policies controlled outside of this shared drive. | 
| GoogleDrive.Drive.Drive.restrictions.driveMembersOnly | Boolean | Whether access to items inside this shared drive is restricted to its members. | 

### google-drive-drive-delete

***
Deletes a shared drive.

#### Base Command

`google-drive-drive-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| use_domain_admin_access | If set to true, then the requester will be granted access if they are an administrator of the domain to which the shared drive belongs. Possible values are: true, false. Default is false. | Optional | 
| allow_item_deletion | Whether any items inside the shared drive should also be deleted. This option is only supported when use_domain_admin_access argument is set to true. Possible values are: true, false. Default is false. | Optional | 
| user_id | The user's primary email address. | Optional | 
| drive_id | ID of the shared drive. Can be retrieved using the `google-drive-drives-list` command. | Required | 

#### Context Output
There is no context output for this command.

### google-drive-files-list

***
Lists the user's shared drives.

#### Base Command

`google-drive-files-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of shared drives to return. Acceptable values are 1 to 100, inclusive. Default is 100. | Optional | 
| page_token | Page token for shared drives. | Optional | 
| query | Query string for searching shared drives. | Optional | 
| include_items_from_all_drives | Whether both My Drive and shared drive items should be included in the results. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| user_id | The user's primary email address. | Optional | 
| fields | The fields you want included in the response. Default is kind, id, name, mimeType, description, starred, trashed, explicitlyTrashed, trashingUser, trashedTime, parents, properties, appProperties, spaces, version, webContentLink, webViewLink, iconLink, hasThumbnail, thumbnailLink, thumbnailVersion, viewedByMe, viewedByMeTime, createdTime, modifiedTime, modifiedByMeTime, modifiedByMe, sharedWithMeTime, sharingUser, owners, teamDriveId, driveId, lastModifyingUser, shared, ownedByMe, capabilities, viewersCanCopyContent, copyRequiresWriterPermission, writersCanShare, permissions, permissionIds, hasAugmentedPermissions, folderColorRgb, originalFilename, fullFileExtension, fileExtension, md5Checksum, size, quotaBytesUsed, headRevisionId, contentHints, isAppAuthorized, exportLinks, shortcutDetails, contentRestrictions, resourceKey, linkShareMetadata. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values are: True, False. Default is False. | Optional | 
| corpora | Files or documents to which the query applies. Prefer 'User' or 'Drive' to 'All Drives' for efficiency. By default, corpora is set to 'User'. However, this can change depending on the filter set through the 'query' argument. Possible values are: User, Domain, Drive, All Drivers. Default is User. | Optional | 
| drive_id | ID of the shared drive to search. Can be retrieved using the `google-drive-drives-list` command. When a drive ID is specified the value of the corpora argument is automatically set to 'Drive' regardless of its selected value. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.id | String | The ID of the file. | 
| GoogleDrive.File.File.mimeType | String | The MIME type of the file. | 
| GoogleDrive.File.File.name | String | The name of the file. This is not necessarily unique within a folder. | 
| GoogleDrive.File.File.resourceKey | String | A key needed to access the item via a shared link. | 

### google-drive-file-get

***
Get a single file.

#### Base Command

`google-drive-file-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| include_items_from_all_drives | Whether both My Drive and shared drive items should be included in the results. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| fields | The fields you want included in the response. Default is kind, id, name, mimeType, description, starred, trashed, explicitlyTrashed, trashingUser, trashedTime, parents, properties, appProperties, spaces, version, webContentLink, webViewLink, iconLink, hasThumbnail, thumbnailLink, thumbnailVersion, viewedByMe, viewedByMeTime, createdTime, modifiedTime, modifiedByMeTime, modifiedByMe, sharedWithMeTime, sharingUser, owners, teamDriveId, driveId, lastModifyingUser, shared, ownedByMe, capabilities, viewersCanCopyContent, copyRequiresWriterPermission, writersCanShare, permissions, permissionIds, hasAugmentedPermissions, folderColorRgb, originalFilename, fullFileExtension, fileExtension, md5Checksum, size, quotaBytesUsed, headRevisionId, contentHints, isAppAuthorized, exportLinks, shortcutDetails, contentRestrictions, resourceKey, linkShareMetadata. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.capabilities.canAddChildren | Boolean | Whether the current user can add children to this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canAddMyDriveParent | Boolean | Whether the current user can add a parent for the item without removing an existing parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.File.File.capabilities.canChangeCopyRequiresWriterPermission | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this file. | 
| GoogleDrive.File.File.capabilities.canChangeSecurityUpdateEnabled | Boolean | Whether the current user can change the 'security update enabled' field on link shared metadata. | 
| GoogleDrive.File.File.capabilities.canComment | Boolean | Whether the current user can comment on this file. | 
| GoogleDrive.File.File.capabilities.canCopy | Boolean | Whether the current user can copy this file. For an item in a shared drive, whether the current user can copy non-folder descendants of this item, or this item itself if it is not a folder. | 
| GoogleDrive.File.File.capabilities.canDelete | Boolean | Whether the current user can delete this file. | 
| GoogleDrive.File.File.capabilities.canDownload | Boolean | Whether the current user can download this file. | 
| GoogleDrive.File.File.capabilities.canEdit | Boolean | Whether the current user can edit this file. | 
| GoogleDrive.File.File.capabilities.canListChildren | Boolean | Whether the current user can list the children of this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canModifyContent | Boolean | Whether the current user can modify the content of this file. | 
| GoogleDrive.File.File.capabilities.canMoveChildrenWithinDrive | Boolean | Whether the current user can move children of this folder within this drive. This is false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canMoveItemOutOfDrive | Boolean | Whether the current user can move this item outside of this drive by changing its parent. | 
| GoogleDrive.File.File.capabilities.canMoveItemWithinDrive | Boolean | Whether the current user can move this item within this drive. | 
| GoogleDrive.File.File.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of this file. For a shared drive item, whether revisions of non-folder descendants of this item, or this item itself if it is not a folder, can be read. | 
| GoogleDrive.File.File.capabilities.canRemoveChildren | Boolean | Whether the current user can remove children from this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canRemoveMyDriveParent | Boolean | Whether the current user can remove a parent from the item without adding another parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.File.File.capabilities.canRename | Boolean | Whether the current user can rename this file. | 
| GoogleDrive.File.File.capabilities.canShare | Boolean | Whether the current user can modify the sharing settings for this file. | 
| GoogleDrive.File.File.capabilities.canTrash | Boolean | Whether the current user can move this file to trash. | 
| GoogleDrive.File.File.capabilities.canUntrash | Boolean | Whether the current user can restore this file from trash. | 
| GoogleDrive.File.File.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download this file, should be disabled for readers and commenters. | 
| GoogleDrive.File.File.createdTime | Date | The time at which the file was created \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.explicitlyTrashed | Boolean | Whether the file has been explicitly trashed, as opposed to recursively trashed from a parent folder. | 
| GoogleDrive.File.File.exportLinks | String | Links for exporting Docs Editors files to specific formats. | 
| GoogleDrive.File.File.hasThumbnail | Boolean | Whether this file has a thumbnail. This does not indicate whether the requesting app has access to the thumbnail. To check access, look for the presence of the thumbnailLink field. | 
| GoogleDrive.File.File.iconLink | String | A static, unauthenticated link to the file's icon. | 
| GoogleDrive.File.File.id | String | The ID of the file. | 
| GoogleDrive.File.File.isAppAuthorized | Boolean | Whether the file was created or opened by the requesting app. | 
| GoogleDrive.File.File.lastModifyingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.lastModifyingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.File.File.lastModifyingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.File.File.lastModifyingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.File.File.lastModifyingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.linkShareMetadata.securityUpdateEligible | Boolean | Whether the file is eligible for a security update. | 
| GoogleDrive.File.File.linkShareMetadata.securityUpdateEnabled | Boolean | Whether the security update is enabled for this file. | 
| GoogleDrive.File.File.mimeType | String | The MIME type of the file. | 
| GoogleDrive.File.File.modifiedByMe | Boolean | Whether the file has been modified by this user. | 
| GoogleDrive.File.File.modifiedByMeTime | Date | The last time the file was modified by the user \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.modifiedTime | Date | The last time the file was modified by anyone \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.name | String | The name of the file. This is not necessarily unique within a folder. Note that for immutable items such as the top level folders of shared drives, My Drive root folder, and Application Data folder the name is constant. | 
| GoogleDrive.File.File.ownedByMe | Boolean | Whether the user owns the file. Not populated for items in shared drives. | 
| GoogleDrive.File.File.owners.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.owners.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.File.File.owners.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.File.File.owners.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.File.File.owners.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.parents | String | The IDs of the parent folders which contain the file. | 
| GoogleDrive.File.File.permissionIds | String | List of permission IDs for users with access to this file. | 
| GoogleDrive.File.File.permissions.deleted | Boolean | Whether the permission was deleted. | 
| GoogleDrive.File.File.permissions.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.permissions.emailAddress | String | The email address of the user. | 
| GoogleDrive.File.File.permissions.id | String | The ID of this permission. | 
| GoogleDrive.File.File.permissions.role | String | The role granted by this permission. | 
| GoogleDrive.File.File.permissions.type | String | The type of the grantee. | 
| GoogleDrive.File.File.permissions.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.quotaBytesUsed | String | The number of storage quota bytes used by the file. This includes the head revision as well as previous revisions with keepForever enabled. | 
| GoogleDrive.File.File.shared | Boolean | Whether the file has been shared. Not populated for items in shared drives. | 
| GoogleDrive.File.File.spaces | String | The list of spaces which contain the file. The currently supported values are 'drive', 'appDataFolder', and 'photos'. | 
| GoogleDrive.File.File.starred | Boolean | Whether the user has starred the file. | 
| GoogleDrive.File.File.thumbnailLink | String | A short-lived link to the file's thumbnail, if available. Typically lasts on the order of hours. | 
| GoogleDrive.File.File.thumbnailVersion | String | The thumbnail version for use in thumbnail cache invalidation. | 
| GoogleDrive.File.File.trashed | Boolean | Whether the file has been trashed, either explicitly or from a trashed parent folder. | 
| GoogleDrive.File.File.version | String | A monotonically increasing version number for the file. This reflects every change made to the file on the server, even those not visible to the user. | 
| GoogleDrive.File.File.viewedByMe | Boolean | Whether the file has been viewed by this user. | 
| GoogleDrive.File.File.viewedByMeTime | Date | The last time the file was viewed by the user \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.webViewLink | String | A link for opening the file in a relevant Google editor or viewer in a browser. | 
| GoogleDrive.File.File.writersCanShare | Boolean | Whether users with only writer permission can modify the file's permissions. Not populated for items in shared drives. | 

### google-drive-file-upload

***
Creates a new file.

#### Base Command

`google-drive-file-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | The name of the file to upload. | Optional | 
| entry_id | The file's Entry ID. | Optional | 
| parent | The ID of the parent folder which contains the file. If not specified as part of a create request, the file will be placed directly in the user's My Drive folder. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values: "true" and "false". Default is "false". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.id | String | The ID of the file. | 
| GoogleDrive.File.File.name | String | The name of the file. This is not necessarily unique within a folder. Note that for immutable items such as the top level folders of shared drives, My Drive root folder, and Application Data folder, the name is constant. | 
| GoogleDrive.File.File.mimeType | String | The MIME type of the file. | 
| GoogleDrive.File.File.starred | Boolean | Whether the user has starred the file. | 
| GoogleDrive.File.File.trashed | Boolean | Whether the file has been trashed, either explicitly or from a trashed parent folder. | 
| GoogleDrive.File.File.explicitlyTrashed | Boolean | Whether the file has been explicitly trashed, as opposed to recursively trashed from a parent folder. | 
| GoogleDrive.File.File.parents | String | The IDs of the parent folders which contain the file. | 
| GoogleDrive.File.File.spaces | String | The list of spaces which contain the file. The currently supported values are 'drive', 'appDataFolder', and 'photos'. | 
| GoogleDrive.File.File.version | String | A monotonically increasing version number for the file. This reflects every change made to the file on the server, even those not visible to the user. | 
| GoogleDrive.File.File.webContentLink | String | A link for downloading the content of the file in a browser. This is only available for files with binary content in Google Drive. | 
| GoogleDrive.File.File.webViewLink | String | A link for opening the file in a relevant Google editor or viewer in a browser. | 
| GoogleDrive.File.File.iconLink | String | A static, unauthenticated link to the file's icon. | 
| GoogleDrive.File.File.hasThumbnail | Boolean | Whether this file has a thumbnail. This does not indicate whether the requesting app has access to the thumbnail. To check access, look for the presence of the thumbnailLink field. | 
| GoogleDrive.File.File.thumbnailVersion | String | The thumbnail version for use in thumbnail cache invalidation. | 
| GoogleDrive.File.File.viewedByMe | Boolean | Whether the file has been viewed by this user. | 
| GoogleDrive.File.File.viewedByMeTime | Date | The last time the file was viewed by the user \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.createdTime | Date | The time at which the file was created \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.modifiedTime | Date | The last time the file was modified by anyone \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.thumbnailLink | String | A short-lived link to the file's thumbnail, if available. Typically lasts on the order of hours. | 
| GoogleDrive.File.File.exportLinks | String | Links for exporting Docs Editors files to specific formats. | 
| GoogleDrive.File.File.quotaBytesUsed | String | The number of storage quota bytes used by the file. This includes the head revision as well as previous revisions with keepForever enabled. | 
| GoogleDrive.File.File.shared | Boolean | Whether the file has been shared. Not populated for items in shared drives. | 
| GoogleDrive.File.File.writersCanShare | Boolean | Whether users with only writer permission can modify the file's permissions. Not populated for items in shared drives. | 
| GoogleDrive.File.File.modifiedByMe | Boolean | Whether the file has been modified by this user. | 
| GoogleDrive.File.File.modifiedByMeTime | Date | The last time the file was modified by the user \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.ownedByMe | Boolean | Whether the user owns the file. Not populated for items in shared drives. | 
| GoogleDrive.File.File.isAppAuthorized | Boolean | Whether the file was created or opened by the requesting app. | 
| GoogleDrive.File.File.capabilities.canAddChildren | Boolean | Whether the current user can add children to this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canAddMyDriveParent | Boolean | Whether the current user can add a parent for the item without removing an existing parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.File.File.capabilities.canChangeCopyRequiresWriterPermission | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this file. | 
| GoogleDrive.File.File.capabilities.canChangeSecurityUpdateEnabled | Boolean | Whether the current user can change the 'security update enabled' field on link shared metadata. | 
| GoogleDrive.File.File.capabilities.canComment | Boolean | Whether the current user can comment on this file. | 
| GoogleDrive.File.File.capabilities.canCopy | Boolean | Whether the current user can copy this file. For an item in a shared drive, whether the current user can copy non-folder descendants of this item, or this item itself if it is not a folder. | 
| GoogleDrive.File.File.capabilities.canDelete | Boolean | Whether the current user can delete this file. | 
| GoogleDrive.File.File.capabilities.canDownload | Boolean | Whether the current user can download this file. | 
| GoogleDrive.File.File.capabilities.canEdit | Boolean | Whether the current user can edit this file. | 
| GoogleDrive.File.File.capabilities.canListChildren | Boolean | Whether the current user can list the children of this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canModifyContent | Boolean | Whether the current user can modify the content of this file. | 
| GoogleDrive.File.File.capabilities.canMoveChildrenWithinDrive | Boolean | Whether the current user can move children of this folder within this drive. This is false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canMoveItemOutOfDrive | Boolean | Whether the current user can move this item outside of this drive by changing its parent. | 
| GoogleDrive.File.File.capabilities.canMoveItemWithinDrive | Boolean | Whether the current user can move this item within this drive. | 
| GoogleDrive.File.File.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of this file. For a shared drive item, whether revisions of non-folder descendants of this item, or this item itself if it is not a folder, can be read. | 
| GoogleDrive.File.File.capabilities.canRemoveChildren | Boolean | Whether the current user can remove children from this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canRemoveMyDriveParent | Boolean | Whether the current user can remove a parent from the item without adding another parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.File.File.capabilities.canRename | Boolean | Whether the current user can rename this file. | 
| GoogleDrive.File.File.capabilities.canShare | Boolean | Whether the current user can modify the sharing settings for this file. | 
| GoogleDrive.File.File.capabilities.canTrash | Boolean | Whether the current user can move this file to trash. | 
| GoogleDrive.File.File.capabilities.canUntrash | Boolean | Whether the current user can restore this file from trash. | 
| GoogleDrive.File.File.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download this file, should be disabled for readers and commenters. | 
| GoogleDrive.File.File.lastModifyingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.lastModifyingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.File.File.lastModifyingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.File.File.lastModifyingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.File.File.lastModifyingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.linkShareMetadata.securityUpdateEligible | Boolean | Whether the file is eligible for security update. | 
| GoogleDrive.File.File.linkShareMetadata.securityUpdateEnabled | Boolean | Whether the security update is enabled for this file. | 
| GoogleDrive.File.File.owners.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.owners.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.File.File.owners.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.File.File.owners.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.File.File.owners.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.permissionIds | String | List of permission IDs for users with access to this file. | 
| GoogleDrive.File.File.permissions.deleted | Boolean | Whether the permission was deleted. | 
| GoogleDrive.File.File.permissions.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.permissions.emailAddress | String | The email address of the user. | 
| GoogleDrive.File.File.permissions.id | String | The ID of this permission. | 
| GoogleDrive.File.File.permissions.role | String | The role granted by this permission. | 
| GoogleDrive.File.File.permissions.type | String | The type of the grantee. | 
| GoogleDrive.File.File.permissions.photoLink | String | A link to the user's profile photo, if available. | 

### google-drive-file-download

***
Download a single file.

#### Base Command

`google-drive-file-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| file_name | Name of the downloaded file. Default is untitled. | Optional | 
| user_id | The user's primary email address. | Optional | 

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

### google-drive-file-replace-existing

***
Updates a file's content.

#### Base Command

`google-drive-file-replace-existing`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the file to replace. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| entry_id | The file's entry ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.id | String | The ID of the file. | 
| GoogleDrive.File.File.name | String | The name of the file. This is not necessarily unique within a folder. Note that for immutable items such as the top level folders of shared drives, My Drive root folder, and Application Data folder, the name is constant. | 
| GoogleDrive.File.File.mimeType | String | The MIME type of the file. | 
| GoogleDrive.File.File.starred | Boolean | Whether the user has starred the file. | 
| GoogleDrive.File.File.trashed | Boolean | Whether the file has been trashed, either explicitly or from a trashed parent folder. | 
| GoogleDrive.File.File.explicitlyTrashed | Boolean | Whether the file has been explicitly trashed, as opposed to recursively trashed from a parent folder. | 
| GoogleDrive.File.File.parents | String | The IDs of the parent folders which contain the file. | 
| GoogleDrive.File.File.spaces | String | The list of spaces which contain the file. The currently supported values are 'drive', 'appDataFolder', and 'photos'. | 
| GoogleDrive.File.File.version | String | A monotonically increasing version number for the file. This reflects every change made to the file on the server, even those not visible to the user. | 
| GoogleDrive.File.File.webContentLink | String | A link for downloading the content of the file in a browser. This is only available for files with binary content in Google Drive. | 
| GoogleDrive.File.File.webViewLink | String | A link for opening the file in a relevant Google editor or viewer in a browser. | 
| GoogleDrive.File.File.iconLink | String | A static, unauthenticated link to the file's icon. | 
| GoogleDrive.File.File.hasThumbnail | Boolean | Whether this file has a thumbnail. This does not indicate whether the requesting app has access to the thumbnail. To check access, look for the presence of the thumbnailLink field. | 
| GoogleDrive.File.File.thumbnailVersion | String | The thumbnail version for use in thumbnail cache invalidation. | 
| GoogleDrive.File.File.viewedByMe | Boolean | Whether the file has been viewed by this user. | 
| GoogleDrive.File.File.viewedByMeTime | Date | The last time the file was viewed by the user \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.createdTime | Date | The time at which the file was created \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.modifiedTime | Date | The last time the file was modified by anyone \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.thumbnailLink | String | A short-lived link to the file's thumbnail, if available. Typically lasts on the order of hours. | 
| GoogleDrive.File.File.exportLinks | String | Links for exporting Docs Editors files to specific formats. | 
| GoogleDrive.File.File.quotaBytesUsed | String | The number of storage quota bytes used by the file. This includes the head revision as well as previous revisions with keepForever enabled. | 
| GoogleDrive.File.File.shared | Boolean | Whether the file has been shared. Not populated for items in shared drives. | 
| GoogleDrive.File.File.writersCanShare | Boolean | Whether users with only writer permission can modify the file's permissions. Not populated for items in shared drives. | 
| GoogleDrive.File.File.modifiedByMe | Boolean | Whether the file has been modified by this user. | 
| GoogleDrive.File.File.modifiedByMeTime | Date | The last time the file was modified by the user \(RFC 3339 date-time\). | 
| GoogleDrive.File.File.ownedByMe | Boolean | Whether the user owns the file. Not populated for items in shared drives. | 
| GoogleDrive.File.File.isAppAuthorized | Boolean | Whether the file was created or opened by the requesting app. | 
| GoogleDrive.File.File.capabilities.canAddChildren | Boolean | Whether the current user can add children to this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canAddMyDriveParent | Boolean | Whether the current user can add a parent for the item without removing an existing parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.File.File.capabilities.canChangeCopyRequiresWriterPermission | Boolean | Whether the current user can change the 'copy requires writer permission' restriction of this file. | 
| GoogleDrive.File.File.capabilities.canChangeSecurityUpdateEnabled | Boolean | Whether the current user can change the 'security update enabled' field on link shared metadata. | 
| GoogleDrive.File.File.capabilities.canComment | Boolean | Whether the current user can comment on this file. | 
| GoogleDrive.File.File.capabilities.canCopy | Boolean | Whether the current user can copy this file. For an item in a shared drive, whether the current user can copy non-folder descendants of this item, or this item itself if it is not a folder. | 
| GoogleDrive.File.File.capabilities.canDelete | Boolean | Whether the current user can delete this file. | 
| GoogleDrive.File.File.capabilities.canDownload | Boolean | Whether the current user can download this file. | 
| GoogleDrive.File.File.capabilities.canEdit | Boolean | Whether the current user can edit this file. | 
| GoogleDrive.File.File.capabilities.canListChildren | Boolean | Whether the current user can list the children of this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canModifyContent | Boolean | Whether the current user can modify the content of this file. | 
| GoogleDrive.File.File.capabilities.canMoveChildrenWithinDrive | Boolean | Whether the current user can move children of this folder within this drive. This is false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canMoveItemOutOfDrive | Boolean | Whether the current user can move this item outside of this drive by changing its parent. | 
| GoogleDrive.File.File.capabilities.canMoveItemWithinDrive | Boolean | Whether the current user can move this item within this drive. | 
| GoogleDrive.File.File.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of this file. For a shared drive item, whether revisions of non-folder descendants of this item, or this item itself if it is not a folder, can be read. | 
| GoogleDrive.File.File.capabilities.canRemoveChildren | Boolean | Whether the current user can remove children from this folder. This is always false when the item is not a folder. | 
| GoogleDrive.File.File.capabilities.canRemoveMyDriveParent | Boolean | Whether the current user can remove a parent from the item without adding another parent in the same request. Not populated for shared drive files. | 
| GoogleDrive.File.File.capabilities.canRename | Boolean | Whether the current user can rename this file. | 
| GoogleDrive.File.File.capabilities.canShare | Boolean | Whether the current user can modify the sharing settings for this file. | 
| GoogleDrive.File.File.capabilities.canTrash | Boolean | Whether the current user can move this file to trash. | 
| GoogleDrive.File.File.capabilities.canUntrash | Boolean | Whether the current user can restore this file from trash. | 
| GoogleDrive.File.File.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download this file, should be disabled for readers and commenters. | 
| GoogleDrive.File.File.lastModifyingUser.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.lastModifyingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.File.File.lastModifyingUser.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.File.File.lastModifyingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.File.File.lastModifyingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.linkShareMetadata.securityUpdateEligible | Boolean | Whether the file is eligible for security update. | 
| GoogleDrive.File.File.linkShareMetadata.securityUpdateEnabled | Boolean | Whether the security update is enabled for this file. | 
| GoogleDrive.File.File.owners.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.owners.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GoogleDrive.File.File.owners.me | Boolean | Whether this user is the requesting user. | 
| GoogleDrive.File.File.owners.permissionId | String | The user's ID as visible in Permission resources. | 
| GoogleDrive.File.File.owners.photoLink | String | A link to the user's profile photo, if available. | 
| GoogleDrive.File.File.permissionIds | String | List of permission IDs for users with access to this file. | 
| GoogleDrive.File.File.permissions.deleted | Boolean | Whether the permission was deleted. | 
| GoogleDrive.File.File.permissions.displayName | String | A plain text displayable name for this user. | 
| GoogleDrive.File.File.permissions.emailAddress | String | The email address of the user. | 
| GoogleDrive.File.File.permissions.id | String | The ID of this permission. | 
| GoogleDrive.File.File.permissions.role | String | The role granted by this permission. | 
| GoogleDrive.File.File.permissions.type | String | The type of the grantee. | 
| GoogleDrive.File.File.permissions.photoLink | String | A link to the user's profile photo, if available. | 

### google-drive-file-delete

***
Permanently deletes a file owned by the user without moving it to the trash. If the file belongs to a shared drive the user must be an organizer on the parent. If the target is a folder, all descendants owned by the user are also deleted.

#### Base Command

`google-drive-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.id | String | ID of the deleted file. | 

### google-drive-file-permissions-list

***
Lists a file's or shared drive's permissions.

#### Base Command

`google-drive-file-permissions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| page_size | Maximum number of shared drives to return. Acceptable values are 1 to 100, inclusive. Default is 100. | Optional | 
| page_token | Page token for shared drives. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| use_domain_admin_access | Issue the request as a domain administrator. If set to true, all shared drives of the domain in which the requester is an administrator are returned. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.FilePermission.FilePermission.deleted | Boolean | Whether the account associated with this permission has been deleted. This field only pertains to user and group permissions. | 
| GoogleDrive.FilePermission.FilePermission.displayName | String | The "pretty" name of the value of the permission. | 
| GoogleDrive.FilePermission.FilePermission.emailAddress | String | The email address of the user or group to which this permission refers. | 
| GoogleDrive.FilePermission.FilePermission.id | String | The ID of this permission. | 
| GoogleDrive.FilePermission.FilePermission.role | String | The role granted by this permission. | 
| GoogleDrive.FilePermission.FilePermission.type | String | The type of the grantee. | 
| GoogleDrive.FilePermission.FilePermission.photoLink | String | A link to the user's profile photo, if available. | 

### google-drive-file-permission-create

***
Creates a permission for a file or shared drive.

#### Base Command

`google-drive-file-permission-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| send_notification_email | Whether a confirmation email will be sent. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 
| role | The role granted by this permission. Possible values: "owner", "organizer", "fileOrganizer", "writer", "commenter", and "reader". Possible values are: owner, organizer, fileOrganizer, writer, commenter, reader. Default is reader. | Optional | 
| type | The type of the grantee. When creating a permission, if type is user or group, you must provide an emailAddress for the user or group. When type is domain, you must provide a domain. No extra information is required for an anyone type. Possible values: "user", "group", "domain", and "anyone". Possible values are: user, group, domain, anyone. Default is anyone. | Optional | 
| domain | The domain to which this permission refers. | Optional | 
| email_address | The email address of the user or group to which this permission refers. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.FilePermission.FilePermission.deleted | Boolean | Whether the account associated with this permission has been deleted. This field only pertains to user and group permissions. | 
| GoogleDrive.FilePermission.FilePermission.displayName | String | The "pretty" name of the value of the permission. | 
| GoogleDrive.FilePermission.FilePermission.emailAddress | String | The email address of the user or group to which this permission refers. | 
| GoogleDrive.FilePermission.FilePermission.id | String | The ID of this permission. | 
| GoogleDrive.FilePermission.FilePermission.role | String | The role granted by this permission. | 
| GoogleDrive.FilePermission.FilePermission.type | String | The type of the grantee. | 
| GoogleDrive.FilePermission.FilePermission.photoLink | String | A link to the user's profile photo, if available. | 

### google-drive-file-permission-update

***
Updates a permission with patch semantics.

#### Base Command

`google-drive-file-permission-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| expiration_time | The time at which this permission will expire (RFC 3339 date-time). | Optional | 
| permission_id | The ID of the permission. Can be retrieved using the `google-drive-file-permissions-list` command. | Optional | 
| role | The role granted by this permission. Possible values: "owner", "organizer", "fileOrganizer", "writer", "commenter", and "reader". Possible values are: owner, organizer, fileOrganizer, writer, commenter, reader. Default is reader. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.FilePermission.FilePermission.deleted | Boolean | Whether the account associated with this permission has been deleted. This field only pertains to user and group permissions. | 
| GoogleDrive.FilePermission.FilePermission.displayName | String | The "pretty" name of the value of the permission. | 
| GoogleDrive.FilePermission.FilePermission.emailAddress | String | The email address of the user or group to which this permission refers. | 
| GoogleDrive.FilePermission.FilePermission.id | String | The ID of this permission. | 
| GoogleDrive.FilePermission.FilePermission.role | String | The role granted by this permission. | 
| GoogleDrive.FilePermission.FilePermission.type | String | The type of the grantee. | 
| GoogleDrive.FilePermission.FilePermission.photoLink | String | A link to the user's profile photo, if available. | 

### google-drive-file-permission-delete

***
Delete a permission.

#### Base Command

`google-drive-file-permission-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| permission_id | The ID of the permission. Can be retrieved using the `google-drive-file-permissions-list` command. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### google-drive-file-modify-label

***
Modify labels to file.

#### Base Command

`google-drive-file-modify-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 
| label_id | The label id to set for the file. | Optional | 
| field_id | the field id of the label to set. | Optional | 
| selection_label_id | the label id to set for the field. | Optional | 
| remove_label | Whether the requesting application supports both My Drives and shared drives. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.Labels.kind | String | The type of resource. This is always drive\#modifyLabelsResponse | 
| GoogleDrive.Labels.modifiedLabels.fields.id | String | The ID of the label field selected | 
| GoogleDrive.Labels.modifiedLabels.fields.kind | String | Kind of resource this is, in this case drive\#labelField | 
| GoogleDrive.Labels.modifiedLabels.fields.selection | String | Selected label. | 
| GoogleDrive.Labels.modifiedLabels.fields.valueType | String | The type of data this label is representing. | 
| GoogleDrive.Labels.modifiedLabels.id | String | The label id of the label to set | 
| GoogleDrive.Labels.modifiedLabels.kind | String | The type of resource. This is always drive\#label | 
| GoogleDrive.Labels.modifiedLabels.revisionId | String |  | 

### google-drive-get-labels

***
Google Drive get labels.

#### Base Command

`google-drive-get-labels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's primary email address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.Labels.labels.appliedCapabilities.canApply | Boolean | Is able to apply this label to files. | 
| GoogleDrive.Labels.labels.appliedCapabilities.canRead | Boolean | Is able to read this label. | 
| GoogleDrive.Labels.labels.appliedCapabilities.canRemove | Boolean | Is able to remove this label from files. | 
| GoogleDrive.Labels.labels.appliedLabelPolicy.copyMode | String | Copy label to all descendants. | 
| GoogleDrive.Labels.labels.createTime | Date | Time at which this label was created. | 
| GoogleDrive.Labels.labels.creator.person | String | The creator of this label. | 
| GoogleDrive.Labels.labels.customer | String | The customer that owns this label. | 
| GoogleDrive.Labels.labels.displayHints.priority | String | Priority of the label. | 
| GoogleDrive.Labels.labels.displayHints.shownInApply | Boolean | Whether this label is shown in the "Apply a label" dropdown. | 
| GoogleDrive.Labels.labels.fields.appliedCapabilities.canRead | Boolean | Is the field readable. | 
| GoogleDrive.Labels.labels.fields.appliedCapabilities.canSearch | Boolean | Is the field searchable. | 
| GoogleDrive.Labels.labels.fields.appliedCapabilities.canWrite | Boolean | Is the field writable. | 
| GoogleDrive.Labels.labels.fields.creator.person | String | The creator of this field. | 
| GoogleDrive.Labels.labels.fields.displayHints.required | Boolean | Is this field required to be set by the user. | 
| GoogleDrive.Labels.labels.fields.displayHints.shownInApply | Boolean | Should this field be shown when editing the label. | 
| GoogleDrive.Labels.labels.fields.id | String | The ID of the field. | 
| GoogleDrive.Labels.labels.fields.lifecycle.state | String | The lifecycle state of this field. | 
| GoogleDrive.Labels.labels.fields.properties.displayName | String | The display name of the property. | 
| GoogleDrive.Labels.labels.fields.properties.required | Boolean | Is this property required to be set by the user. | 
| GoogleDrive.Labels.labels.fields.publisher.person | String | The user who published this field. | 
| GoogleDrive.Labels.labels.fields.queryKey | String | The query key for this field. | 
| GoogleDrive.Labels.labels.fields.schemaCapabilities | Unknown | Schema capabilities for this field. | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.appliedCapabilities.canRead | Boolean |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.appliedCapabilities.canSearch | Boolean |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.appliedCapabilities.canSelect | Boolean |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.backgroundColor.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.backgroundColor.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.backgroundColor.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.foregroundColor.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.foregroundColor.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.foregroundColor.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.soloColor.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.soloColor.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgeColors.soloColor.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.badgePriority | String |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.backgroundColor.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.backgroundColor.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.backgroundColor.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.foregroundColor.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.foregroundColor.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.foregroundColor.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.soloColor.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.soloColor.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.darkBadgeColors.soloColor.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.displayHints.shownInApply | Boolean |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.id | String |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.lifecycle.state | String |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.properties.badgeConfig.color.blue | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.properties.badgeConfig.color.green | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.properties.badgeConfig.color.red | Number |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.properties.displayName | String |  | 
| GoogleDrive.Labels.labels.fields.selectionOptions.choices.schemaCapabilities | Unknown |  | 
| GoogleDrive.Labels.labels.fields.updater.person | String |  | 
| GoogleDrive.Labels.labels.id | String |  | 
| GoogleDrive.Labels.labels.labelType | String |  | 
| GoogleDrive.Labels.labels.lifecycle.state | String |  | 
| GoogleDrive.Labels.labels.name | String |  | 
| GoogleDrive.Labels.labels.properties.title | String |  | 
| GoogleDrive.Labels.labels.publishTime | Date |  | 
| GoogleDrive.Labels.labels.publisher.person | String |  | 
| GoogleDrive.Labels.labels.revisionCreateTime | Date |  | 
| GoogleDrive.Labels.labels.revisionCreator.person | String |  | 
| GoogleDrive.Labels.labels.revisionId | String |  | 
| GoogleDrive.Labels.labels.schemaCapabilities | Unknown |  | 
| GoogleDrive.Labels.labels.fields.userOptions | Unknown |  | 

### google-drive-get-file-labels

***
Modify labels to file.

#### Base Command

`google-drive-get-file-labels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Optional | 
| user_id | The user's primary email address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.id | String | The ID of the file. | 
| GoogleDrive.Labels.kind | String | The type of resource. This is always drive\#labelList | 
| GoogleDrive.Labels.labels.fields.id | String | The ID of the label field selected | 
| GoogleDrive.Labels.labels.fields.kind | String | The kind of this field. This is always drive\#labelField | 
| GoogleDrive.Labels.labels.fields.selection | String | The label field selected. | 
| GoogleDrive.Labels.labels.fields.valueType | String | The type of data this label is representing. | 
| GoogleDrive.Labels.labels.id | String | The label id of the label to set | 
| GoogleDrive.Labels.labels.kind | String | The type of resource. This is always drive\#label | 
| GoogleDrive.Labels.labels.revisionId | String | The revision id of the label | 

### google-drive-file-copy

***
Make a copy of a Google Drive file.

#### Base Command

`google-drive-file-copy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The ID of the file to copy. | Required | 
| copy_title | The name of the copied file. | Optional | 
| user_id | The user's primary email address. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.File.kind | String | The content type of the file. | 
| GoogleDrive.File.File.id | String | The ID of the copied file. | 
| GoogleDrive.File.File.name | String | The name of the copied file. | 
| GoogleDrive.File.File.mimeType | String | The MIME type of the copied file. | 

#### Command example
```!google-drive-file-copy file_id="1O8Gx7DslVpbd-HN7lp4MIN1DDakpw-bHVHCwir2wUlo" copy_title="New Copy"```
#### Context Example
```json
{
    "GoogleDrive": {
        "File": {
            "File": {
                "id": "1JBZfuJcRpnpv5wS5-RBxT5OGjfKMP1cCmqOBHCe7GPw",
                "kind": "drive#file",
                "mimeType": "application/vnd.google-apps.spreadsheet",
                "name": "New Copy"
            }
        }
    }
}
```

#### Human Readable Output

>### File copied successfully.
>|Id|Kind|Mimetype|Name|
>|---|---|---|---|
>| 1JBZfuJcRpnpv5wS5-RBxT5OGjfKMP1cCmqOBHCe7GPw | drive#file | application/vnd.google-apps.spreadsheet | New Copy |

### google-drive-file-get-parents

***
Get parents of a Google Drive file.

#### Base Command

`google-drive-file-get-parents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | ID of the requested file. Can be retrieved using the `google-drive-files-list` command. | Required | 
| user_id | The user's primary email address. | Required | 
| include_items_from_all_drives | Whether both My Drive and shared drive items should be included in the results. Possible values are: true, false. Default is false. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleDrive.File.Parents | String | The IDs of the parent folders which contain the file. | 