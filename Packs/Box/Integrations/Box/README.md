Deprecated. Use the Box v2 integration instead.

## Configure Box in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| insecure | Trust any certificate \(not secure\) | False |


## How to initialize the Box integration:

  Note: The following steps should be done in less than 30 seconds due to Box security.
  1. Create a new Box instance. Do not click **Test**.
  2. In your browser, copy the following line containing the Cortex XSOAR application client id:
  https://account.box.com/api/oauth2/authorize?response_type=code&client_id=hznnisyhdf09nu9saf2eyfzupawrn9b2&state=lulubalulu
  (client_id is demisto-application client id)
  3. Click **Grant access to Box**. Allow access to it using your box credentials.
  4. You will be redirected to a non active page, with a url in this form:
  https://localhost/?state=lulubalulu&code=MCTNCsN1gJIjA2cEJ72nczpXzcLVVQxJ
  5. Copy the code from the url and use it the next step.  (For example, copy MCTNCsN1gJIjA2cEJ72nczpXzcLVVQxJ)
  6. Run the ***box_initiate*** command with the *access_code* argument in the CLI in this form:
  ***!box_initiate access_code=ACCESS_CODE***
  For additional information, watch https://www.youtube.com/watch?v=ha26tN8amI0
  Or read about the box oauth2 process at https://developer.box.com/guides/authentication/oauth2/


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### box_get_current_user
***
Retrieves information about the user who is currently logged in i.e. the user for whom this auth token was generated


#### Base Command

`box_get_current_user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verbose | Print verbose data on each user | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box_get_current_user```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Box account current user
>|ID|Username|Name|Created at|Status|
>|---|----|----|----|----|
>|14226607780|exampleuser@paloaltonetworks.com|My Name|2020-09-25T15:23:39-07:00|active|


### box_get_users
***
Returns a list of all users for the Enterprise along with their user_id, public_name, and login


#### Base Command

`box_get_users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_term | A string used to filter the results to only users starting with the filter_term in either the name or the login | Optional | 
| limit | The number of records to return. The default is 100 and the max is 1000 | Optional | 
| offset | The record at which to start. The default is 0 | Optional | 
| user_type | The type of user to search for. Valid values are all, external or managed. If nothing is provided, the default behavior will be managed only | Optional | 
| verbose | Print verbose data on each user | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account | unknown | Account information of users returned by query, including ID, name and username | 


#### Command Example
```!box_get_users```

#### Context Example
```json
{
    "Account": [
        {
            "Display Name": "My Name",
            "Groups": "user",
            "ID": "14226607780",
            "Username": "exampleuser@paloaltonetworks.com",
            "type": "Box"
        }
    ]
}
```

#### Human Readable Output

>### Box account users
>|ID|Username|Name|Created at|Status|
>|---|---|---|---|---|
>|14226607780|exampleuser@paloaltonetworks.com|My Name|2020-10-29T07:49:51-07:00|active|

### box_update_user
***
Used to edit the settings and information about a user


#### Base Command

`box_update_user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notify | Whether the user should receive an email when they are rolled out of an enterprise | Optional | 
| enterprise | Setting this to null will roll the user out of the enterprise and make them a free user. When passing a null value, do not pass this value as a string | Optional | 
| name | The name of this user | Optional | 
| role | string This user’s enterprise role | Optional | 
| language | The language of this user | Optional | 
| is_sync_enabled | Whether or not this user can use Box Sync | Optional | 
| job_title | The user’s job title | Optional | 
| phone | The user’s phone number | Optional | 
| address | The user’s address | Optional | 
| space_amount | The user’s total available space amount in byte. A value of -1 grants unlimited storage | Optional | 
| tracking_codes | An array of key/value pairs set by the user’s admin | Optional | 
| can_see_managed_users |  boolean Whether this user can see other enterprise users in its contact list | Optional | 
| status | Can be active, inactive, cannot_delete_edit, or cannot_delete_edit_upload | Optional | 
| timezone | The timezone of this user | Optional | 
| is_exempt_from_device_limits | Whether to exempt this user from Enterprise device limits | Optional | 
| is_exempt_from_login_verification | Whether or not this user must use two-factor authentication | Optional | 
| is_password_reset_required | Whether or not the user is required to reset password | Optional | 
| user_id | The user id to update | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box_update_user user_id=14226607780```

#### Context Example
```json
{}
```

#### Human Readable Output

>### User updated
>|ID|Username|Name|Created at|Status|
>|---|---|---|---|---|
>|14226607780|eampleuser@paloaltonetworks.com|My Name |2020-09-25T16:02:17-07:00|active|


### box_add_user
***
Used to provision a new user in an enterprise


#### Base Command

`box_add_user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| login | The email address this user uses to login | Required | 
| name | The name of this user | Required | 
| role | This user’s enterprise role. Can be coadmin or user | Optional | 
| language | The language of this user | Optional | 
| is_sync_enabled | Whether or not this user can use Box Sync | Optional | 
| job_title | The user’s job title | Optional | 
| phone | The user’s phone number | Optional | 
| address | The user’s address | Optional | 
| space_amount | The user’s total available space amount in bytes | Optional | 
| tracking_codes | An array of key/value pairs set by the user’s admin | Optional | 
| can_see_managed_users | Can be active, inactive, cannot_delete_edit, or cannot_delete_edit_upload | Optional | 
| timezone | The timezone of this user | Optional | 
| is_exempt_from_device_limits | Whether to exempt this user from Enterprise device limits | Optional | 
| is_exempt_from_login_verification | Whether or not this user must use two-factor authentication | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box_add_user login=exampleuser@paloaltonetworks.com name="My Name"```

#### Context Example
```json
{}
```

#### Human Readable Output

>### User created
>|ID|Username|Name|Created at|Status|
>|---|---|---|---|---|
>|14226607780|exampleuser@paloaltonetworks.com|My Name|2020-10-29T07:49:51-07:00|active|


### box_delete_user
***
Deletes a user in an enterprise account


#### Base Command

`box_delete_user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notify | Determines if the destination user should receive email notification of the transfer | Optional | 
| force | Whether or not the user should be deleted even if this user still own files | Optional | 
| user_id | The user id to update | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box_delete_user user_id=14226607780```

#### Context Example
```json
{}
```

#### Human Readable Output

>### User deleted
>success


### box_move_folder
***
Moves all of the owned content from within one user’s folder into a new folder in another user’s account. You can move folders across users as long as the you have administrative permissions and the ‘source’ user owns the folders. To move everything from the root folder, use “0” which always represents the root folder of a Box account (Currently only moving of the root folder (0) is supported)


#### Base Command

`box_move_folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_user_id | The ID of the user who the folder will be transferred from | Required | 
| to_user_id | The ID of the user who the folder will be transferred to | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box_move_folder from_user_id=13917563262 to_user_id=14226607780```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Folder moved
>Content is now available in account **exampleuser@paloaltonetworks.com** under directory **exmple@paloaltonetworks.com - My Name's Files and Folders (2)**


### box_files_get
***
getting a file from private Box storage


#### Base Command

`box_files_get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | File's id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | string | Filename | 
| File.Type | string | File type | 
| File.Size | number | File size | 
| File.MD5 | string | MD5 hash of the file | 
| File.SHA1 | string | SHA1 hash of the file | 
| File.SHA256 | string | SHA256 hash of the file | 


#### Command Example
```!box_files_get file_id=723447059947```

#### Context Example
```json
{
    "File": {
        "EntryID": "863@6e069bc4-2a1e-43ea-8ed3-ea558e377751",
        "Extension": "boxnote",
        "Info": "boxnote",
        "MD5": "5bb1cfa1f61f0f5322a10c401f869919",
        "Name": "Untitled Note 2020-09-25 15.56.56.boxnote",
        "SHA1": "fc9ed186f1e2b4b5a93cf8d0f698a86d396b7b2f",
        "SHA256": "cd98285440b5d341c7ca37d389fa5c79558e8f681c26a165573321cfc1a5f3f5",
        "SHA512": "590a0bcf34b13d5b1eab9ce48f1520f75708b137b2ef31053e881915cbf4eb54a39d7c5b15b06478f5cf4b09e2cedc41e45f99b3d3f3cbfbbc7f42749acb2627",
        "SSDeep": "24:Y2YuI2qFcH3KUGIwYdAYsAuhvZqwNRpLk28:YfuAe3G6sA6TpP8",
        "Size": 959,
        "Type": "ASCII text, with very long lines, with no line terminators"
    }
}
```

#### Human Readable Output

>Untitled Note 2020-09-25 15.56.56.boxnote

### box_initiate
***
Initialising of Box's integration


#### Base Command

`box_initiate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access_code | Box's access code (see description) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box_initiate access_code=wOK4V7vzcljJNTFu2mSDyQq7phlFY5nx```

#### Context Example
```json
{}
```

#### Human Readable Output

>Box initialized successfully

### box_files_get_info
***
Getting file info of provided ID


#### Base Command

`box_files_get_info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | File's ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.Size | number | Size of file \(in bits\) | 
| Box.ContentModifiedAt | date | Time of content modification | 
| Box.Sha1 | string | File's SHA1 | 
| Box.ModifiedAt | date | Time of file info | 
| Box.Parent.Etag | string | Parent's etag | 
| Box.Parent.Id | string | Parent's ID | 
| Box.Parent.Name | string | Parent's name | 
| Box.SequenceId | string | Parent's sequence ID | 
| Box.Parent.Type | string | Parent's type | 
| Box.CreatedAt | date | Time of file's upload | 
| Box.Name | string | File's name | 
| Box.ModifiedBy.Id | string | ID's of last user modified | 
| Box.ModifiedBy.Login | string | User's login email | 
| Box.ModifiedBy.Name | string | User's name of last modified | 
| Box.ModifiedBy.User | string | User's type | 
| Box.ContentCreatedAt | date | File's time of creation | 
| Box.OwnedBy.Id | string | File's owner ID | 
| Box.OwnedBy.Login | string | File's owner email | 
| Box.OwnedBy.Name | string | File's owner name | 
| Box.OwnedBy.Type | string | File's owner type | 
| Box.SharedLink | string | Shared link | 
| Box.Etag | string | File's etag | 
| Box.FileVersion.Id | string | File's version ID | 
| Box.FileVersion.Sha1 | string | File's version SHA1 | 
| Box.FileVersion.Type | string | File's version type | 
| Box.PathCollection.Entries.Etag | string | Path's collection entries etag | 
| Box.PathCollection.Entries.Id | string | Path's collection entries ID | 
| Box.PathCollection.Entries.Sha1 | string | Path's collection entries SHA1 | 
| Box.PathCollection.Entries.Name | string | Path's collection entries name | 
| Box.PathCollection.Entries.SequenceId | string | Path's collection entries sequence_id | 
| Box.PathCollection.Entries.Type | string | Path's collection entries type | 
| Box.PathCollection.TotalCount | string | Size of path_collection object | 
| Box.PurgedAt | string | purged at | 
| Box.Type | string | File's type | 
| Box.Id | string | File's ID | 
| Box.Description | string | File's description | 
| Box.ItemStatus | string | File's status | 


#### Command Example
```!box_files_get_info file_id=723447059947```

#### Context Example
```json
{
    "Box": {
        "ContentCreatedAt": "2020-09-25T15:56:57-07:00",
        "ContentModifiedAt": "2020-09-25T16:26:54-07:00",
        "CreatedAt": "2020-09-25T15:56:57-07:00",
        "CreatedBy": {
            "Id": "14226607780",
            "Login": "eampleuser@paloaltonetworks.com",
            "Name": "My Name",
            "Type": "user"
        },
        "Description": "",
        "Etag": "1",
        "FileVersion": {
            "Id": "769566241780",
            "Sha1": "fc9ed186f1e2b4b5a93cf8d0f698a86d396b7b2f",
            "Type": "file_version"
        },
        "Id": "723447059947",
        "ItemStatus": "active",
        "ModifiedAt": "2020-09-25T16:27:19-07:00",
        "ModifiedBy": {
            "Id": "14226607780",
            "Login": "eampleuser@paloaltonetworks.com",
            "Name": "My Name",
            "Type": "user"
        },
        "Name": "Untitled Note 2020-09-25 15.56.56.boxnote",
        "OwnedBy": {
            "Id": "14226607780",
            "Login": "eampleuser@paloaltonetworks.com",
            "Name": "My Name",
            "Type": "user"
        },
        "Parent": {
            "Etag": "0",
            "Id": "123342801935",
            "Name": "My Box Notes",
            "SequenceId": "0",
            "Type": "folder"
        },
        "PathCollection": {
            "Entries": [
                "0",
                "1"
            ],
            "TotalCount": 2
        },
        "PurgedAt": null,
        "SequenceId": "1",
        "Sha1": "fc9ed186f1e2b4b5a93cf8d0f698a86d396b7b2f",
        "SharedLink": null,
        "Size": 959,
        "TrashedAt": null,
        "Type": "file"
    }
}
```

#### Human Readable Output

>### File info:
>
>| Key | Value |
>|---|---|
>| ContentCreatedAt | 2020-09-25T15:56:57-07:00 |
>| ContentModifiedAt | 2020-09-25T16:26:54-07:00 |
>| CreatedAt | 2020-09-25T15:56:57-07:00 |
>| CreatedBy.Id | 14226607780 |
>| CreatedBy.Login | exampleuser@paloaltonetworks.com |
>| CreatedBy.Name | My Name |
>| CreatedBy.Type | user |
>| Etag | 1 |
>| FileVersion.Id | 769566241780 |
>| FileVersion.Sha1 | fc9ed186f1e2b4b5a93cf8d0f698a86d396b7b2f |
>| FileVersion.Type | file_version |
>| Id | 723447059947 |
>| ItemStatus | active |
>| ModifiedAt | 2020-09-25T16:27:19-07:00 |
>| ModifiedBy.Id | 14226607780 |
>| ModifiedBy.Login | exampleuser@paloaltonetworks.com |
>| ModifiedBy.Name | My Name |
>| ModifiedBy.Type | user |
>| Name | Untitled Note 2020-09-25 15.56.56.boxnote |
>| OwnedBy.Id | 14226607780 | 
>| OwnedBy.Login | exampleuser@paloaltonetworks.com |
>| OwnedBy.Name | My Name |
>| OwnedBy.Type | user |
>| Parent.Etag | 0 |
>| Parent.Id | 123342801935 |
>| Parent.Name | My Box Notes |
>| Parent.SequenceId | 0 |
>| Parent.Type | folder |
>| PathCollection.Entries.0 | 0 |
>| PathCollection.Entries.1 | 1 |
>| PathCollection.TotalCount | 2 |
>| SequenceId | 1 |
>| Sha1 | fc9ed186f1e2b4b5a93cf8d0f698a86d396b7b2f |
>| Size | 959 |
>| Type | file |
