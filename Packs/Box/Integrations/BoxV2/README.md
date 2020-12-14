Manage Box users
This integration was integrated and tested with version xx of Box v2
## Configure Box v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Box v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | insecure | Trust any certificate \(not secure\) | False |
    | credentials_json | Credentials JSON | True |
    | as_user | As User for Fetching Incidents | False |
    | event_type |  | False |
    | default_user | Default User | False |
    | search_user_id | Auto-detect user IDs based on their email address. | False |
    | incidentType | Incident type | False |
    | isFetch | Fetch incidents | False |
    | first_fetch | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | max_fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### box-search-content
***
Searches for files, folders, web links, and shared files across the users content or across the entire enterprise.


#### Base Command

`box-search-content`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Limits the search results to any items of this type. This parameter only takes one value. By default the API returns items that match any of these types. Possible values are: file, folder, web_link. | Optional | 
| ancestor_folder_ids | Limits the search results to items within the given list of folders, defined as a comma separated lists of folder IDs. | Optional | 
| item_name | Query for an item by name. | Optional | 
| item_description | Search for an item by its description. | Optional | 
| comments | Search for an item by its comments. | Optional | 
| tag | Search for an item by its tag. | Optional | 
| created_range | Time frame of when the item was created. Can be comma separated RFC3339 timestamps, or relative to now. (e.g. 3 Days). | Optional | 
| file_extensions | Limits the search results to any files that match any of the provided file extensions. | Optional | 
| limit | Defines the maximum number of items to return as part of a page of results. Default is 100. | Optional | 
| offset | The offset of the item at which to begin the response. Default is 0. | Optional | 
| owner_uids | Limits the search results to any items that are owned by the given list of owners, defined as a list of comma separated user IDs. | Optional | 
| trash_content | Determines if the search should look in the trash for items. | Optional | 
| updated_at_range | Limits the search results to any items updated within a given date range. | Optional | 
| query | The string to search for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.Query.id | Number | The ID of the item found | 
| Box.Query.etag | Number | The entry tag for the item found. | 
| Box.Query.type | String | The type of the item found. | 
| Box.Query.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Query.name | String | The name of the item. | 
| Box.Query.sha1 | String | The SHA1 hash of the item. | 
| Box.Query.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.Query.file_version.type | String | Value is always file_version | 
| Box.Query.file_version.sha1 | String | The SHA1 hash of this version of the file. | 
| Box.Query.description | String | The description of the item. | 
| Box.Query.size | Number | The file size in bytes. | 
| Box.Query.path_collection.total_count | Number | The number of folders in the list. | 
| Box.Query.path_collection.entries.id | Number | The ID of the item found | 
| Box.Query.path_collection.entries.etag | Number | The entry tag for the item found. | 
| Box.Query.path_collection.entries.type | String | The type of the item found. | 
| Box.Query.path_collection.entries.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Query.path_collection.entries.name | String | The name of the item. | 
| Box.Query.created_at | Date | The date and time when the item was created on Box. | 
| Box.Query.modified_at | Date | The date and time when the item was last updated on Box. | 
| Box.Query.trashed_at | Date | The time at which the item was put in the trash. | 
| Box.Query.purged_at | Date | The time at which the item is expected to be purged from the trash. | 
| Box.Query.content_created_at | Date | The date and time at which the item was originally created, which might be before it was uploaded to Box. | 
| Box.Query.content_modified_at | Date | The date and time at which the item was last updated, which might be before it was uploaded to Box. | 
| Box.Query.created_by.id | Number | The unique identifier for the user who created the item. | 
| Box.Query.created_by.type | String | Value is always user. | 
| Box.Query.created_by.name | String | The display name of the user who created the item. | 
| Box.Query.created_by.login | String | The primary email address of the user who created the item. | 
| Box.Query.modified_by.id | Number | The unique identifier for the user who modified the item. | 
| Box.Query.modified_by.type | String | Value is always user. | 
| Box.Query.modified_by.name | String | The display name of the user who modified the item. | 
| Box.Query.modified_by.login | String | The primary email address of the user who modified the item. | 
| Box.Query.owned_by.id | Number | The unique identifier for the user who owns the item. | 
| Box.Query.owned_by.type | String | Value is always user. | 
| Box.Query.owned_by.name | String | The display name of the user who owns the item. | 
| Box.Query.owned_by.login | String | The primary email address of the user who owns the item. | 
| Box.Query.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.Query.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.Query.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.Query.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.Query.entries.shared_link.access | String | The access level for the shared link. | 
| Box.Query.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.Query.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.Query.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.Query.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.Query.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.Query.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.Query.entries.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.Query.shared_link.preview_count | Number | The number of times the item has been previewed. | 
| Box.Query.parent.id | Number | The ID of the parent for the item found | 
| Box.Query.parent.etag | Number | The entry tag for the parent of the item found. | 
| Box.Query.parent.type | String | The type for the parent of the item found. | 
| Box.Query.parent.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the parent of the item. | 
| Box.Query.parent.name | String | The name of the parent of the item. | 
| Box.Query.item_status | String | The status of the parent of the item. | 


#### Command Example
```!box-search-content item_name="test"```

#### Context Example
```json
{
    "Box": {
        "Query": [
            {
                "content_created_at": "2020-11-30T03:53:45-08:00",
                "content_modified_at": "2020-11-30T03:53:45-08:00",
                "created_at": "2020-11-30T03:53:45-08:00",
                "created_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "description": "",
                "etag": "0",
                "folder_upload_email": null,
                "id": "127109452066",
                "item_status": "active",
                "modified_at": "2020-11-30T03:53:45-08:00",
                "modified_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "name": "test-demo name",
                "owned_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "parent": {
                    "etag": null,
                    "id": "0",
                    "name": "All Files",
                    "sequence_id": null,
                    "type": "folder"
                },
                "path_collection": {
                    "entries": [
                        {
                            "etag": null,
                            "id": "0",
                            "name": "All Files",
                            "sequence_id": null,
                            "type": "folder"
                        }
                    ],
                    "total_count": 1
                },
                "purged_at": null,
                "sequence_id": "0",
                "shared_link": null,
                "size": 0,
                "trashed_at": null,
                "type": "folder"
            },
            {
                "content_created_at": "2020-11-19T07:05:00-08:00",
                "content_modified_at": "2020-11-19T07:05:00-08:00",
                "created_at": "2020-11-19T07:05:00-08:00",
                "created_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "description": "",
                "etag": "0",
                "folder_upload_email": null,
                "id": "126469445717",
                "item_status": "active",
                "modified_at": "2020-11-19T07:05:00-08:00",
                "modified_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "name": "Sample Testing Folder test",
                "owned_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "parent": {
                    "etag": null,
                    "id": "0",
                    "name": "All Files",
                    "sequence_id": null,
                    "type": "folder"
                },
                "path_collection": {
                    "entries": [
                        {
                            "etag": null,
                            "id": "0",
                            "name": "All Files",
                            "sequence_id": null,
                            "type": "folder"
                        }
                    ],
                    "total_count": 1
                },
                "purged_at": null,
                "sequence_id": "0",
                "shared_link": {
                    "access": "open",
                    "download_count": 0,
                    "download_url": null,
                    "effective_access": "open",
                    "effective_permission": "can_preview",
                    "is_password_enabled": false,
                    "permissions": {
                        "can_download": false,
                        "can_preview": true
                    },
                    "preview_count": 0,
                    "unshared_at": null,
                    "url": "https://app.box.com/s/bnw2mwxngw04j4iy2vve5hkxllxvz1xw",
                    "vanity_name": null,
                    "vanity_url": null
                },
                "size": 0,
                "trashed_at": null,
                "type": "folder"
            },
            {
                "content_created_at": "2020-12-13T03:50:02-08:00",
                "content_modified_at": "2020-12-13T03:50:02-08:00",
                "created_at": "2020-12-13T03:50:02-08:00",
                "created_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "description": "",
                "etag": "0",
                "folder_upload_email": null,
                "id": "127912817927",
                "item_status": "active",
                "modified_at": "2020-12-13T03:50:02-08:00",
                "modified_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "name": "Sample Testing Folder 2",
                "owned_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "parent": {
                    "etag": null,
                    "id": "0",
                    "name": "All Files",
                    "sequence_id": null,
                    "type": "folder"
                },
                "path_collection": {
                    "entries": [
                        {
                            "etag": null,
                            "id": "0",
                            "name": "All Files",
                            "sequence_id": null,
                            "type": "folder"
                        }
                    ],
                    "total_count": 1
                },
                "purged_at": null,
                "sequence_id": "0",
                "shared_link": null,
                "size": 0,
                "trashed_at": null,
                "type": "folder"
            },
            {
                "content_created_at": "2020-12-03T01:41:12-08:00",
                "content_modified_at": "2020-12-03T01:41:12-08:00",
                "created_at": "2020-12-03T01:41:12-08:00",
                "created_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "description": "",
                "etag": "0",
                "folder_upload_email": null,
                "id": "127304720432",
                "item_status": "active",
                "modified_at": "2020-12-03T01:41:12-08:00",
                "modified_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "name": "Sample Testing Folder test1",
                "owned_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "parent": {
                    "etag": null,
                    "id": "0",
                    "name": "All Files",
                    "sequence_id": null,
                    "type": "folder"
                },
                "path_collection": {
                    "entries": [
                        {
                            "etag": null,
                            "id": "0",
                            "name": "All Files",
                            "sequence_id": null,
                            "type": "folder"
                        }
                    ],
                    "total_count": 1
                },
                "purged_at": null,
                "sequence_id": "0",
                "shared_link": null,
                "size": 0,
                "trashed_at": null,
                "type": "folder"
            },
            {
                "content_created_at": "2020-11-25T06:50:31-08:00",
                "content_modified_at": "2020-11-25T06:50:31-08:00",
                "created_at": "2020-11-25T06:50:31-08:00",
                "created_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "description": "",
                "etag": "5",
                "file_version": {
                    "id": "794764999514",
                    "sha1": "bd992f78f1f50b4b424b0633870aca5eed3bedce",
                    "type": "file_version"
                },
                "id": "745898898314",
                "item_status": "active",
                "modified_at": "2020-12-09T08:42:32-08:00",
                "modified_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "name": "testing event1234.gif",
                "owned_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "parent": {
                    "etag": null,
                    "id": "0",
                    "name": "All Files",
                    "sequence_id": null,
                    "type": "folder"
                },
                "path_collection": {
                    "entries": [
                        {
                            "etag": null,
                            "id": "0",
                            "name": "All Files",
                            "sequence_id": null,
                            "type": "folder"
                        }
                    ],
                    "total_count": 1
                },
                "purged_at": null,
                "sequence_id": "5",
                "sha1": "bd992f78f1f50b4b424b0633870aca5eed3bedce",
                "shared_link": {
                    "access": "open",
                    "download_count": 0,
                    "download_url": "https://app.box.com/shared/static/96qoiji3fgi8jnamuks99obharump0vn.gif",
                    "effective_access": "open",
                    "effective_permission": "can_download",
                    "is_password_enabled": false,
                    "permissions": {
                        "can_download": true,
                        "can_preview": true
                    },
                    "preview_count": 0,
                    "unshared_at": null,
                    "url": "https://app.box.com/s/96qoiji3fgi8jnamuks99obharump0vn",
                    "vanity_name": null,
                    "vanity_url": null
                },
                "size": 3653705,
                "trashed_at": null,
                "type": "file"
            },
            {
                "content_created_at": "2020-11-19T00:53:57-08:00",
                "content_modified_at": "2020-11-19T00:53:57-08:00",
                "created_at": "2020-11-19T00:53:57-08:00",
                "created_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "description": "",
                "etag": "0",
                "folder_upload_email": null,
                "id": "126452434994",
                "item_status": "active",
                "modified_at": "2020-11-19T00:53:57-08:00",
                "modified_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "name": "Sample Testing Folder",
                "owned_by": {
                    "id": "14342567114",
                    "login": "ashamah@paloaltonetworks.com",
                    "name": "Andrew Shamah",
                    "type": "user"
                },
                "parent": {
                    "etag": null,
                    "id": "0",
                    "name": "All Files",
                    "sequence_id": null,
                    "type": "folder"
                },
                "path_collection": {
                    "entries": [
                        {
                            "etag": null,
                            "id": "0",
                            "name": "All Files",
                            "sequence_id": null,
                            "type": "folder"
                        }
                    ],
                    "total_count": 1
                },
                "purged_at": null,
                "sequence_id": "0",
                "shared_link": null,
                "size": 0,
                "trashed_at": null,
                "type": "folder"
            }
        ]
    }
}
```

#### Human Readable Output

>### Search results
>|Content Created At|Content Modified At|Created At|Created By|Etag|Id|Item Status|Modified At|Modified By|Name|Owned By|Parent|Path Collection|Sequence Id|Shared Link|Size|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-11-30T03:53:45-08:00 | 2020-11-30T03:53:45-08:00 | 2020-11-30T03:53:45-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 0 | 127109452066 | active | 2020-11-30T03:53:45-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | test-demo name | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | type: folder<br/>id: 0<br/>sequence_id: null<br/>etag: null<br/>name: All Files | total_count: 1<br/>entries: {'type': 'folder', 'id': '0', 'sequence_id': None, 'etag': None, 'name': 'All Files'} | 0 |  | 0 | folder |
>| 2020-11-19T07:05:00-08:00 | 2020-11-19T07:05:00-08:00 | 2020-11-19T07:05:00-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 0 | 126469445717 | active | 2020-11-19T07:05:00-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | Sample Testing Folder test | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | type: folder<br/>id: 0<br/>sequence_id: null<br/>etag: null<br/>name: All Files | total_count: 1<br/>entries: {'type': 'folder', 'id': '0', 'sequence_id': None, 'etag': None, 'name': 'All Files'} | 0 | url: https://app.box.com/s/bnw2mwxngw04j4iy2vve5hkxllxvz1xw<br/>download_url: null<br/>vanity_url: null<br/>vanity_name: null<br/>effective_access: open<br/>effective_permission: can_preview<br/>is_password_enabled: false<br/>unshared_at: null<br/>download_count: 0<br/>preview_count: 0<br/>access: open<br/>permissions: {"can_preview": true, "can_download": false} | 0 | folder |
>| 2020-12-13T03:50:02-08:00 | 2020-12-13T03:50:02-08:00 | 2020-12-13T03:50:02-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 0 | 127912817927 | active | 2020-12-13T03:50:02-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | Sample Testing Folder 2 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | type: folder<br/>id: 0<br/>sequence_id: null<br/>etag: null<br/>name: All Files | total_count: 1<br/>entries: {'type': 'folder', 'id': '0', 'sequence_id': None, 'etag': None, 'name': 'All Files'} | 0 |  | 0 | folder |
>| 2020-12-03T01:41:12-08:00 | 2020-12-03T01:41:12-08:00 | 2020-12-03T01:41:12-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 0 | 127304720432 | active | 2020-12-03T01:41:12-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | Sample Testing Folder test1 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | type: folder<br/>id: 0<br/>sequence_id: null<br/>etag: null<br/>name: All Files | total_count: 1<br/>entries: {'type': 'folder', 'id': '0', 'sequence_id': None, 'etag': None, 'name': 'All Files'} | 0 |  | 0 | folder |
>| 2020-11-25T06:50:31-08:00 | 2020-11-25T06:50:31-08:00 | 2020-11-25T06:50:31-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 5 | 745898898314 | active | 2020-12-09T08:42:32-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | testing event1234.gif | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | type: folder<br/>id: 0<br/>sequence_id: null<br/>etag: null<br/>name: All Files | total_count: 1<br/>entries: {'type': 'folder', 'id': '0', 'sequence_id': None, 'etag': None, 'name': 'All Files'} | 5 | url: https://app.box.com/s/96qoiji3fgi8jnamuks99obharump0vn<br/>download_url: https://app.box.com/shared/static/96qoiji3fgi8jnamuks99obharump0vn.gif<br/>vanity_url: null<br/>vanity_name: null<br/>effective_access: open<br/>effective_permission: can_download<br/>is_password_enabled: false<br/>unshared_at: null<br/>download_count: 0<br/>preview_count: 0<br/>access: open<br/>permissions: {"can_preview": true, "can_download": true} | 3653705 | file |
>| 2020-11-19T00:53:57-08:00 | 2020-11-19T00:53:57-08:00 | 2020-11-19T00:53:57-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 0 | 126452434994 | active | 2020-11-19T00:53:57-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | Sample Testing Folder | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | type: folder<br/>id: 0<br/>sequence_id: null<br/>etag: null<br/>name: All Files | total_count: 1<br/>entries: {'type': 'folder', 'id': '0', 'sequence_id': None, 'etag': None, 'name': 'All Files'} | 0 |  | 0 | folder |


### box-find-file-folder-by-share-link
***
Return the file represented by a shared link.


#### Base Command

`box-find-file-folder-by-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| shared_link | Linked used to share the file. | Required | 
| password | Password used to access the shared link. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | Number | The ID of the item found | 
| Box.ShareLink.etag | Number | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.ShareLink.name | String | The name of the item. | 
| Box.ShareLink.sha1 | String | The SHA1 hash of the item. | 
| Box.ShareLink.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.ShareLink.file_version.type | String | Value is always file_version | 
| Box.ShareLink.file_version.sha1 | String | The SHA1 hash of this version of the file. | 
| Box.ShareLink.description | String | The description of the item. | 
| Box.ShareLink.size | Number | The file size in bytes. | 
| Box.ShareLink.path_collection.total_count | Number | The number of folders in the list. | 
| Box.ShareLink.path_collection.entries.id | Number | The ID of the item found | 
| Box.ShareLink.path_collection.entries.etag | Number | The entry tag for the item found. | 
| Box.ShareLink.path_collection.entries.type | String | The type of the item found. | 
| Box.ShareLink.path_collection.entries.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.ShareLink.path_collection.entries.name | String | The name of the item. | 
| Box.ShareLink.created_at | Date | The date and time when the item was created on Box. | 
| Box.ShareLink.modified_at | Date | The date and time when the item was last updated on Box. | 
| Box.ShareLink.trashed_at | Date | The time at which the item was put in the trash. | 
| Box.ShareLink.purged_at | Date | The time at which the item is expected to be purged from the trash. | 
| Box.ShareLink.content_created_at | Date | The date and time at which the item was originally created, which might be before it was uploaded to Box. | 
| Box.ShareLink.content_modified_at | Date | The date and time at which the item was last updated, which might be before it was uploaded to Box. | 
| Box.ShareLink.created_by.id | Number | The unique identifier for the user who created the item. | 
| Box.ShareLink.created_by.type | String | Value is always user. | 
| Box.ShareLink.created_by.name | String | The display name of the user who created the item. | 
| Box.ShareLink.created_by.login | String | The primary email address of the user who created the item. | 
| Box.ShareLink.modified_by.id | Number | The unique identifier for the user who modified the item. | 
| Box.ShareLink.modified_by.type | String | Value is always user. | 
| Box.ShareLink.modified_by.name | String | The display name of the user who modified the item. | 
| Box.ShareLink.modified_by.login | String | The primary email address of the user who modified the item. | 
| Box.ShareLink.owned_by.id | Number | The unique identifier for the user who owns the item. | 
| Box.ShareLink.owned_by.type | String | Value is always user. | 
| Box.ShareLink.owned_by.name | String | The display name of the user who owns the item. | 
| Box.ShareLink.owned_by.login | String | The primary email address of the user who owns the item. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 
| Box.ShareLink.parent.id | Number | The ID of the parent for the item found | 
| Box.ShareLink.parent.etag | Number | The entry tag for the parent of the item found. | 
| Box.ShareLink.parent.type | String | The type for the parent of the item found. | 
| Box.ShareLink.parent.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the parent of the item. | 
| Box.ShareLink.parent.name | String | The name of the parent of the item. | 
| Box.ShareLink.item_status | String | The status of the parent of the item. | 


#### Command Example
```!box-find-file-folder-by-share-link shared_link="https://app.box.com/s/oyujr5qpxy1nbky394slw7n98v8pnpmy"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "content_created_at": "2020-11-25T05:20:55-08:00",
            "content_modified_at": "2020-11-25T05:20:55-08:00",
            "created_at": "2020-11-25T05:20:56-08:00",
            "created_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "description": "",
            "etag": "2",
            "file_version": {
                "id": "794731944502",
                "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                "type": "file_version"
            },
            "id": "745868717302",
            "item_status": "active",
            "modified_at": "2020-12-01T06:28:21-08:00",
            "modified_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "name": "55555.gif",
            "owned_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "parent": null,
            "path_collection": {
                "entries": [],
                "total_count": 0
            },
            "purged_at": null,
            "sequence_id": "2",
            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
            "shared_link": null,
            "size": 26891788,
            "trashed_at": null,
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>### File/Folder Share Link for https://app.box.com/s/oyujr5qpxy1nbky394slw7n98v8pnpmy
>|Content Created At|Content Modified At|Created At|Created By|Etag|File Version|Id|Item Status|Modified At|Modified By|Name|Owned By|Path Collection|Sequence Id|Sha1|Size|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-11-25T05:20:55-08:00 | 2020-11-25T05:20:55-08:00 | 2020-11-25T05:20:56-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 2 | type: file_version<br/>id: 794731944502<br/>sha1: 1ff8be1766d9e16b0b651f89001e8e7375c9e71f | 745868717302 | active | 2020-12-01T06:28:21-08:00 | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | 55555.gif | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | total_count: 0<br/>entries:  | 2 | 1ff8be1766d9e16b0b651f89001e8e7375c9e71f | 26891788 | file |


### box-get-shared-link-by-file
***
Gets the information for a shared link on a file.


#### Base Command

`box-get-shared-link-by-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The unique identifier that represent a file. | Required | 
| as_user | The user ID for the account used to access the file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | String | The ID of the item found | 
| Box.ShareLink.etag | String | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.entries.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 


#### Command Example
```!box-get-shared-link-by-file file_id="742246263170" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "7",
            "id": "742246263170",
            "shared_link": {
                "access": "open",
                "download_count": 0,
                "download_url": "https://app.box.com/shared/static/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao.jpeg",
                "effective_access": "open",
                "effective_permission": "can_preview",
                "is_password_enabled": false,
                "permissions": {
                    "can_download": false,
                    "can_preview": true
                },
                "preview_count": 0,
                "unshared_at": null,
                "url": "https://app.box.com/s/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao",
                "vanity_name": null,
                "vanity_url": null
            },
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>### Shared link information for the file 742246263170
>|Access|Download Count|Download Url|Effective Access|Effective Permission|Is Password Enabled|Permissions|Preview Count|Url|
>|---|---|---|---|---|---|---|---|---|
>| open | 0 | https://app.box.com/shared/static/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao.jpeg | open | can_preview | false | can_preview: true<br/>can_download: false | 0 | https://app.box.com/s/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao |


### box-create-file-share-link
***
Adds a shared link to a file.


#### Base Command

`box-create-file-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The unique identifier that represent a file. | Optional | 
| access | The level of access for the shared link. Possible values are: open, company, collaborators. | Optional | 
| password | The password required to access the shared link. | Optional | 
| unshared_at | The timestamp at which this shared link will expire. | Optional | 
| can_download | If the shared link allows for downloading of files. Possible values are: true, false. | Optional | 
| as_user | User which is making the request. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | Number | The ID of the item found | 
| Box.ShareLink.etag | Number | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.entries.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 


#### Command Example
```!box-create-file-share-link file_id="742246263170" access="open" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "7",
            "id": "742246263170",
            "shared_link": {
                "access": "open",
                "download_count": 0,
                "download_url": "https://app.box.com/shared/static/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao.jpeg",
                "effective_access": "open",
                "effective_permission": "can_preview",
                "is_password_enabled": false,
                "permissions": {
                    "can_download": false,
                    "can_preview": true
                },
                "preview_count": 0,
                "unshared_at": null,
                "url": "https://app.box.com/s/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao",
                "vanity_name": null,
                "vanity_url": null
            },
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>### File Share Link was created/updated for file_id: 742246263170
>|Access|Download Count|Download Url|Effective Access|Effective Permission|Is Password Enabled|Permissions|Preview Count|Url|
>|---|---|---|---|---|---|---|---|---|
>| open | 0 | https://app.box.com/shared/static/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao.jpeg | open | can_preview | false | can_preview: true<br/>can_download: false | 0 | https://app.box.com/s/ddo9okgj3xxxsqr7vk2wxv3zugtzqtao |


### box-update-file-share-link
***
Updates a shared link on a file.


#### Base Command

`box-update-file-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access | The level of access for the shared link. Possible values are: open, company, collaborators. | Optional | 
| password | The password required to access the shared link. | Optional | 
| unshared_at | The timestamp at which this shared link will expire. | Optional | 
| can_download | If the shared link allows for downloading of files. Possible values are: true, false. | Optional | 
| file_id | The unique identifier that represent a file. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | Number | The ID of the item found | 
| Box.ShareLink.etag | Number | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.entries.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 


#### Command Example
```!box-update-file-share-link file_id="742246263170" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "9",
            "id": "742246263170",
            "shared_link": {
                "access": "open",
                "download_count": 0,
                "download_url": "https://app.box.com/shared/static/2hvls15bpbmrjuo4vks6znrvye6gm6g1.jpeg",
                "effective_access": "open",
                "effective_permission": "can_preview",
                "is_password_enabled": false,
                "permissions": {
                    "can_download": false,
                    "can_preview": true
                },
                "preview_count": 0,
                "unshared_at": null,
                "url": "https://app.box.com/s/2hvls15bpbmrjuo4vks6znrvye6gm6g1",
                "vanity_name": null,
                "vanity_url": null
            },
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>### File Share Link was created/updated for file_id: 742246263170
>|Access|Download Count|Download Url|Effective Access|Effective Permission|Is Password Enabled|Permissions|Preview Count|Url|
>|---|---|---|---|---|---|---|---|---|
>| open | 0 | https://app.box.com/shared/static/2hvls15bpbmrjuo4vks6znrvye6gm6g1.jpeg | open | can_preview | false | can_preview: true<br/>can_download: false | 0 | https://app.box.com/s/2hvls15bpbmrjuo4vks6znrvye6gm6g1 |


### box-remove-file-share-link
***
Removes a shared link from a file.


#### Base Command

`box-remove-file-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The unique identifier that represents a file. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | String | The ID of the item found | 
| Box.ShareLink.etag | String | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 


#### Command Example
```!box-remove-file-share-link file_id="742246263170" as_user="ashamah@paloaltonetworks.com"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "8",
            "id": "742246263170",
            "shared_link": null,
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>File Share Link for the file_id 742246263170 was removed.

### box-get-shared-link-by-folder
***
Gets the information for a shared link on a folder.


#### Base Command

`box-get-shared-link-by-folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_id | The unique identifier that represent a folder. | Required | 
| as_user | User which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | String | The ID of the item found | 
| Box.ShareLink.etag | String | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.entries.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 


#### Command Example
``` ```

#### Human Readable Output



### box-create-folder-share-link
***
Adds a shared link to a folder.


#### Base Command

`box-create-folder-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access | The level of access for the shared link. Possible values are: open, company, collaborators. | Optional | 
| password | The password required to access the shared link. | Optional | 
| unshared_at | The timestamp at which this shared link will expire. | Optional | 
| can_download | If the shared link allows for downloading of folders. Possible values are: true, false. | Optional | 
| folder_id | The unique identifier that represent a folder. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | String | The ID of the item found | 
| Box.ShareLink.etag | String | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.entries.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 


#### Command Example
```!box-create-folder-share-link folder_id="125959916474" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "0",
            "id": "125959916474",
            "shared_link": {
                "access": "open",
                "download_count": 0,
                "download_url": null,
                "effective_access": "open",
                "effective_permission": "can_preview",
                "is_password_enabled": false,
                "permissions": {
                    "can_download": false,
                    "can_preview": true
                },
                "preview_count": 0,
                "unshared_at": null,
                "url": "https://app.box.com/s/c5g45p507hb8ury5r7xnl2a3ole5cy33",
                "vanity_name": null,
                "vanity_url": null
            },
            "type": "folder"
        }
    }
}
```

#### Human Readable Output

>### Folder Share Link for 125959916474
>|Etag|Id|Shared Link|Type|
>|---|---|---|---|
>| 0 | 125959916474 | url: https://app.box.com/s/c5g45p507hb8ury5r7xnl2a3ole5cy33<br/>download_url: null<br/>vanity_url: null<br/>vanity_name: null<br/>effective_access: open<br/>effective_permission: can_preview<br/>is_password_enabled: false<br/>unshared_at: null<br/>download_count: 0<br/>preview_count: 0<br/>access: open<br/>permissions: {"can_preview": true, "can_download": false} | folder |


### box-update-folder-share-link
***
Updates a shared link on a folder.


#### Base Command

`box-update-folder-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_id | The unique identifier that represent a folder. | Required | 
| as_user | The user which is performing the action. | Required | 
| access | The level of access for the shared link. Possible values are: open, company, collaborators. | Optional | 
| password | The password required to access the shared link. | Optional | 
| unshared_at | The timestamp at which this shared link will expire. | Optional | 
| can_download | If the shared link allows for downloading of folders. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | String | The ID of the item found | 
| Box.ShareLink.etag | String | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.entries.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 


#### Command Example
```!box-update-folder-share-link folder_id="125959916474" as_user="14342567114" access="open" can_download="false"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "0",
            "id": "125959916474",
            "shared_link": {
                "access": "open",
                "download_count": 0,
                "download_url": null,
                "effective_access": "open",
                "effective_permission": "can_preview",
                "is_password_enabled": false,
                "permissions": {
                    "can_download": false,
                    "can_preview": true
                },
                "preview_count": 0,
                "unshared_at": null,
                "url": "https://app.box.com/s/e29dyat8gnaz6lzav2gws0qqsm2g33oo",
                "vanity_name": null,
                "vanity_url": null
            },
            "type": "folder"
        }
    }
}
```

#### Human Readable Output

>### Folder Share Link for 125959916474
>|Etag|Id|Shared Link|Type|
>|---|---|---|---|
>| 0 | 125959916474 | url: https://app.box.com/s/e29dyat8gnaz6lzav2gws0qqsm2g33oo<br/>download_url: null<br/>vanity_url: null<br/>vanity_name: null<br/>effective_access: open<br/>effective_permission: can_preview<br/>is_password_enabled: false<br/>unshared_at: null<br/>download_count: 0<br/>preview_count: 0<br/>access: open<br/>permissions: {"can_preview": true, "can_download": false} | folder |


### box-remove-folder-share-link
***
Removes a shared link from a folder.


#### Base Command

`box-remove-folder-share-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_id | The unique identifier that represent a folder. | Required | 
| as_user | User which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | String | The ID of the item found | 
| Box.ShareLink.etag | String | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 


#### Command Example
```!box-remove-folder-share-link folder_id="125959916474" as_user="ashamah@paloaltonetworks.com"```

#### Context Example
```json
{
    "Box": {
        "ShareLink": {
            "etag": "0",
            "id": "125959916474",
            "shared_link": null,
            "type": "folder"
        }
    }
}
```

#### Human Readable Output

>### Folder Share Link for 125959916474 was removed.
>|Etag|Id|Type|
>|---|---|---|
>| 0 | 125959916474 | folder |


### box-get-folder
***
Retrieves details for a folder, including the first 100 entries in the folder.


#### Base Command

`box-get-folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_id | The unique identifier that represent a folder. | Required | 
| as_user | The user that is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.ShareLink.id | Number | The ID of the item found | 
| Box.ShareLink.etag | Number | The entry tag for the item found. | 
| Box.ShareLink.type | String | The type of the item found. | 
| Box.ShareLink.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.ShareLink.name | String | The name of the item. | 
| Box.ShareLink.sha1 | String | The SHA1 hash of the item. | 
| Box.ShareLink.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.ShareLink.file_version.type | String | Value is always file_version | 
| Box.ShareLink.file_version.sha1 | String | The SHA1 hash of this version of the file. | 
| Box.ShareLink.description | String | The description of the item. | 
| Box.ShareLink.size | Number | The file size in bytes. | 
| Box.ShareLink.path_collection.total_count | Number | The number of folders in the list. | 
| Box.ShareLink.path_collection.entries.id | Number | The ID of the item found | 
| Box.ShareLink.path_collection.entries.etag | Number | The entry tag for the item found. | 
| Box.ShareLink.path_collection.entries.type | String | The type of the item found. | 
| Box.ShareLink.path_collection.entries.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.ShareLink.path_collection.entries.name | String | The name of the item. | 
| Box.ShareLink.created_at | Date | The date and time when the item was created on Box. | 
| Box.ShareLink.modified_at | Date | The date and time when the item was last updated on Box. | 
| Box.ShareLink.trashed_at | Date | The time at which the item was put in the trash. | 
| Box.ShareLink.purged_at | Date | The time at which the item is expected to be purged from the trash. | 
| Box.ShareLink.content_created_at | Date | The date and time at which the item was originally created, which might be before it was uploaded to Box. | 
| Box.ShareLink.content_modified_at | Date | The date and time at which the item was last updated, which might be before it was uploaded to Box. | 
| Box.ShareLink.created_by.id | Number | The unique identifier for the user who created the item. | 
| Box.ShareLink.created_by.type | String | Value is always user. | 
| Box.ShareLink.created_by.name | String | The display name of the user who created the item. | 
| Box.ShareLink.created_by.login | String | The primary email address of the user who created the item. | 
| Box.ShareLink.modified_by.id | Number | The unique identifier for the user who modified the item. | 
| Box.ShareLink.modified_by.type | String | Value is always user. | 
| Box.ShareLink.modified_by.name | String | The display name of the user who modified the item. | 
| Box.ShareLink.modified_by.login | String | The primary email address of the user who modified the item. | 
| Box.ShareLink.owned_by.id | Number | The unique identifier for the user who owns the item. | 
| Box.ShareLink.owned_by.type | String | Value is always user. | 
| Box.ShareLink.owned_by.name | String | The display name of the user who owns the item. | 
| Box.ShareLink.owned_by.login | String | The primary email address of the user who owns the item. | 
| Box.ShareLink.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.ShareLink.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.ShareLink.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.ShareLink.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.ShareLink.shared_link.access | String | The access level for the shared link. | 
| Box.ShareLink.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.ShareLink.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.ShareLink.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.ShareLink.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.ShareLink.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.ShareLink.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.ShareLink.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.ShareLink.shared_link.preview_count | Number | The number of times the item has been previewed. | 
| Box.ShareLink.parent.id | Number | The ID of the parent for the item found | 
| Box.ShareLink.parent.etag | Number | The entry tag for the parent of the item found. | 
| Box.ShareLink.parent.type | String | The type for the parent of the item found. | 
| Box.ShareLink.parent.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the parent of the item. | 
| Box.ShareLink.parent.name | String | The name of the parent of the item. | 
| Box.ShareLink.item_status | String | The status of the parent of the item. | 


#### Command Example
```!box-get-folder folder_id="0" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "Folder": {
            "content_created_at": null,
            "content_modified_at": null,
            "created_at": null,
            "created_by": {
                "id": "",
                "login": "",
                "name": "",
                "type": "user"
            },
            "description": "",
            "etag": null,
            "folder_upload_email": null,
            "id": "0",
            "item_collection": {
                "entries": [
                    {
                        "etag": "0",
                        "id": "125959916474",
                        "name": "My Box Notes",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "126452434994",
                        "name": "Sample Testing Folder",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "127912817927",
                        "name": "Sample Testing Folder 2",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "126469445717",
                        "name": "Sample Testing Folder test",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "127304720432",
                        "name": "Sample Testing Folder test1",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "127109452066",
                        "name": "test-demo name",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "2",
                        "file_version": {
                            "id": "794731944502",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745868717302",
                        "name": "55555.gif",
                        "sequence_id": "2",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "802646696736",
                            "sha1": "f401d87fa1cc4f96a357c564bf0de2e19ccf9d1f",
                            "type": "file_version"
                        },
                        "id": "752998071936",
                        "name": "customers.jpg",
                        "sequence_id": "0",
                        "sha1": "f401d87fa1cc4f96a357c564bf0de2e19ccf9d1f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794713426050",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745851995250",
                        "name": "image.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794716642653",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745854929853",
                        "name": "image1.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794719141622",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745857164822",
                        "name": "image2.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794721102684",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745859107884",
                        "name": "image3.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794733314512",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745870218112",
                        "name": "image4.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794736891054",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745873525854",
                        "name": "image6_please_work.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "2",
                        "file_version": {
                            "id": "792056280660",
                            "sha1": "533a85c782614a6dfe19b83f7d628466ceb00c39",
                            "type": "file_version"
                        },
                        "id": "743439873060",
                        "name": "new-devs-touching-the-build.gif",
                        "sequence_id": "2",
                        "sha1": "533a85c782614a6dfe19b83f7d628466ceb00c39",
                        "type": "file"
                    },
                    {
                        "etag": "5",
                        "file_version": {
                            "id": "794764999514",
                            "sha1": "bd992f78f1f50b4b424b0633870aca5eed3bedce",
                            "type": "file_version"
                        },
                        "id": "745898898314",
                        "name": "testing event1234.gif",
                        "sequence_id": "5",
                        "sha1": "bd992f78f1f50b4b424b0633870aca5eed3bedce",
                        "type": "file"
                    }
                ],
                "limit": 100,
                "offset": 0,
                "order": [
                    {
                        "by": "type",
                        "direction": "ASC"
                    },
                    {
                        "by": "name",
                        "direction": "ASC"
                    }
                ],
                "total_count": 16
            },
            "item_status": "active",
            "modified_at": null,
            "modified_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "name": "All Files",
            "owned_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "parent": null,
            "path_collection": {
                "entries": [],
                "total_count": 0
            },
            "purged_at": null,
            "sequence_id": null,
            "shared_link": null,
            "size": 193450921,
            "trashed_at": null,
            "type": "folder"
        }
    }
}
```

#### Human Readable Output

>### Folder overview for 0.
>|Created By|Id|Item Status|Modified By|Name|Owned By|Path Collection|Size|Type|
>|---|---|---|---|---|---|---|---|---|
>| type: user<br/>id: <br/>name: <br/>login:  | 0 | active | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | All Files | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | total_count: 0<br/>entries:  | 193450921 | folder |
>### File contents for the folder 0
>|Etag|Id|Name|Sequence Id|Type|
>|---|---|---|---|---|
>| 0 | 125959916474 | My Box Notes | 0 | folder |
>| 0 | 126452434994 | Sample Testing Folder | 0 | folder |
>| 0 | 127912817927 | Sample Testing Folder 2 | 0 | folder |
>| 0 | 126469445717 | Sample Testing Folder test | 0 | folder |
>| 0 | 127304720432 | Sample Testing Folder test1 | 0 | folder |
>| 0 | 127109452066 | test-demo name | 0 | folder |
>| 2 | 745868717302 | 55555.gif | 2 | file |
>| 0 | 752998071936 | customers.jpg | 0 | file |
>| 0 | 745851995250 | image.gif | 0 | file |
>| 0 | 745854929853 | image1.gif | 0 | file |
>| 0 | 745857164822 | image2.gif | 0 | file |
>| 0 | 745859107884 | image3.gif | 0 | file |
>| 0 | 745870218112 | image4.gif | 0 | file |
>| 0 | 745873525854 | image6_please_work.gif | 0 | file |
>| 2 | 743439873060 | new-devs-touching-the-build.gif | 2 | file |
>| 5 | 745898898314 | testing event1234.gif | 5 | file |


### box-list-folder-items
***
Retrieves a page of items in a folder.


#### Base Command

`box-list-folder-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_id | The unique identifier that represent a folder. | Required | 
| as_user | The user which is performing the action. | Required | 
| limit | The maximum number of items to return per page. Default is 100. | Optional | 
| offset | The offset of the item at which to begin the response. Default is 0. | Optional | 
| sort | The field the results should be sorted by. Possible values are: id, name, date, size. Default is name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.Folder.id | Number | The ID of the folder. | 
| Box.Folder.etag | Number | The entity tag of the folder. | 
| Box.Folder.type | String | Is always \`folder\`. | 
| Box.Folder.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Folder.name | String | The name of the folder. | 
| Box.Folder.sha1 | String | The SHA1 has of the folder. | 
| Box.Folder.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.Folder.file_version.type | String | Value is always file_version | 
| Box.Folder.file_version.sha1 | String | The SHA1 hash of this version of the file. | 


#### Command Example
```!box-list-folder-items folder_id="0" as_user="ashamah@paloaltonetworks.com"```

#### Context Example
```json
{
    "Box": {
        "Folder": {
            "content_created_at": null,
            "content_modified_at": null,
            "created_at": null,
            "created_by": {
                "id": "",
                "login": "",
                "name": "",
                "type": "user"
            },
            "description": "",
            "etag": null,
            "folder_upload_email": null,
            "id": "0",
            "item_collection": {
                "entries": [
                    {
                        "etag": "0",
                        "id": "125959916474",
                        "name": "My Box Notes",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "126452434994",
                        "name": "Sample Testing Folder",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "127912817927",
                        "name": "Sample Testing Folder 2",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "126469445717",
                        "name": "Sample Testing Folder test",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "127304720432",
                        "name": "Sample Testing Folder test1",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "0",
                        "id": "127109452066",
                        "name": "test-demo name",
                        "sequence_id": "0",
                        "type": "folder"
                    },
                    {
                        "etag": "2",
                        "file_version": {
                            "id": "794731944502",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745868717302",
                        "name": "55555.gif",
                        "sequence_id": "2",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "802646696736",
                            "sha1": "f401d87fa1cc4f96a357c564bf0de2e19ccf9d1f",
                            "type": "file_version"
                        },
                        "id": "752998071936",
                        "name": "customers.jpg",
                        "sequence_id": "0",
                        "sha1": "f401d87fa1cc4f96a357c564bf0de2e19ccf9d1f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794713426050",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745851995250",
                        "name": "image.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794716642653",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745854929853",
                        "name": "image1.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794719141622",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745857164822",
                        "name": "image2.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794721102684",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745859107884",
                        "name": "image3.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794733314512",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745870218112",
                        "name": "image4.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "0",
                        "file_version": {
                            "id": "794736891054",
                            "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                            "type": "file_version"
                        },
                        "id": "745873525854",
                        "name": "image6_please_work.gif",
                        "sequence_id": "0",
                        "sha1": "1ff8be1766d9e16b0b651f89001e8e7375c9e71f",
                        "type": "file"
                    },
                    {
                        "etag": "2",
                        "file_version": {
                            "id": "792056280660",
                            "sha1": "533a85c782614a6dfe19b83f7d628466ceb00c39",
                            "type": "file_version"
                        },
                        "id": "743439873060",
                        "name": "new-devs-touching-the-build.gif",
                        "sequence_id": "2",
                        "sha1": "533a85c782614a6dfe19b83f7d628466ceb00c39",
                        "type": "file"
                    },
                    {
                        "etag": "5",
                        "file_version": {
                            "id": "794764999514",
                            "sha1": "bd992f78f1f50b4b424b0633870aca5eed3bedce",
                            "type": "file_version"
                        },
                        "id": "745898898314",
                        "name": "testing event1234.gif",
                        "sequence_id": "5",
                        "sha1": "bd992f78f1f50b4b424b0633870aca5eed3bedce",
                        "type": "file"
                    }
                ],
                "limit": 100,
                "offset": 0,
                "order": [
                    {
                        "by": "type",
                        "direction": "ASC"
                    },
                    {
                        "by": "name",
                        "direction": "ASC"
                    }
                ],
                "total_count": 16
            },
            "item_status": "active",
            "modified_at": null,
            "modified_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "name": "All Files",
            "owned_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "parent": null,
            "path_collection": {
                "entries": [],
                "total_count": 0
            },
            "purged_at": null,
            "sequence_id": null,
            "shared_link": null,
            "size": 193450921,
            "trashed_at": null,
            "type": "folder"
        }
    }
}
```

#### Human Readable Output

>### Folder overview for 0.
>|Created By|Id|Item Status|Modified By|Name|Owned By|Path Collection|Size|Type|
>|---|---|---|---|---|---|---|---|---|
>| type: user<br/>id: <br/>name: <br/>login:  | 0 | active | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | All Files | type: user<br/>id: 14342567114<br/>name: Andrew Shamah<br/>login: ashamah@paloaltonetworks.com | total_count: 0<br/>entries:  | 193450921 | folder |
>### File contents for the folder 0
>|Etag|Id|Name|Sequence Id|Type|
>|---|---|---|---|---|
>| 0 | 125959916474 | My Box Notes | 0 | folder |
>| 0 | 126452434994 | Sample Testing Folder | 0 | folder |
>| 0 | 127912817927 | Sample Testing Folder 2 | 0 | folder |
>| 0 | 126469445717 | Sample Testing Folder test | 0 | folder |
>| 0 | 127304720432 | Sample Testing Folder test1 | 0 | folder |
>| 0 | 127109452066 | test-demo name | 0 | folder |
>| 2 | 745868717302 | 55555.gif | 2 | file |
>| 0 | 752998071936 | customers.jpg | 0 | file |
>| 0 | 745851995250 | image.gif | 0 | file |
>| 0 | 745854929853 | image1.gif | 0 | file |
>| 0 | 745857164822 | image2.gif | 0 | file |
>| 0 | 745859107884 | image3.gif | 0 | file |
>| 0 | 745870218112 | image4.gif | 0 | file |
>| 0 | 745873525854 | image6_please_work.gif | 0 | file |
>| 2 | 743439873060 | new-devs-touching-the-build.gif | 2 | file |
>| 5 | 745898898314 | testing event1234.gif | 5 | file |


### box-folder-create
***
Creates a new empty folder within the specified parent folder.


#### Base Command

`box-folder-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for the new folder. | Required | 
| parent_id | The parent folder to create the new folder within. Default is 0. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.Folder.id | Number | The ID of the folder created. | 
| Box.Folder.etag | Number | The entry tag for the folder created. | 
| Box.Folder.type | String | The type of folder. | 
| Box.Folder.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the folder. | 
| Box.Folder.name | String | The name of the folder. | 
| Box.Folder.sha1 | String | The SHA1 hash of the folder. | 
| Box.Folder.file_version.id | Number | The unique identifier that represents a file version. | 
| Box.Folder.file_version.type | String | Value is always file_version | 
| Box.Folder.file_version.sha1 | String | The SHA1 hash of this version of the file. | 
| Box.Folder.description | String | The description of the item. | 
| Box.Folder.size | Number | The folder size in bytes. | 
| Box.Folder.path_collection.total_count | Number | The number of folders in the list. | 
| Box.Folder.path_collection.entries.id | Number | The ID of the item found | 
| Box.Folder.path_collection.entries.etag | Number | The entry tag for the item found. | 
| Box.Folder.path_collection.entries.type | String | The type of the item found. | 
| Box.Folder.path_collection.entries.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Folder.path_collection.entries.name | String | The name of the item. | 
| Box.Folder.created_at | Date | The date and time when the item was created on Box. | 
| Box.Folder.modified_at | Date | The date and time when the item was last updated on Box. | 
| Box.Folder.trashed_at | Date | The time at which the item was put in the trash. | 
| Box.Folder.purged_at | Date | The time at which the item is expected to be purged from the trash. | 
| Box.Folder.content_created_at | Date | The date and time at which the item was originally created, which might be before it was uploaded to Box. | 
| Box.Folder.content_modified_at | Date | The date and time at which the item was last updated, which might be before it was uploaded to Box. | 
| Box.Folder.created_by.id | Number | The unique identifier for the user who created the item. | 
| Box.Folder.created_by.type | String | Value is always user. | 
| Box.Folder.created_by.name | String | The display name of the user who created the item. | 
| Box.Folder.created_by.login | String | The primary email address of the user who created the item. | 
| Box.Folder.modified_by.id | Number | The unique identifier for the user who modified the item. | 
| Box.Folder.modified_by.type | String | Value is always user. | 
| Box.Folder.modified_by.name | String | The display name of the user who modified the item. | 
| Box.Folder.modified_by.login | String | The primary email address of the user who modified the item. | 
| Box.Folder.owned_by.id | Number | The unique identifier for the user who owns the item. | 
| Box.Folder.owned_by.type | String | Value is always user. | 
| Box.Folder.owned_by.name | String | The display name of the user who owns the item. | 
| Box.Folder.owned_by.login | String | The primary email address of the user who owns the item. | 
| Box.Folder.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.Folder.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.Folder.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.Folder.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.Folder.shared_link.access | String | The access level for the shared link. | 
| Box.Folder.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.Folder.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.Folder.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.Folder.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.Folder.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.Folder.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.Folder.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.Folder.shared_link.preview_count | Number | The number of times the item has been previewed. | 
| Box.Folder.parent.id | Number | The ID of the parent for the item found | 
| Box.Folder.parent.etag | Number | The entry tag for the parent of the item found. | 
| Box.Folder.parent.type | String | The type for the parent of the item found. | 
| Box.Folder.parent.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the parent of the item. | 
| Box.Folder.parent.name | String | The name of the parent of the item. | 
| Box.Folder.item_status | String | The status of the parent of the item. | 


#### Command Example
``` ```

#### Human Readable Output



### box-file-delete
***
Deletes a file, either permanently or by moving it to the trash.


#### Base Command

`box-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The unique identifier that represent a file. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box-file-delete file_id="751526132294" as_user="14342567114"```

#### Context Example
```json
{}
```

#### Human Readable Output

>The file 751526132294 was successfully deleted.

### box-list-users
***
Returns a list of all users for the Enterprise along with their user_id, public_name, and login.


#### Base Command

`box-list-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Attributes to include in the response. Possible values are: id, type, name. | Optional | 
| filter_term | Limits the results to only users who's name or login start with the search term. | Optional | 
| limit | The maximum number of items to return per page. Default is 100. | Optional | 
| offset | The offset of the item at which to begin the response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.User.id | Number | The unique identifier for this user. | 
| Box.User.type | String | Value is always user. | 
| Box.User.name | String | The display name of this user. | 
| Box.User.login | String | The primary email address of this user. | 
| Box.User.created_at | Date | When the user object was created. | 
| Box.User.modified_at | Date | When the user object was last modified. | 
| Box.User.language | String | The language of the user, formatted in modified version of the ISO 639-1 format. | 
| Box.User.timezone | String | The users timezone. | 
| Box.User.space_amount | Number | The users total available space amount in bytes. | 
| Box.User.space_used | Number | The amount of space in use by the user. | 
| Box.User.max_upload_size | Number | The maximum individual file size in bytes the user can have. | 
| Box.User.status | String | The users account status. | 
| Box.User.job_title | String | The users job title. | 
| Box.User.phone | Number | The users phone number. | 
| Box.User.address | String | The users address. | 
| Box.User.avatar_url | String | URL of the users avatar image | 
| Box.User.notification_email.email | String | The email address to send the notifications to. | 
| Box.User.notification_email.is_confirmed | Boolean | Specifies if this email address has been confirmed. | 


#### Command Example
``` ```

#### Human Readable Output



### box-upload-file
***
Uploads a file to the given folder.


#### Base Command

`box-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID of the file to upload. | Required | 
| as_user | The id of the user who is performing the action. | Required | 
| file_name | The name of the file. | Optional | 
| folder_id | The ID of the folder the file is being uploaded to. Default is 0/root. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.File.id | Number | The ID of the item found | 
| Box.File.etag | Number | The entry tag for the item found. | 
| Box.File.type | String | The type of the item found. | 
| Box.File.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.File.name | String | The name of the item. | 
| Box.File.sha1 | String | The SHA1 hash of the item. | 
| Box.File.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.File.file_version.type | String | Value is always file_version | 
| Box.File.file_version.sha1 | String | The SHA1 hash of this version of the file. | 
| Box.File.description | String | The description of the item. | 
| Box.File.size | Number | The file size in bytes. | 
| Box.File.path_collection.total_count | Number | The number of folders in the list. | 
| Box.File.path_collection.entries.id | Number | The ID of the item found | 
| Box.File.path_collection.entries.etag | Number | The entry tag for the item found. | 
| Box.File.path_collection.entries.type | String | The type of the item found. | 
| Box.File.path_collection.entries.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.File.path_collection.entries.name | String | The name of the item. | 
| Box.File.created_at | Date | The date and time when the item was created on Box. | 
| Box.File.modified_at | Date | The date and time when the item was last updated on Box. | 
| Box.File.trashed_at | Date | The time at which the item was put in the trash. | 
| Box.File.purged_at | Date | The time at which the item is expected to be purged from the trash. | 
| Box.File.content_created_at | Date | The date and time at which the item was originally created, which might be before it was uploaded to Box. | 
| Box.File.content_modified_at | Date | The date and time at which the item was last updated, which might be before it was uploaded to Box. | 
| Box.File.created_by.id | Number | The unique identifier for the user who created the item. | 
| Box.File.created_by.type | String | Value is always user. | 
| Box.File.created_by.name | String | The display name of the user who created the item. | 
| Box.File.created_by.login | String | The primary email address of the user who created the item. | 
| Box.File.modified_by.id | Number | The unique identifier for the user who modified the item. | 
| Box.File.modified_by.type | String | Value is always user. | 
| Box.File.modified_by.name | String | The display name of the user who modified the item. | 
| Box.File.modified_by.login | String | The primary email address of the user who modified the item. | 
| Box.File.owned_by.id | Number | The unique identifier for the user who owns the item. | 
| Box.File.owned_by.type | String | Value is always user. | 
| Box.File.owned_by.name | String | The display name of the user who owns the item. | 
| Box.File.owned_by.login | String | The primary email address of the user who owns the item. | 
| Box.File.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.File.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.File.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.File.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.File.shared_link.access | String | The access level for the shared link. | 
| Box.File.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.File.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.File.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.File.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.File.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.File.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.File.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.File.shared_link.preview_count | Number | The number of times the item has been previewed. | 
| Box.File.parent.id | Number | The ID of the parent for the item found | 
| Box.File.parent.etag | Number | The entry tag for the parent of the item found. | 
| Box.File.parent.type | String | The type for the parent of the item found. | 
| Box.File.parent.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the parent of the item. | 
| Box.File.parent.name | String | The name of the parent of the item. | 
| Box.File.item_status | String | The status of the parent of the item. | 


#### Command Example
``` ```

#### Human Readable Output



### box-trashed-items-list
***
Retrieves the files and folders that have been moved to the trash.


#### Base Command

`box-trashed-items-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| as_user | The user performing the action. | Required | 
| limit | The maximum number of items to return per page. | Optional | 
| offset | The offset of the item at which to begin the response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.Trash.id | Number | The ID of the item found | 
| Box.Trash.etag | Number | The entry tag for the item found. | 
| Box.Trash.type | String | The type of the item found. | 
| Box.Trash.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Trash.name | String | The name of the item. | 
| Box.Trash.sha1 | String | The SHA1 hash of the item. | 
| Box.Trash.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.Trash.file_version.type | String | Value is always file_version | 
| Box.Trash.file_version.sha1 | String | The SHA1 hash of this version of the file. | 


#### Command Example
```!box-trashed-items-list as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "Trash": {
            "etag": "3",
            "file_version": {
                "id": "801011020694",
                "sha1": "aa58d9692d58f5d9316d7cf1950d19a0b01bc204",
                "type": "file_version"
            },
            "id": "751526132294",
            "name": "list.json",
            "sequence_id": "3",
            "sha1": "aa58d9692d58f5d9316d7cf1950d19a0b01bc204",
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>### Trashed items were found.
>|Etag|File Version|Id|Name|Sequence Id|Sha1|Type|
>|---|---|---|---|---|---|---|
>| 3 | type: file_version<br/>id: 801011020694<br/>sha1: aa58d9692d58f5d9316d7cf1950d19a0b01bc204 | 751526132294 | list.json | 3 | aa58d9692d58f5d9316d7cf1950d19a0b01bc204 | file |


### box-trashed-item-restore
***
Restores a file or folder that has been moved to the trash.


#### Base Command

`box-trashed-item-restore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The unique identifier that represents the file or folder. | Required | 
| type | Type of the object to restore. Possible values are: file, folder. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.Item.id | Number | The ID of the item found | 
| Box.Item.etag | Number | The entry tag for the item found. | 
| Box.Item.type | String | The type of the item found. | 
| Box.Item.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Item.name | String | The name of the item. | 
| Box.Item.sha1 | String | The SHA1 hash of the item. | 
| Box.Item.file_version.id | Number | The unique identifier that represent a file version. | 
| Box.Item.file_version.type | String | Value is always file_version | 
| Box.Item.file_version.sha1 | String | The SHA1 hash of this version of the file. | 
| Box.Item.description | String | The description of the item. | 
| Box.Item.size | Number | The file size in bytes. | 
| Box.Item.path_collection.total_count | Number | The number of folders in the list. | 
| Box.Item.path_collection.entries.id | Number | The ID of the item found | 
| Box.Item.path_collection.entries.etag | Number | The entry tag for the item found. | 
| Box.Item.path_collection.entries.type | String | The type of the item found. | 
| Box.Item.path_collection.entries.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the item. | 
| Box.Item.path_collection.entries.name | String | The name of the item. | 
| Box.Item.created_at | Date | The date and time when the item was created on Box. | 
| Box.Item.modified_at | Date | The date and time when the item was last updated on Box. | 
| Box.Item.trashed_at | Date | The time at which the item was put in the trash. | 
| Box.Item.purged_at | Date | The time at which the item is expected to be purged from the trash. | 
| Box.Item.content_created_at | Date | The date and time at which the item was originally created, which might be before it was uploaded to Box. | 
| Box.Item.content_modified_at | Date | The date and time at which the item was last updated, which might be before it was uploaded to Box. | 
| Box.Item.created_by.id | Number | The unique identifier for the user who created the item. | 
| Box.Item.created_by.type | String | Value is always user. | 
| Box.Item.created_by.name | String | The display name of the user who created the item. | 
| Box.Item.created_by.login | String | The primary email address of the user who created the item. | 
| Box.Item.modified_by.id | Number | The unique identifier for the user who modified the item. | 
| Box.Item.modified_by.type | String | Value is always user. | 
| Box.Item.modified_by.name | String | The display name of the user who modified the item. | 
| Box.Item.modified_by.login | String | The primary email address of the user who modified the item. | 
| Box.Item.owned_by.id | Number | The unique identifier for the user who owns the item. | 
| Box.Item.owned_by.type | String | Value is always user. | 
| Box.Item.owned_by.name | String | The display name of the user who owns the item. | 
| Box.Item.owned_by.login | String | The primary email address of the user who owns the item. | 
| Box.Item.shared_link.url | String | The URL that can be used to access the item on Box. | 
| Box.Item.shared_link.download_url | String | The URL that can be used to download the item from Box. | 
| Box.Item.shared_link.vanity_url | String | The "Custom URL" that can also be used to preview the item on Box. | 
| Box.Item.shared_link.vanity_name | String | The custom name of a shared link, as used in the vanity_url field. | 
| Box.Item.shared_link.access | String | The access level for the shared link. | 
| Box.Item.shared_link.effective_access | String | The effective access level for the shared link.  | 
| Box.Item.shared_link.effective_permission | String | The effective permissions for this shared link. | 
| Box.Item.shared_link.unshared_at | Date | The date and time when the link will be unshared. | 
| Box.Item.shared_link.is_password_enabled | Boolean | Defines if the shared link requires a password to access the item. | 
| Box.Item.shared_link.permissions.can_download | Boolean | Defines if the shared link allows for the item to be downloaded. | 
| Box.Item.shared_link.permissions.can_preview | Boolean | Defines if the shared link allows for the item to be previewed. | 
| Box.Item.shared_link.download_count | Number | The number of times the item has been downloaded. | 
| Box.Item.shared_link.preview_count | Number | The number of times the item has been previewed. | 
| Box.Item.parent.id | Number | The ID of the parent for the item found | 
| Box.Item.parent.etag | Number | The entry tag for the parent of the item found. | 
| Box.Item.parent.type | String | The type for the parent of the item found. | 
| Box.Item.parent.sequence_id | Number | The numeric identifier that represents the most recent user event that has been applied to the parent of the item. | 
| Box.Item.parent.name | String | The name of the parent of the item. | 
| Box.Item.item_status | String | The status of the parent of the item. | 


#### Command Example
```!box-trashed-item-restore item_id="751526132294" type="file" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "Item": {
            "content_created_at": "2020-12-09T08:49:16-08:00",
            "content_modified_at": "2020-12-09T08:49:16-08:00",
            "created_at": "2020-12-09T09:16:32-08:00",
            "created_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "description": "",
            "etag": "4",
            "file_version": {
                "id": "801011020694",
                "sha1": "aa58d9692d58f5d9316d7cf1950d19a0b01bc204",
                "type": "file_version"
            },
            "id": "751526132294",
            "item_status": "active",
            "modified_at": "2020-12-09T09:16:32-08:00",
            "modified_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "name": "list.json",
            "owned_by": {
                "id": "14342567114",
                "login": "ashamah@paloaltonetworks.com",
                "name": "Andrew Shamah",
                "type": "user"
            },
            "parent": {
                "etag": null,
                "id": "0",
                "name": "All Files",
                "sequence_id": null,
                "type": "folder"
            },
            "path_collection": {
                "entries": [
                    {
                        "etag": null,
                        "id": "0",
                        "name": "All Files",
                        "sequence_id": null,
                        "type": "folder"
                    }
                ],
                "total_count": 1
            },
            "purged_at": null,
            "sequence_id": "4",
            "sha1": "aa58d9692d58f5d9316d7cf1950d19a0b01bc204",
            "shared_link": null,
            "size": 1135,
            "trashed_at": null,
            "type": "file"
        }
    }
}
```

#### Human Readable Output

>Item with the ID 751526132294 was restored.

### box-trashed-item-delete-permanently
***
Permanently deletes a file or folder that is in the trash. This action cannot be undone.


#### Base Command

`box-trashed-item-delete-permanently`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The unique identifier that represents the file or folder. | Required | 
| type | The type of the item to delete. Possible values are: file, folder. | Required | 
| as_user | The user which is performing the action. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### box-get-current-user
***
Retrieves information about the user who is currently authenticated.


#### Base Command

`box-get-current-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| as_user | The ID of the user making the request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.User.id | Number | The unique identifier for this user. | 
| Box.User.type | String | Value is always user. | 
| Box.User.name | String | The display name of this user. | 
| Box.User.login | String | The primary email address of this user. | 
| Box.User.created_at | Date | When the user object was created. | 
| Box.User.modified_at | Date | When the user object was last modified. | 
| Box.User.language | String | The language of the user, formatted in modified version of the ISO 639-1 format. | 
| Box.User.timezone | String | The users timezone. | 
| Box.User.space_amount | Number | The users total available space amount in bytes. | 
| Box.User.space_used | Number | The amount of space in use by the user. | 
| Box.User.max_upload_size | Number | The maximum individual file size in bytes the user can have. | 
| Box.User.status | String | The users account status. | 
| Box.User.job_title | String | The users job title. | 
| Box.User.phone | Number | The users phone number. | 
| Box.User.address | String | The users address. | 
| Box.User.avatar_url | String | URL of the users avatar image | 
| Box.User.notification_email.email | String | The email address to send the notifications to. | 
| Box.User.notification_email.is_confirmed | Boolean | Specifies if this email address has been confirmed. | 


#### Command Example
```!box-get-current-user as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "User": {
            "address": "",
            "avatar_url": "https://app.box.com/api/avatar/large/14342567114",
            "created_at": "2020-11-11T04:34:53-08:00",
            "id": "14342567114",
            "job_title": "",
            "language": "en",
            "login": "ashamah@paloaltonetworks.com",
            "max_upload_size": 2147483648,
            "modified_at": "2020-12-14T05:02:46-08:00",
            "name": "Andrew Shamah",
            "notification_email": [],
            "phone": "0587059866",
            "space_amount": 10737418240,
            "space_used": 193450921,
            "status": "active",
            "timezone": "America/Los_Angeles",
            "type": "user"
        }
    }
}
```

#### Human Readable Output

>### The current user is ashamah@paloaltonetworks.com.
>|Avatar Url|Created At|Id|Language|Login|Max Upload Size|Modified At|Name|Phone|Space Amount|Space Used|Status|Timezone|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| https://app.box.com/api/avatar/large/14342567114 | 2020-11-11T04:34:53-08:00 | 14342567114 | en | ashamah@paloaltonetworks.com | 2147483648 | 2020-12-14T05:02:46-08:00 | Andrew Shamah | 0587059866 | 10737418240 | 193450921 | active | America/Los_Angeles | user |


### box-update-user
***
Updates a managed user in an enterprise. This endpoint is only available to users and applications with the right admin permissions.


#### Base Command

`box-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role | The user’s enterprise role. Possible values are: coadmin, user. | Optional | 
| address | The user’s address. | Optional | 
| job_title | The user’s job title. | Optional | 
| language | The language of the user, formatted in modified version of the ISO 639-1 format. | Optional | 
| login | The email address the user uses to log in. | Optional | 
| name | The name of the user. | Optional | 
| phone | The user’s phone number. | Optional | 
| space_amount | The user’s total available space in bytes. Set this to -1 to indicate unlimited storage. | Optional | 
| status | The user's account status. Possible values are: active, inactive, cannot_delete_edit, cannot_delete_edit_upload. | Optional | 
| timezone | The user's timezone. | Optional | 
| is_sync_enabled | Whether the user can use Box Sync. Possible values are: true, false. | Optional | 
| is_exempt_from_device_limits | Whether to exempt the user from enterprise device limits. Possible values are: true, false. | Optional | 
| is_external_collab_restricted | Whether the user is allowed to collaborate with users outside their enterprise. Possible values are: true, false. | Optional | 
| is_exempt_from_login_verification | Whether the user must use two-factor authentication. Possible values are: true, false. | Optional | 
| can_see_managed_users | Whether the user can see other enterprise users in their contact list. Possible values are: true, false. | Optional | 
| tracking_codes | Tracking codes allow an admin to generate reports from the admin console and assign an attribute to a specific group of users. The expected format is `key=FirstKey,value=FirstValue`. Multiple key value pairs may be used when using the `;` seperator. | Optional | 
| user_id | The ID of the user. | Required | 
| as_user | The ID of the user who is making the request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.User.id | Number | The unique identifier for this user. | 
| Box.User.type | String | Value is always user. | 
| Box.User.name | String | The display name of this user. | 
| Box.User.login | String | The primary email address of this user. | 
| Box.User.created_at | Date | When the user object was created. | 
| Box.User.modified_at | Date | When the user object was last modified. | 
| Box.User.language | String | The language of the user, formatted in modified version of the ISO 639-1 format. | 
| Box.User.timezone | String | The users timezone. | 
| Box.User.space_amount | Number | The users total available space amount in bytes. | 
| Box.User.space_used | Number | The amount of space in use by the user. | 
| Box.User.max_upload_size | Number | The maximum individual file size in bytes the user can have. | 
| Box.User.status | String | The users account status. | 
| Box.User.job_title | String | The users job title. | 
| Box.User.phone | Number | The users phone number. | 
| Box.User.address | String | The users address. | 
| Box.User.avatar_url | String | URL of the users avatar image | 
| Box.User.notification_email.email | String | The email address to send the notifications to. | 
| Box.User.notification_email.is_confirmed | Boolean | Specifies if this email address has been confirmed. | 


#### Command Example
```!box-update-user phone="4808675309" is_sync_enabled="true" is_exempt_from_device_limits="true" is_external_collab_restricted="false" is_exempt_from_login_verification="false" can_see_managed_users="true" user_id="14342567114" as_user="14342567114"```

#### Context Example
```json
{
    "Box": {
        "User": {
            "address": "",
            "avatar_url": "https://app.box.com/api/avatar/large/14342567114",
            "created_at": "2020-11-11T04:34:53-08:00",
            "id": "14342567114",
            "job_title": "",
            "language": "en",
            "login": "ashamah@paloaltonetworks.com",
            "max_upload_size": 2147483648,
            "modified_at": "2020-12-14T05:04:00-08:00",
            "name": "Andrew Shamah",
            "notification_email": [],
            "phone": "4808675309",
            "space_amount": 10737418240,
            "space_used": 193452056,
            "status": "active",
            "timezone": "America/Los_Angeles",
            "type": "user"
        }
    }
}
```

#### Human Readable Output

>### The user ashamah@paloaltonetworks.com has been updated.
>|Avatar Url|Created At|Id|Language|Login|Max Upload Size|Modified At|Name|Phone|Space Amount|Space Used|Status|Timezone|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| https://app.box.com/api/avatar/large/14342567114 | 2020-11-11T04:34:53-08:00 | 14342567114 | en | ashamah@paloaltonetworks.com | 2147483648 | 2020-12-14T05:04:00-08:00 | Andrew Shamah | 4808675309 | 10737418240 | 193452056 | active | America/Los_Angeles | user |


### box-create-user
***
Creates a new managed user in an enterprise. This endpoint is only available to users and applications with the right admin permissions.


#### Base Command

`box-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| as_user | The user who is making the request. | Optional | 
| login | The email address the user uses to log in. | Optional | 
| name | The name of the user. | Required | 
| role | The user’s enterprise role. Possible values are: coadmin, user. | Optional | 
| language | The language of the user, formatted in modified version of the ISO 639-1 format. | Optional | 
| is_sync_enabled | Whether the user can use Box Sync. Possible values are: true, false. | Optional | 
| job_title | The user’s job title. | Optional | 
| phone | The user’s phone number. | Optional | 
| address | The user’s address. | Optional | 
| space_amount | The user’s total available space in bytes. Set this to -1 to indicate unlimited storage. | Optional | 
| tracking_codes | Tracking codes allow an admin to generate reports from the admin console and assign an attribute to a specific group of users. The expected format is `key=FirstKey,value=FirstValue`. Multiple key value pairs may be used when using the `;` seperator. | Optional | 
| can_see_managed_users | Whether the user can see other enterprise users in their contact list. Possible values are: true, false. | Optional | 
| timezone | The user's timezone. | Optional | 
| is_exempt_from_device_limits | Whether to exempt the user from enterprise device limits. Possible values are: true, false. | Optional | 
| is_exempt_from_login_verification | Whether the user must use two-factor authentication. Possible values are: true, false. | Optional | 
| is_external_collab_restricted | Whether the user is allowed to collaborate with users outside their enterprise. Possible values are: true, false. | Optional | 
| is_platform_access_only | Specifies that the user is an app user. Possible values are: true, false. | Optional | 
| status | The user's account status. Possible values are: active, inactive, cannot_delete_edit, cannot_delete_edit_upload. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Box.User.id | Number | The unique identifier for this user. | 
| Box.User.type | String | Value is always user. | 
| Box.User.name | String | The display name of this user. | 
| Box.User.login | String | The primary email address of this user. | 
| Box.User.created_at | Date | When the user object was created. | 
| Box.User.modified_at | Date | When the user object was last modified. | 
| Box.User.language | String | The language of the user, formatted in modified version of the ISO 639-1 format. | 
| Box.User.timezone | String | The users timezone. | 
| Box.User.space_amount | Number | The users total available space amount in bytes. | 
| Box.User.space_used | Number | The amount of space in use by the user. | 
| Box.User.max_upload_size | Number | The maximum individual file size in bytes the user can have. | 
| Box.User.status | String | The users account status. | 
| Box.User.job_title | String | The users job title. | 
| Box.User.phone | Number | The users phone number. | 
| Box.User.address | String | The users address. | 
| Box.User.avatar_url | String | URL of the users avatar image | 
| Box.User.notification_email.email | String | The email address to send the notifications to. | 
| Box.User.notification_email.is_confirmed | Boolean | Specifies if this email address has been confirmed. | 


#### Command Example
```!box-create-user name="some_name_test" is_sync_enabled="false" phone="000000000" can_see_managed_users="false" is_exempt_from_device_limits="true" is_exempt_from_login_verification="false" is_external_collab_restricted="false" is_platform_access_only="true"```

#### Context Example
```json
{
    "Box": {
        "User": {
            "address": "",
            "avatar_url": "https://app.box.com/api/avatar/large/14649827308",
            "created_at": "2020-12-14T05:02:37-08:00",
            "id": "14649827308",
            "job_title": "",
            "language": "en",
            "login": "AppUser_1403892_z21JOrtxHS@boxdevedition.com",
            "max_upload_size": 2147483648,
            "modified_at": "2020-12-14T05:02:37-08:00",
            "name": "some_name_test",
            "notification_email": [],
            "phone": "000000000",
            "space_amount": 10737418240,
            "space_used": 0,
            "status": "active",
            "timezone": "America/Los_Angeles",
            "type": "user"
        }
    }
}
```

#### Human Readable Output

>### The user AppUser_1403892_z21JOrtxHS@boxdevedition.com has been created.
>|Avatar Url|Created At|Id|Language|Login|Max Upload Size|Modified At|Name|Phone|Space Amount|Space Used|Status|Timezone|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| https://app.box.com/api/avatar/large/14649827308 | 2020-12-14T05:02:37-08:00 | 14649827308 | en | AppUser_1403892_z21JOrtxHS@boxdevedition.com | 2147483648 | 2020-12-14T05:02:37-08:00 | some_name_test | 000000000 | 10737418240 | 0 | active | America/Los_Angeles | user |


### box-delete-user
***
Deletes a user. By default this will fail if the user still owns any content. Move their owned content first before proceeding, or use the force field to delete the user and their files.


#### Base Command

`box-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user. | Required | 
| as_user | The user ID of the account making the request. | Optional | 
| force | Whether the user should be deleted even if this user still own files. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!box-delete-user user_id="14639008448"```

#### Context Example
```json
{}
```

#### Human Readable Output

>The user 14639008448 was successfully deleted.
