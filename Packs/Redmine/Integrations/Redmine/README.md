A project management and issue tracking system that provides a web-based platform for managing projects, tracking tasks, and handling various types of project-related activities. 
This integration was integrated and tested with version 5.1.2 of Redmine.

## Configure Redmine on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Redmine.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., <https://1.1.1.1>) | True |
    | Trust any certificate (not secure) | False |
    | API Key | True |
    | Project id | False |
4. Getting your API key:
    - Use your **server URL** to enter your Redmine instance.
    - Authenticate with your username and password.
    - Navigate to **My Account** (at the top right corner).
    - Click API **Access key** > **Show** - This is your API key
5. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### redmine-issue-create

***

- Create a new issue.
- The status of the newly created issue will be set to the default status of the Redmine instance.
- When attaching a file to an issue, include the entry ID in the request as file_entry_id=entry ID.
- To create a custom field, navigate to the server URL with administrative privileges, click **Administration** (located at the top left), select **Custom fields**, and then proceed to create a new custom field. Once created, you can add values as needed
- To create a category/version, navigate to the server URL > click **Settings** (top bar) > **Versions** tab and **Issue categories** tab.


#### Base Command

`redmine-issue-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The project ID for this issue. If not specified, the value from the instance configuration will be used. | Optional | 
| tracker_id | - A tracker ID (e.g., 1,2,3).<br/>- Get the tracker_name to tracker_id mapping by using the command redmine-tracker-id-list.<br/>- If an invalid ID was entered,  the default tracker ID set in the Redmine instance wil be used. | Required | 
| priority_id | - A priority ID (e.g., 1,2,3).<br/>- Get the priority_name to priority_id mapping by using the command redmine-priority-id-list. | Required | 
| subject | The subject for this issue. | Required | 
| description | A description for this issue. | Optional | 
| category_id | The category ID for this issue. | Optional | 
| fixed_version_id | The target version ID for this issue. | Optional | 
| assigned_to_id | The ID of the user to assign the issue to. | Optional | 
| parent_issue_id | The ID of the parent issue. | Optional | 
| custom_fields | The custom field to update.<br/>- "The format is `{\"customFieldID2\": \"value3\", \"customFieldID1\": [\"value1\",\"value2\"]}`."<br/>- Use an array if the field is of multiselect type.<br/>- Instruction for each custom field type:<br/>  - Boolean: use "0" for False and "1" for True.<br/>  - Date: the format is "yyyy-mm-dd".<br/>  - Float: A number with two digits after the decimal point.<br/>  - Integer: A number.<br/>  - Key/Value list: Use the Key (ID) of the value.<br/>  - User: Use the user ID.<br/> - Version- use the version ID.| Optional | 
| watcher_user_ids | An array with watcher user IDs for this issue -&gt; 1,2,3. | Optional | 
| is_private | Is the issue private?. Possible values are: True, False. | Optional | 
| estimated_hours | The number of hours estimated for this issue. | Optional | 
| file_entry_id | The entry ID of the file to upload. | Optional | 
| file_name | The name of the file to attach. Make sure the file name ends with .jpg/png/txt. | Optional | 
| file_description | The description of the file you attached. | Optional | 
| file_content_type | The file content type of the file you attached. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Issue.id | srt | The ID of the new issue. | 
| Redmine.Issue.priority.id | str | The ID of the priority of the issue. | 
| Redmine.Issue.tracker.id | str | The ID of the tracker of the issue. | 
| Redmine.Issue.project.id | str | The ID of the project of the issue. | 
| Redmine.Issue.status.id | str | The ID of the status of the issue. | 
| Redmine.Issue.subject | str | The subject of the issue. | 

#### Command example
```!redmine-issue-create priority_id=High subject=helloExample tracker_id=1 project_id=1 watcher_user_ids=5,6 custom_fields=1:helloCustom priority_id=1```
#### Context Example
```json
{
    "Redmine": {
        "Issue": {
            "author": {
                "id": 6,
                "name": "Integration Test"
            },
            "closed_on": null,
            "created_on": "2024-04-07T11:59:34Z",
            "custom_fields": [
                {
                    "id": 1,
                    "name": "Team_of_workers",
                    "value": "helloCustom"
                }
            ],
            "description": null,
            "done_ratio": 0,
            "due_date": null,
            "estimated_hours": null,
            "id": "167",
            "is_private": false,
            "priority": {
                "id": 1,
                "name": "Low"
            },
            "project": {
                "id": 1,
                "name": "Cortex XSOAR"
            },
            "start_date": "2024-04-07",
            "status": {
                "id": 1,
                "is_closed": false,
                "name": "New"
            },
            "subject": "helloExample",
            "total_estimated_hours": null,
            "tracker": {
                "id": 1,
                "name": "Bug"
            },
            "updated_on": "2024-04-07T11:59:34Z"
        }
    }
}
```

#### Human Readable Output

>### The issue you created:
>|Id|Project|Tracker|Status|Priority|Author|Created On|Subject|Start Date|Custom Fields|
>|---|---|---|---|---|---|---|---|---|---|
>| 167 | Cortex XSOAR | Bug | New | Low | Integration Test | 2024-04-07T11:59:34Z | helloExample | 2024-04-07 | **-**	***name***: Team_of_workers<br/>	***value***: helloCustom |


### redmine-issue-list

***
Display a list of issues

#### Base Command

`redmine-issue-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_number | The page number. | Optional | 
| page_size | The page size. Default value is 50, if limit is not specified. | Optional | 
| limit | The number of issues to display in the response (maximum is 100). If page_number or page_size are specified, this field will be ignored. Default is 25. | Optional | 
| sort | A field by which to sort the results. Append ":desc" to invert the order.<br/>- Possible values:<br/>1. tracker.<br/>2. status.<br/>3. priority.<br/>4. project.<br/>5. subproject.<br/>6. assigned_to.<br/>- For example: sort=tracker:desc.<br/> | Optional | 
| include | An array of extra fields to fetch.<br/>- Possible values:<br/>    1. attachments.<br/>    2. relations.<br/> | Optional | 
| issue_id | An array of issue IDs to display -&gt; 1,2,3. | Optional | 
| project_id | Aa project ID to display issues of this project. If not specified here or in the instance configuration, all projects will be displayed. | Optional | 
| subproject_id | A subproject ID to display issues of this subproject (use "project_id=someID" and "subproject_id=!name_of_subproject" to exclude subprojects). | Optional | 
| tracker_id | - A tracker ID (e.g., 1,2,3).<br/>- Get the tracker_name to tracker_id mapping by using the command redmine-tracker-id-list. | Optional |
| status | - A status ID (e.g., 1,2,3) or use predefined values.  <br/>- Possible values: Open/Closed/All from the predefined values or use any of your custom status ids (e.g., 1).| Optional | 
| assigned_to_id | An assigned-to ID to display issues assigned to this user ID. | Optional | 
| parent_id | A parent ID to display issues that are under this parent ID. | Optional | 
| custom_field | - The custom field to filter by. The format is costumFieldID:Value.<br/>- To filter according to the desired custom field, ensure that it is marked as 'used as a filter' and 'searchable' in your Redmine server settings.  <br/>- You can only filter one custom field at a time. <br/>- Make sure the custom field ID which was entered is valid, or the request won't fail but will not be filtered correctly.   <br/>| Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Issue | dict | A list of issues. | 
| Redmine.Issue.id | str | A list of issues. | 

#### Command example
```!redmine-issue-list limit=2```
#### Context Example
```json
{
    "Redmine": {
        "Issue": [
            {
                "author": {
                    "id": 6,
                    "name": "Integration Test"
                },
                "closed_on": null,
                "created_on": "2024-03-11T09:16:47Z",
                "custom_fields": [
                    {
                        "id": 1,
                        "name": "Team_of_workers",
                        "value": "helloCustom"
                    }
                ],
                "description": null,
                "done_ratio": 0,
                "due_date": null,
                "estimated_hours": null,
                "id": "130",
                "is_private": false,
                "priority": {
                    "id": 3,
                    "name": "High"
                },
                "project": {
                    "id": 1,
                    "name": "Cortex XSOAR"
                },
                "spent_hours": 0,
                "start_date": "2024-03-11",
                "status": {
                    "id": 1,
                    "is_closed": false,
                    "name": "New"
                },
                "subject": "subjectChanged",
                "total_estimated_hours": null,
                "total_spent_hours": 0,
                "tracker": {
                    "id": 1,
                    "name": "Bug"
                },
                "updated_on": "2024-03-11T09:16:54Z"
            },
            {
                "author": {
                    "id": 6,
                    "name": "Integration Test"
                },
                "closed_on": null,
                "created_on": "2024-03-11T09:08:09Z",
                "custom_fields": [
                    {
                        "id": 1,
                        "name": "Team_of_workers",
                        "value": "helloCustom"
                    }
                ],
                "description": null,
                "done_ratio": 0,
                "due_date": null,
                "estimated_hours": null,
                "id": "129",
                "is_private": false,
                "priority": {
                    "id": 3,
                    "name": "High"
                },
                "project": {
                    "id": 1,
                    "name": "Cortex XSOAR"
                },
                "spent_hours": 0,
                "start_date": "2024-03-11",
                "status": {
                    "id": 1,
                    "is_closed": false,
                    "name": "New"
                },
                "subject": "helloExample",
                "total_estimated_hours": null,
                "total_spent_hours": 0,
                "tracker": {
                    "id": 1,
                    "name": "Bug"
                },
                "updated_on": "2024-03-11T09:08:09Z"
            }
        ]
    }
}
```

#### Human Readable Output

>#### Showing 2 results from page 1:
>### Issues Results:
>|ID|Tracker|Status| Priority|Author|Subject|Start Date|done_ratio|Is Private|Custom Fields|Created On|updated_on|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 130 | Bug | New | High | Integration Test | subjectChanged | 2024-03-11 | 0 | false | **-**	***name***: Team_of_workers<br/>	***value***: helloCustom | 2024-03-11T09:16:47Z | 2024-03-11T09:16:54Z |
>| 129 | Bug | New | High | Integration Test | helloExample | 2024-03-11 | 0 | false | **-**	***name***: Team_of_workers<br/>	***value***: helloCustom | 2024-03-11T09:08:09Z | 2024-03-11T09:08:09Z |


### redmine-issue-update

***
Update an existing issue. When attaching a file to an issue, include the entry ID in the request as file_entry_id=entry ID. To create a custom field, navigate to the server URL with administrative privileges, click **'Administration** (located at the top left), select **Custom fields**, and proceed to create a new custom field. Once created, you can add values as needed.

#### Base Command

`redmine-issue-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the issue to be updated. | Required | 
| project_id | The ID of the project to associate with the issue. If not specified, the value from integration configuration will be taken if specified. | Optional | 
| tracker_id | - A tracker ID (e.g., 1,2,3).<br/>- Get the tracker_name to tracker_id mapping by using the command redmine-tracker-id-list.<br/>- If an invalid ID was entered, tracker_id won't be changed and won't raise an error. | Optional | 
| priority_id | - A priority ID (e.g., 1,2,3).<br/>- Get the priority_name to priority_id mapping by using the command redmine-priority-id-list. | Optional | 
| status | - A status ID (e.g., 1,2,3).<br/> - Get the status_name to status_id mapping by using the command redmine-status-id-list.<br/>  - If an invalid ID was entered, status_id won't be changed and won't raise an error. | Optional | 
| subject | The subject of the issue. | Optional | 
| description | The description of the issue. | Optional | 
| category_id | The ID of the category to assign to the issue. | Optional | 
| fixed_version_id | The ID of the fixed version for the issue. | Optional | 
| assigned_to_id | The ID of the user to whom the issue is assigned. | Optional | 
| parent_issue_id | The ID of the parent issue, if applicable. | Optional | 
| custom_fields | The custom field to update.<br/>- "The format is `{\"customFieldID2\": \"value3\", \"customFieldID1\": [\"value1\",\"value2\"]}`."<br/>- Use an array if the field is of multiselect type.<br/>- Instruction for each custom field type:<br/>  - Boolean: use "0" for False and "1" for True.<br/>  - Date: the format is "yyyy-mm-dd".<br/>  - Float: A number with two digits after the decimal point.<br/>  - Integer: A number.<br/>  - Key/Value list: Use the Key (ID) of the value.<br/>  - User: Use the user ID.<br/> - Version- use the version ID.| Optional | 
| watcher_user_ids | A comma-separated list of watcher IDs. -&gt; 1,2,3. | Optional | 
| is_private | Is the issue private?. Possible values are: True, False. | Optional | 
| estimated_hours | The estimated number of hours to complete the issue. | Optional | 
| notes | Additional comments about the update. | Optional | 
| private_notes | Specifies if the notes are private. Possible values are: True, False. | Optional | 
| file_entry_id | The entry ID of the file to upload. Required if uploading a file.  | Optional | 
| file_name | The name of the file to upload (should end with .jpg/.png/.txt, etc.). | Optional | 
| file_description | The description of the attached file. | Optional | 
| file_content_type | The content type of the attached file (image/jpg or image/png or text/txt, etc.). | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!redmine-issue-update issue_id=130 subject=subjectChanged```
#### Human Readable Output

>Issue with id 130 was successfully updated.

### redmine-issue-get

***
Show an issue by id

#### Base Command

`redmine-issue-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the wanted issue. | Required | 
| include | - Fields to add to the response.<br/>- Possible values:<br/>  1.children.<br/>  2.attachments.<br/>  3.relations.<br/>  4.changesets.<br/>  5.journals.<br/>  6.watchers.<br/>  7.allowed_statuses.<br/>- Separate multiple values with comma ONLY.<br/> | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Issue.id | str | The ID of the found issue. | 
| Redmine.Issue.priority.id | str | The ID of the priority of the issue. | 
| Redmine.Issue.tracker.id | str | The ID of the tracker of the issue. | 
| Redmine.Issue.project.id | str | The ID of the project of the issue. | 
| Redmine.Issue.status.id | str | The ID of the status of the issue. | 
| Redmine.Issue.subject | str | The subject of the issue. | 
| Redmine.Issue.watchers.id | str | The watchers of the issue. | 

#### Command example
```!redmine-issue-get issue_id=130 include=watchers```
#### Context Example
```json
{
    "Redmine": {
        "Issue": {
            "author": {
                "id": 6,
                "name": "Integration Test"
            },
            "closed_on": null,
            "created_on": "2024-03-11T09:16:47Z",
            "custom_fields": [
                {
                    "id": 1,
                    "name": "Team_of_workers",
                    "value": "helloCustom"
                }
            ],
            "description": null,
            "done_ratio": 0,
            "due_date": null,
            "estimated_hours": null,
            "id": "130",
            "is_private": false,
            "priority": {
                "id": 3,
                "name": "High"
            },
            "project": {
                "id": 1,
                "name": "Cortex XSOAR"
            },
            "spent_hours": 0,
            "start_date": "2024-03-11",
            "status": {
                "id": 1,
                "is_closed": false,
                "name": "New"
            },
            "subject": "subjectChanged",
            "total_estimated_hours": null,
            "total_spent_hours": 0,
            "tracker": {
                "id": 1,
                "name": "Bug"
            },
            "updated_on": "2024-03-11T09:16:54Z",
            "watchers": [
                {
                    "id": 5,
                    "name": "admin tests"
                },
                {
                    "id": 6,
                    "name": "Integration Test"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Issues List:
>|Id|Project|Tracker|Status|Priority|Author|Subject|StartDate|DoneRatio|IsPrivate|CustomFields|CreatedOn|Watchers|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 130 | Cortex XSOAR | Bug | New | High | Integration Test | subjectChanged | 2024-03-11 | 0 | false | **-**	***name***: Team_of_workers<br/>	***value***: helloCustom | 2024-03-11T09:16:47Z | **-**	***name***: admin tests<br/>**-**	***name***: Integration Test |


### redmine-issue-delete

***
Delete an issue by its ID

#### Base Command

`redmine-issue-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the about to be deleted issue. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!redmine-issue-delete issue_id=130```
#### Human Readable Output

>Issue with id 130 was deleted successfully.

### redmine-issue-watcher-add

***
Add a watcher to the specified issue

#### Base Command

`redmine-issue-watcher-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the issue to which you want to add a watcher. | Required | 
| watcher_id | The ID of the watcher you want to add to the issue. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!redmine-issue-watcher-add issue_id=130 watcher_id=1```
#### Human Readable Output

>Watcher with id 1 was added successfully to issue with id 130.

### redmine-issue-watcher-remove

***
Remove a watcher of an issue

#### Base Command

`redmine-issue-watcher-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the issue from which you want to remove the watcher. | Required | 
| watcher_id | The ID of the watcher you want to remove from the issue. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!redmine-issue-watcher-remove issue_id=130 watcher_id=1```
#### Human Readable Output

>Watcher with id 1 was removed successfully from issue with id 130.

### redmine-project-list

***
Retrieve a list of all projects, including both public and private ones that the user has access to.

#### Base Command

`redmine-project-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include | - Specify which additional fields to include in the response.<br/>- Choose from the following options:<br/>  1. trackers.<br/>  2. issue_categories<br/>  3. enabled_modules <br/>  4. time_entry_activities<br/>  5. issue_custom_fields<br/>- Separate multiple values with comma ONLY.<br/> | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Project | Array | Display a list of projects accessible to the user. | 

#### Command example
```!redmine-project-list ```
#### Context Example
```json
{
    "Redmine": {
        "Project": {
            "created_on": "2024-02-29T10:34:23Z",
            "custom_fields": [
                {
                    "id": 3,
                    "name": "second_custom_field",
                    "value": null
                }
            ],
            "description": "",
            "homepage": "",
            "id": "1",
            "identifier": "cortex-xsoar",
            "inherit_members": false,
            "is_public": "True",
            "name": "Cortex XSOAR",
            "status": "1",
            "updated_on": "2024-02-29T10:34:23Z"
        }
    }
}
```

#### Human Readable Output

>### Projects List:
>|Id|Name|Identifier|Status|IsPublic|CreatedOn|UpdatedOn|
>|---|---|---|---|---|---|---|
>| 1 | Cortex XSOAR | cortex-xsoar | 1 | True | 2024-02-29T10:34:23Z | 2024-02-29T10:34:23Z |


### redmine-custom-field-list

***
Retrieve a list of all custom fields.

#### Base Command

`redmine-custom-field-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.CustomField | dict | Retrieve details of all custom fields. | 
| Redmine.CustomField.id | str | Display ids of custom fields. | 
| Redmine.CustomField.name | str | Display names of custom fields. | 
| Redmine.CustomField.customized_type | str | Display customized_type of custom fields. | 

#### Command example
```!redmine-custom-field-list```
#### Context Example
```json
{
    "Redmine": {
        "CustomField": [
            {
                "customized_type": "issue",
                "default_value": "",
                "description": "specify the team of workers under this issue",
                "field_format": "string",
                "id": "1",
                "is_filter": "True",
                "is_required": "False",
                "max_length": null,
                "min_length": null,
                "multiple": false,
                "name": "Team_of_workers",
                "regexp": "",
                "roles": [],
                "searchable": true,
                "trackers": [
                    {
                        "id": 1,
                        "name": "Bug"
                    },
                    {
                        "id": 2,
                        "name": "Feature"
                    },
                    {
                        "id": 3,
                        "name": "Support"
                    }
                ],
                "visible": true
            },
            {
                "customized_type": "project",
                "default_value": "",
                "description": "",
                "field_format": "string",
                "id": "3",
                "is_filter": "False",
                "is_required": "False",
                "max_length": null,
                "min_length": null,
                "multiple": false,
                "name": "second_custom_field",
                "regexp": "",
                "searchable": false,
                "visible": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Custom Fields List:
>|Id|Name|CustomizedType|FieldFormat|IsRequired|IsFilter|Searchable|Trackers|
>|---|---|---|---|---|---|---|---|
>| 1 | Team_of_workers | issue | string | False | True |  | **-**	***id***: 1<br/>	***name***: Bug<br/>**-**	***id***: 2<br/>	***name***: Feature<br/>**-**	***id***: 3<br/>	***name***: Support |
>| 3 | second_custom_field | project | string | False | False |  |  |


### redmine-user-id-list

***
- Retrieve a list of users with optional filtering options.
- This command requires admin privileges in your Redmine account.


#### Base Command

`redmine-user-id-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Specify the status of users to retrieve. Possible values are: Active, Registered, Locked. | Optional | 
| name | Search for users matching a specific name (searches in first name, last name, and email). | Optional | 
| group_id | Specify the group ID to filter users by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Users | dict |A list of users. | 
| Redmine.Users.id | str | A list of users IDs. | 
| Redmine.Users.login | str | A list of users login usernames. | 
| Redmine.Users.admin | str | A list of users admins permission. | 
| Redmine.Users.firstname | str | A list of users first name. | 
| Redmine.Users.lastname | str | A list of users last name. | 
| Redmine.Users.mail | str | A list of users mails. | 

#### Command example
```!redmine-user-id-list```
#### Context Example
```json
{
    "Redmine": {
        "Users": [
            {
                "admin": "True",
                "created_on": "2024-02-28T19:47:56Z",
                "firstname": "admin",
                "id": "5",
                "last_login_on": "2024-02-29T10:25:08Z",
                "lastname": "tests",
                "login": "admin",
                "mail": "admin@redmine-test.local",
                "passwd_changed_on": "2024-02-28T19:49:17Z",
                "twofa_scheme": null,
                "updated_on": "2024-02-28T19:50:49Z"
            },
            {
                "admin": "True",
                "created_on": "2024-02-29T10:27:31Z",
                "firstname": "Integration",
                "id": "6",
                "last_login_on": "2024-02-29T10:55:25Z",
                "lastname": "Test",
                "login": "demiadmin",
                "mail": "demiadmin@redmine-test.local",
                "passwd_changed_on": "2024-02-29T10:27:31Z",
                "twofa_scheme": null,
                "updated_on": "2024-02-29T10:27:31Z"
            },
            {
                "admin": "True",
                "created_on": "2024-02-28T18:34:10Z",
                "firstname": "UserName",
                "id": "1",
                "last_login_on": "2024-02-29T09:50:10Z",
                "lastname": "LastName",
                "login": "user",
                "mail": "user@example.com",
                "passwd_changed_on": null,
                "twofa_scheme": null,
                "updated_on": "2024-02-28T18:34:10Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users List:
>|ID|Login|Admin|First Name|Last Name|Email|Created On|Last Login On|
>|---|---|---|---|---|---|---|---|
>| 5 | admin | True | admin | tests | admin@redmine-test.local | 2024-02-28T19:47:56Z | 2024-02-29T10:25:08Z |
>| 6 | demiadmin | True | Integration | Test | demiadmin@redmine-test.local | 2024-02-29T10:27:31Z | 2024-02-29T10:55:25Z |
>| 1 | user | True | UserName | LastName | user@example.com | 2024-02-28T18:34:10Z | 2024-02-29T09:50:10Z |

### redmine-priority-id-list

***
Returns a list of priorities (priority_name to priority_id).

#### Base Command

`redmine-priority-id-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.priorities.ID | str | ID of the priority field. | 
| Redmine.priorities.Name | str | Name of the priority field. | 

#### Command example
```!redmine-priority-id-list```
#### Context Example
```json
{
    "Redmine": {
        "priorities": [
            {
                "ID": 1,
                "Name": "Low"
            },
            {
                "ID": 2,
                "Name": "Normal"
            },
            {
                "ID": 3,
                "Name": "High"
            },
            {
                "ID": 4,
                "Name": "Urgent"
            },
            {
                "ID": 5,
                "Name": "Immediate"
            }
        ]
    }
}
```

#### Human Readable Output

>### priorities name to id List:
>|ID|Name|
>|---|---|
>| 1 | Low |
>| 2 | Normal |
>| 3 | High |
>| 4 | Urgent |
>| 5 | Immediate |


### redmine-status-id-list

***
Returns a list of statuses (status_name to status_id).

#### Base Command

`redmine-status-id-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.statuses.ID | str | ID of the status field. | 
| Redmine.Users.Name | str | Name of the status field. | 

#### Command example
```!redmine-status-id-list```
#### Context Example
```json
{
    "Redmine": {
        "statuses": [
            {
                "ID": 1,
                "Name": "help"
            },
            {
                "ID": 2,
                "Name": "In Progress"
            },
            {
                "ID": 3,
                "Name": "Resolved"
            },
            {
                "ID": 4,
                "Name": "Feedback"
            },
            {
                "ID": 5,
                "Name": "Closed"
            },
            {
                "ID": 6,
                "Name": "Rejected"
            }
        ]
    }
}
```

#### Human Readable Output

>### statuses name to id List:
>|ID|Name|
>|---|---|
>| 1 | help |
>| 2 | In Progress |
>| 3 | Resolved |
>| 4 | Feedback |
>| 5 | Closed |
>| 6 | Rejected |


### redmine-tracker-id-list

***
Returns a list of trackers (tracker_name to tracker_id).

#### Base Command

`redmine-tracker-id-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.trackers.ID | str | ID of the tracker field. | 
| Redmine.trackers.Name | str | Name of the tracker field. | 

#### Command example
```!redmine-tracker-id-list```
#### Context Example
```json
{
    "Redmine": {
        "trackers": [
            {
                "ID": 1,
                "Name": "Bug111"
            },
            {
                "ID": 2,
                "Name": "Feature"
            },
            {
                "ID": 3,
                "Name": "Support"
            }
        ]
    }
}
```

#### Human Readable Output

>### trackers name to id List:
>|ID|Name|
>|---|---|
>| 1 | Bug111 |
>| 2 | Feature |
>| 3 | Support |


