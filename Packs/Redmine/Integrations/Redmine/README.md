A project management and issue tracking system that provides a web-based platform for managing projects, tracking tasks, and handling various types of project-related activities. 
This integration was integrated and tested with version xx of Redmine.

## Configure Redmine on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Redmine.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. <https://1.1.1.1>) | True |
    | Trust any certificate (not secure) | False |
    | API Key | True |
    | Project id | False |
4. Getting your API key:
    - Use your **server URL** to enter to your Redmine instance.
    - Authenticate with your username and password.
    - Navigate to **My Account** (at the top right corner).
    - Click on API **Access key** > **Show** - This is your API key
5. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### redmine-issue-create

***

- Create a new issue
- When attaching a file to an issue, include the entry ID in the request as file_entry_id=the ID you created
- To create a custom field, navigate to the server URL with administrative privileges, click on 'Administration' (located at the top left), select 'Custom fields,' then proceed to create a new custom field. Once created, you can add values as needed
- To create a category/version, navigate to the server URL -> Click on the Settings (top bar) -> Versions tab and Issue categories tab


#### Base Command

`redmine-issue-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Enter the project ID for this issue (If given, by default- project_id from authentication, this field override it). | Optional | 
| tracker_id | Enter the tracker ID for this issue. Possible values are: Bug, Feature, Support. | Required | 
| status_id | Enter the status ID for this issue. Possible values are: New, In progress, Resolved, Feedback, Closed, Rejected. | Required | 
| priority_id | Enter the priority ID for this issue. Possible values are: Low, Normal, High, Urgent, Immediate. | Required | 
| subject | Enter the subject for this issue. | Required | 
| description | Enter a description for this issue. | Optional | 
| category_id | Enter the category ID for this issue. | Optional | 
| fixed_version_id | Enter the target version ID for this issue. | Optional | 
| assigned_to_id | Enter the ID of the user to assign the issue to. | Optional | 
| parent_issue_id | Enter the ID of the parent issue. | Optional | 
| custom_fields | Insert the custom field to update, THE FORMAT is costumFieldID:Value,costumFieldID:Value etc... | Optional | 
| watcher_user_ids | Add an array with watcher user IDs for this issue -&gt; 1,2,3. | Optional | 
| is_private | Is the issue private? (True/False). | Optional | 
| estimated_hours | Enter the number of hours estimated for this issue. | Optional | 
| file_entry_id | Enter the entry ID of the file to upload. | Optional | 
| file_name | Enter the name of the file to attach. Make sure the file name ends with .jpg/png/txt. | Optional | 
| file_description | Enter the description of the file you attached. | Optional | 
| file_content_type | Enter the file content type of the file you attached. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Issue.id | str | The ID of the new issue. | 
| Redmine.Issue.priority.id | str | The ID of the priority of the issue. | 
| Redmine.Issue.tracker.id | str | The ID of the tracker of the issue. | 
| Redmine.Issue.project.id | str | The ID of the project of the issue. | 
| Redmine.Issue.status.id | str | The ID of the status of the issue. | 
| Redmine.Issue.subject | str | The subject of the issue. | 

### redmine-issue-list

***
Display a list of issues

#### Base Command

`redmine-issue-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_number | Enter the page number. | Optional | 
| page_size | Enter the page size (default is 50). | Optional | 
| limit | Specify the number of issues to display in the response (default is 25, maximum is 100). | Optional | 
| sort | - Specify a field to sort according to. Append ":desc" to invert the order.<br/>- Possible values:<br/>1. tracker.<br/>2. status.<br/>3. priority.<br/>4. project.<br/>5. subproject.<br/>6. assigned_to.<br/>- For example: sort=tracker:desc.<br/>. | Optional | 
| include | - Specify an array of extra fields to fetch.<br/>- Possible values:<br/>    1. attachments.<br/>    2. relations.<br/>. | Optional | 
| issue_id | Specify an array of issue IDs to display -&gt; 1,2,3. | Optional | 
| project_id | Specify a project ID to display issues of this project. | Optional | 
| subproject_id | Specify a subproject ID to display issues of this subproject (use "project_id=someID" and "subproject_id=!*" to exclude subprojects). | Optional | 
| tracker_id | Specify a tracker ID to display issues of this tracker ID. Possible values are: Bug, Feature, Support. | Optional | 
| status_id | Specify a status ID to display issues of this status ID (* means all). Possible values are: open, closed, *. | Optional | 
| assigned_to_id | Specify an assigned-to ID to display issues assigned to this user ID. | Optional | 
| parent_id | Specify a parent ID to display issues that are under this parent ID. | Optional | 
| custom_field | - Insert the custom field to filter with, THE FORMAT is costumFieldID:Value.<br/>- To filter according to the desired custom field, ensure that it is marked as 'used as a filter' and 'searchable' in your Redmine server settings.  <br/>- You can only filter one custom field at a time. <br/>- Make sure the custom field id you entered is valid, or the request won't fail but will not be filtered correctly   <br/>. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Redmine.Issue | dict | Display a list of issues | 
| Redmine.Issue.id | str | Display a list of issues | 

### redmine-issue-update

***
Update an existing issue When attaching a file to an issue, include the entry ID in the request as file_entry_id=the ID you created To create a custom field, navigate to the server URL with administrative privileges, click on 'Administration' (located at the top left), select 'Custom fields,' then proceed to create a new custom field. Once created, you can add values as needed

#### Base Command

`redmine-issue-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the issue to be updated. | Required | 
| project_id | The ID of the project to associate with the issue. | Optional | 
| tracker_id | The ID of the tracker type. Possible values are: Bug, Feature, Support. | Optional | 
| status_id | The ID of the status to set for the issue. Possible values are: New, In progress, Resolved, Feedback, Closed, Rejected. | Optional | 
| priority_id | The ID of the priority level for the issue. Possible values are: Low, Normal, High, Urgent, Immediate. | Optional | 
| subject | The subject of the issue. | Optional | 
| description | The description of the issue. | Optional | 
| category_id | The ID of the category to assign to the issue. | Optional | 
| fixed_version_id | The ID of the fixed version for the issue. | Optional | 
| assigned_to_id | The ID of the user to whom the issue is assigned. | Optional | 
| parent_issue_id | The ID of the parent issue, if applicable. | Optional | 
| custom_fields | Insert the custom field to update, THE FORMAT is costumFieldID:Value,costumFieldID:Value etc... | Optional | 
| watcher_user_ids | Add an array of watcher ids seperated with comma -&gt; 1,2,3. | Optional | 
| is_private | Is the issue private? (True/False). Possible values are: True, False. | Optional | 
| estimated_hours | The estimated number of hours to complete the issue. | Optional | 
| notes | Additional comments about the update. | Optional | 
| private_notes | Specifies if the notes are private (True/False). Possible values are: True, False. | Optional | 
| file_entry_id | Required if uploading a file- The entry ID of the file to upload. | Optional | 
| file_name | The name of the file to upload (should end with .jpg/.png/.txt etc...). | Optional | 
| file_description | The description of the attached file. | Optional | 
| file_content_type | The content type of the attached file (image/jpg or image/png or text/txt etc...). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| None | None | The issue was updated | 

### redmine-issue-show

***
Show an issue by id

#### Base Command

`redmine-issue-show`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Add the id of the issue you want to show. | Required | 
| include | - fields to add to the response.<br/>- Possible values:<br/>  1.children.<br/>  2.attachments.<br/>  3.relations.<br/>  4.changesets.<br/>  5.journals.<br/>  6.watchers.<br/>  7.allowed_statuses.<br/>- Separate multiple values with comma ONLY.<br/>. | Optional | 

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

### redmine-issue-delete

***
Delete an issue by its ID

#### Base Command

`redmine-issue-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | The ID of the issue you want to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| None | None | The issue was deleted | 

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| None | None | Added a watcher to an issue | 

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| None | None | Removed a watcher from an issue | 

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
| Redmine.Project | dict | Display a list of projects accessible to the user. | 

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
| Redmine.Users | dict | Display a list of users. | 
| Redmine.Users.id | str | Display a list of users ids. | 
| Redmine.Users.login | str | Display a list of users login usernames. | 
| Redmine.Users.admin | str | Display a list of users admins permission. | 
| Redmine.Users.firstname | str | Display a list of users first name. | 
| Redmine.Users.lastname | str | Display a list of users last name. | 
| Redmine.Users.mail | str | Display a list of users mails. | 
