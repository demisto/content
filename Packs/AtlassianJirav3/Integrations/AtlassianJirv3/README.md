Use the Jira integration to manage issues and create XSOAR incidents from projects. Supports mirroring.
This integration was integrated and tested with version xx of Atlassian Jira v3
## Configure Atlassian Jira v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Atlassian Jira v3.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| mirror | Ticket Mirroring | False |
| tag_internal_note | Tag for internal notes | True |
| tag_public_note | Tag for public notes | True |
| url | Jira URL, for example: https://demisto.atlassian.net/ | True |
| username | \_\_\_\_\_\_\_\_\_\_\_\_\_ Basic Authentication \_\_\_\_\_\_\_\_\_\_\_\_

Username | False |
| password | Password \(Deprecated \- Use API token\) | False |
| APItoken | API token | False |
| consumerKey | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ OAuth 1.0 \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

ConsumerKey | False |
| accessToken | AccessToken | False |
| privateKey | PrivateKey | False |
| query | Query \(in JQL\) for fetching incidents | False |
| dateOffset | Issue date to start fetching incidents from \(format is yyyy\-MM\-dd\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### jira-issue-query
***
Queries Jira issues.


#### Base Command

`jira-issue-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The JQL query string. | Required | 
| startAt | The index (integer) of the first issue to return (0-based). | Optional | 
| maxResults | The maximum number of issues to return (default is 50). The maximum allowed value is dictated by the JIRA property 'jira.search.views.default.max'. If you specify a value that is higher than this number, your search results will be truncated. | Optional | 
| headers | The headers to display in human readable format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | unknown | The ID of the ticket. | 
| Ticket.Key | unknown | The key of the ticket. | 
| Ticket.Assignee | unknown | The user assigned to the ticket. | 
| Ticket.Creator | unknown | The user who created the ticket. | 
| Ticket.Summary | unknown | The summary of the ticket. | 
| Ticket.Status | unknown | The status of the ticket. | 


#### Command Example
``` ```

#### Human Readable Output



### jira-get-issue
***
Fetches an issue from Jira.


#### Base Command

`jira-get-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue. | Required | 
| headers | Headers to display in human readable format. | Optional | 
| getAttachments | If "true", retrives the issue's attachments. | Optional | 
| expandLinks | If "true", expands the issue's links. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | unknown | The ID of the ticket. | 
| Ticket.Key | unknown | The key of ticket. | 
| Ticket.Assignee | unknown | The user assigned to the ticket. | 
| Ticket.Creator | unknown | The user who created the ticket. | 
| Ticket.Summary | unknown | The summary of the ticket. | 
| Ticket.Status | unknown | The status of the ticket. | 
| File.Size | unknown | The size of the file. | 
| File.SHA256 | unknown | The SHA256 hash of the file. | 
| File.Name | unknown | The name of the file. | 
| File.SHA1 | unknown | The SHA1 hash of the file. | 


#### Command Example
``` ```

#### Human Readable Output



### jira-create-issue
***
Creates a new issue in Jira.


#### Base Command

`jira-create-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueJson | The issue object (in JSON format). | Optional | 
| summary | The summary of the issue. | Required | 
| projectKey | The project key with which to associate the issue. | Optional | 
| issueTypeName | Select an issue type by name, for example: "Problem". | Optional | 
| issueTypeId | Select an issue type by its numeric ID. | Optional | 
| projectName | The project name with which to associate the issue. | Optional | 
| description | A description of the issue. | Optional | 
| labels | A CSV list of labels. | Optional | 
| priority | The priority name, for example: "High" or "Medium". | Optional | 
| dueDate | The due date for the issue (in the format: 2018-03-11). | Optional | 
| assignee | The name of the assignee. | Optional | 
| reporter | The ID of the reporter. | Optional | 
| parentIssueKey | The parent issue key (if you create a sub-task). | Optional | 
| parentIssueId | The parent issue ID (if you create a sub-task). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | unknown | The ID of the ticket. | 
| Ticket.Key | unknown | The key of the ticket. | 


#### Command Example
``` ```

#### Human Readable Output



### jira-issue-upload-file
***
Uploads a file attachment to an issue.


#### Base Command

`jira-issue-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue. | Required | 
| entryID | The entry ID to upload. | Optional | 
| attachmentName | The attachment name to be displayed in Jira (overrides original file name) | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### jira-issue-add-comment
***
Adds a new comment to an existing Jira issue.


#### Base Command

`jira-issue-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue. | Required | 
| comment | The comment body. | Required | 
| visibility | The roles that can view the comment, for example: "Administrators". | Optional | 
| internal | Whether to make this comment internal only. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### jira-issue-add-link
***
Creates (or updates) an issue link.


#### Base Command

`jira-issue-add-link`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| globalId | If a globalId is provided, and a remote issue link exists with that globalId, the remote issue link is updated. | Optional | 
| relationship | The object relationship to issue, for example: "causes". | Optional | 
| url | The URL link. | Required | 
| title | The title of the link. | Required | 
| summary | The summary of the link. | Optional | 
| issueId | The ID of the issue. | Required | 
| applicationType | The application type of the linked remote application. E.g "com.atlassian.confluence". | Optional | 
| applicationName | The application name of the linked remote application. E.g "My Confluence Instance". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### jira-edit-issue
***
Modifies an issue in JIRA.


#### Base Command

`jira-edit-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue to edit. | Required | 
| issueJson | The issue object (in JSON format). e.g, {"fields":{"customfield_10037": "field_value"}} | Optional | 
| summary | The summary of the issue. | Optional | 
| description | The description of the issue. | Optional | 
| labels | A CSV list of labels. | Optional | 
| priority | A priority name, for example "High" or "Medium". | Optional | 
| dueDate | The due date for the issue (in the format 2018-03-11). | Optional | 
| assignee | The name of the assignee. | Optional | 
| status | The name of the status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | unknown | The ID of the ticket. | 
| Ticket.Key | unknown | The key of the ticket. | 
| Ticket.Assignee | unknown | The user assigned to the ticket. | 
| Ticket.Creator | unknown | The user who created the ticket. | 
| Ticket.Summary | unknown | The summary of the ticket. | 
| Ticket.Status | unknown | The status of the ticket. | 


#### Command Example
``` ```

#### Human Readable Output



### jira-get-comments
***
Returns the comments added to a ticket.


#### Base Command

`jira-get-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue from which to get the comments. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Comment.Comment | string | The text of the comment. | 
| Ticket.Comment.Created | string | The issue creation date. | 
| Ticket.Comment.User | string | The user that created the comment. | 


#### Command Example
``` ```

#### Human Readable Output



### jira-delete-issue
***
Deletes an issue in Jira.


#### Base Command

`jira-delete-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueIdOrKey | The ID or key of the issue. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### jira-get-id-offset
***
Returns the ID offset, for example, the first issue ID.


#### Base Command

`jira-get-id-offset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.idOffSet | string | The ID offset. | 


#### Command Example
``` ```

#### Human Readable Output


