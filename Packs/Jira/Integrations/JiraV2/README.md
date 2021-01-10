Use the Atlassian Jira v2 integration to manage issues and create Demisto incidents from projects.

This integration was integrated and tested with version 1001.0.0-SNAPSHOT of Jira.
For more information about manage syntax, see the https://support.atlassian.com/

## Use Cases
---
1. Create, edit, delete, and query Jira issues.
2. Get or add issue’s comments.
3. Add link and upload an attachment to issue.

## Configure jira-v2 on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Jira v2.
3. __Authentiction__: As of June 2019, Basic authentication using passwords for Jira is no longer supported, please use an API Token or OAuth 1.0.
4. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Jira URL, for example: https://demisto.atlassian.net/__
    *  ______________ Basic Authentication ________________
    
        To use basic authentication, follow [this tutorial](https://confluence.atlassian.com/cloud/api-tokens-938839638.html) to get an API token. Authorizing using basic authentication requires:
    
        * __Username__
        * __Password (Deprecated)__
        * __API token__
        
    * ____________________ OAuth 1.0 __________________
           
      To use OAuth1.0 follow [this tutorial](https://developer.atlassian.com/cloud/jira/platform/jira-rest-api-oauth-authentication/) to get the Access Token. Authorizing using OAuth1.0 requires:

        * __ConsumerKey__
        * __AccessToken__
        * __PrivateKey__
    * __Query (in JQL) for fetching incidents__
    * __Issue index to start fetching incidents from__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Fetch incidents__
    * __Incident type__
    * __Use created field to fetch incidents__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
When you enable fetched incidents, Demisto fetches the first batch of Jira issues from the 10 minutes prior to when the integration was added. After the first batch of fetched issues, Demisto fetches new Jira issues as soon as they are generated in Jira. By default, 50 issues are pulled for each call. To pull older Jira issues, use the query to fetch issues option.
If mirror `Mirror incoming incidents` is enabled, any incident data changed in remote JIRA server will reflected on existing fetched incidents.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. Search Jira issues: jira-issue-query
2. Fetch an issue: jira-get-issue
3. Create an issue: jira-create-issue
4. Upload a file to an issue: jira-issue-upload-file
5. Add a comment to an issue: jira-issue-add-comment
6. Create (or update) a link to an issue: jira-issue-add-link
7. Edit an issue: jira-edit-issue
8. Get a ticket's comments: jira-get-comments
9. Delete an issue: jira-delete-issue
10. Get the ID offset: jira-get-id-offset

### 1. Search Jira issues
---
Queries Jira issues.

##### Base Command

`jira-issue-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The JQL query string. | Required | 
| startAt | The index (integer) of the first issue to return (0-based). | Optional | 
| maxResults | The maximum number of issues to return (default is 50). The maximum allowed value is dictated by the JIRA property 'jira.search.views.default.max'. If you specify a value that is higher than this number, your search results will be truncated. | Optional | 
| headers | The headers to display in human readable format. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | Unknown | The ID of the ticket. | 
| Ticket.Key | Unknown | The key of the ticket. | 
| Ticket.Assignee | Unknown | The user assigned to the ticket. | 
| Ticket.Creator | Unknown | The user who created the ticket. | 
| Ticket.Summary | Unknown | The summary of the ticket. | 
| Ticket.Status | Unknown | The status of the ticket. | 


##### Command Example
```!jira-issue-query query="status=done"```

##### Context Example
```
{
    "Ticket": [
        {
            "Status": "Done", 
            "Creator": "{creator}", 
            "Summary": "HelloBlocked11", 
            "Assignee": "null(null)", 
            "Key": "TES-25", 
            "Id": "12658"
        }, 
        {
            "Status": "Done", 
            "Creator": "{creator}", 
            "Summary": "Test2", 
            "Assignee": "null(null)", 
            "Key": "SOC-40", 
            "Id": "10986"
        }
    ]
}
```

##### Human Readable Output
### jira-issue-query
|assignee|created|creator|description|duedate|id|issueType|key|labels|priority|project|reporter|status|summary|ticket_link|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| null(null) | 2019-05-04T02:45:09.909+0300 | {creator} | TypeofIssueIdList |  | 12658 | A task that needs to be done. | TES-25 |  | Medium | test1 | {creator} | Done | HelloBlocked11 | https://demistodev.atlassian.net/rest/api/latest/issue/12658 |
| null(null) | 2019-01-27T15:59:03.134+0200 | {creator} |  |  | 10986 | jira.translation.issuetype.bug.name.desc | SOC-40 |  | Medium | SOC | {creator} | Done | Test2 | https://demistodev.atlassian.net/rest/api/latest/issue/10986 |



### 2. Fetch an issue
---
Fetches an issue from Jira.

##### Base Command

`jira-get-issue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue. | Required | 
| headers | Headers to display in human readable format. | Optional | 
| getAttachments | If "true", retrives the issue's attachments. | Optional | 
| expandLinks | If "true", expands the issue's links. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | Unknown | The ID of the ticket. | 
| Ticket.Key | Unknown | The key of ticket. | 
| Ticket.Assignee | Unknown | The user assigned to the ticket. | 
| Ticket.Creator | Unknown | The user who created the ticket. | 
| Ticket.Summary | Unknown | The summary of the ticket. | 
| Ticket.Status | Unknown | The status of the ticket. | 
| File.Size | Unknown | The size of the file. | 
| File.SHA256 | Unknown | The SHA256 hash of the file. | 
| File.Name | Unknown | The name of the file. | 
| File.SHA1 | Unknown | The SHA1 hash of the file. | 


##### Command Example
```!jira-get-issue issueId=15572 getAttachments=true```

##### Context Example
```
{
    "Ticket": [
        {
            "Status": "To Do", 
            "Creator": "{creator}", 
            "Summary": "Test issue23", 
            "Assignee": "{assignee}", 
            "attachment": "", 
            "Key": "DEM-5415", 
            "Id": "15572"
        }
    ]
}
```

##### Human Readable Output
### jira-get-issue
|assignee|attachment|created|creator|description|duedate|id|issueType|key|labels|priority|project|reporter|status|summary|ticket_link|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| null(null) |  | 2020-01-19T12:34:13.784+0200 | {creator} | lala |  | 15572 | Request for Action | DEM-5415 |  | Medium | demistodev | {assignee} | To Do | Test issue23 | https://demistodev.atlassian.net/rest/api/latest/issue/15572 |


### 3. Create an issue
---
Creates a new issue in Jira.

##### Base Command

`jira-create-issue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueJson | The issue object (in JSON format). | Optional | 
| summary | The summary of the issue. | Required | 
| projectKey | The project key with which to associate the issue. | Optional | 
| issueTypeName |  Select an issue type by name, for example: "Problem".  | Optional | 
| issueTypeId | Select an issue type by its numeric ID. | Optional | 
| projectName | The project name with which to associate the issue. | Optional | 
| description | A description of the issue. | Optional | 
| labels | A CSV list of labels.  | Optional | 
| priority | The priority name, for example: "High" or "Medium". | Optional | 
| dueDate | The due date for the issue (in the format: 2018-03-11). | Optional | 
| assignee | The name of the assignee. | Optional | 
| reporter | The account ID of the reporter. | Optional | 
| parentIssueKey | The parent issue key (if you create a sub-task). | Optional | 
| parentIssueId | The parent issue ID (if you create a sub-task). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | Unknown | The ID of the ticket. | 
| Ticket.Key | Unknown | The key of the ticket. | 


##### Command Example
```!jira-create-issue summary="test SOC issue26" issueTypeId=10008 projectKey=DEM issueJson=\`{"fields":{"issuetype":{"name":"Request for Action"}}}\````

##### Context Example
```
{
    "Ticket": [
        {
            "Id": "15576", 
            "Key": "DEM-5419"
        }
    ]
}
```

##### Human Readable Output
### jira-create-issue
|id|key|projectKey|self|
|---|---|---|---|
| 15576 | DEM-5419 | DEM | https://demistodev.atlassian.net/rest/api/latest/issue/15576 |


### 4. Upload a file to an issue
---
Uploads a file attachment to an issue.

##### Base Command

`jira-issue-upload-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue. | Required | 
| upload | The entry ID to upload. | Optional | 
| attachmentName | The attachment name to be displayed in Jira (overrides original file name) | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!jira-issue-upload-file issueId=15572 upload=19@75```



##### Human Readable Output
### jira-issue-upload-file
|attachment_link|attachment_name|id|issueId|
|---|---|---|---|
| https://demistodev.atlassian.net/rest/api/2/attachment/13456 | jira_v2_yml.yml | 13456 | 15572 |


### 5. Add a comment to an issue
---
Adds a new comment to an existing Jira issue.

##### Base Command

`jira-issue-add-comment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue. | Required | 
| comment | The comment body. | Required | 
| visibility | The roles that can view the comment, for example: "Administrators".  | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!jira-issue-add-comment issueId=15572 comment="test comment"```


##### Human Readable Output
### jira-issue-add-comment
|comment|id|key|ticket_link|
|---|---|---|---|
| test comment | 13779 | admin | https://demistodev.atlassian.net/rest/api/2/issue/15572/comment/13779 |


### 6. Create (or update) a link to an issue
---
Creates (or updates) an issue link.

##### Base Command

`jira-issue-add-link`
##### Input

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


##### Context Output

There is no context output for this command.

##### Command Example
```!jira-issue-add-link issueId=15572 title=test url=https://www.demisto.com/```



##### Human Readable Output
### jira-issue-add-link
|id|ticket_link|
|---|---|
| 13722 | https://demistodev.atlassian.net/rest/api/latest/issue/DEM-5415/remotelink/13722 |


### 7. Edit an issue
---
Modifies an issue in JIRA.

##### Base Command

`jira-edit-issue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue to edit. | Required | 
| issueJson | The issue object (in JSON format). e.g, {"fields":{"customfield_10037": "field_value"}} | Optional | 
| summary | The summary of the issue. | Optional | 
| description | The description of the issue. | Optional | 
| labels |  A CSV list of labels.  | Optional | 
| priority |  A priority name, for example "High" or "Medium".  | Optional | 
| dueDate | The due date for the issue (in the format 2018-03-11). | Optional | 
| assignee | The name of the assignee. | Optional | 
| status | The name of the status. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Id | Unknown | The ID of the ticket. | 
| Ticket.Key | Unknown | The key of the ticket. | 
| Ticket.Assignee | Unknown | The user assigned to the ticket. | 
| Ticket.Creator | Unknown | The user who created the ticket. | 
| Ticket.Summary | Unknown | The summary of the ticket. | 
| Ticket.Status | Unknown | The status of the ticket. | 


##### Command Example
```!jira-edit-issue issueId=15572 customFields=Type_of_incident:Malware(Virus,_Ransomware) description="Just a description"```

##### Context Example
```
{
    "Ticket": [
        {
            "Status": "To Do", 
            "Creator": "{creator}", 
            "Summary": "Test issue23", 
            "Assignee": "{assignee}", 
            "attachment": "test_file.yml", 
            "Key": "DEM-5415", 
            "Id": "15572"
        }
    ]
}
```

##### Human Readable Output
### jira-edit-issue
|assignee|attachment|created|creator|description|duedate|id|issueType|key|labels|priority|project|reporter|status|summary|ticket_link|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| {assignee} | test_file.yml | 2020-01-19T12:34:13.784+0200 | {creator} | Just a description |  | 15572 | Request for Action | DEM-5415 |  | Medium | demistodev | {reporter} | To Do | Test issue23 | https://demistodev.atlassian.net/rest/api/latest/issue/15572 |
Issue #15572 was updated successfully

### 8. Get a ticket's comments
---
Returns the comments added to a ticket.

##### Base Command

`jira-get-comments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueId | The ID of the issue from which to get the comments. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.Comment.Comment | string | The text of the comment. | 
| Ticket.Comment.Created | string | The issue creation date. | 
| Ticket.Comment.User | string | The user that created the comment. | 


##### Command Example
```!jira-get-comments issueId=15572```

##### Context Example
```
{
    "Ticket": {
        "Comment": [
            {
                "Comment": "test comment", 
                "User": "admin", 
                "Created": "2020-01-19T12:35:49.194+0200"
            }
        ], 
        "Id": "15572"
    }
}
```

##### Human Readable Output
### Comments
|Comment|Created|User|
|---|---|---|
| test comment | 2020-01-19T12:35:49.194+0200 | admin |


### 9. Delete an issue
---
Deletes an issue in Jira.

##### Base Command

`jira-delete-issue`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issueIdOrKey | The ID or key of the issue. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!jira-delete-issue issueIdOrKey=DEM-5415```

##### Human Readable Output
Issue deleted successfully.

### 10. Get the ID offset
---
Returns the ID offset, for example, the first issue ID.

##### Base Command

`jira-get-id-offset`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Ticket.idOffSet | string | The ID offset. | 


##### Command Example
```!jira-get-id-offset```

##### Context Example
```
{
    "Ticket.idOffSet": "10161"
}
```

##### Human Readable Output
ID Offset: 10161
